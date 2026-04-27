package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedIssued is the canonical client_id_issued_at used across the
// GET-handler tests so the JSON expectations stay simple.
var fixedIssued = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newGETDeps(meta *ManageMetaRow, metaErr error) ManageDeps {
	return ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
			metaRow: meta,
			metaErr: metaErr,
		},
		RATVerifier:       &fakeRATVerifier{},
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: "$argon2id$dummy",
	}
}

// serveGET mounts the GET handler under /{client_id} and runs one
// request with Bearer set, returning the recorder.
func serveGET(deps ManageDeps, clientID string) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, getClientHandler(deps))).Methods(http.MethodGet)
	req := httptest.NewRequest(http.MethodGet, "/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestGetClient_Success_BodyShape covers cavekit-manage-handler.md R4
// AC2 — the body includes every field listed in the kit, with the
// values from the projection. R4 AC3 is a separate test
// (TestGetClient_OmitsClientSecretAndRAT).
func TestGetClient_Success_BodyShape(t *testing.T) {
	dcrMeta, err := json.Marshal(map[string]any{
		"contacts":    []string{"ops@example.com"},
		"logo_uri":    "https://example.com/logo.png",
		"client_uri":  "https://example.com",
		"software_id": "claude-code",
		"scope":       "openid profile",
	})
	require.NoError(t, err)

	meta := &ManageMetaRow{
		AppID:            "app-1",
		ClientName:       "Claude Code",
		ClientIDIssuedAt: fixedIssued,
		RedirectURIs:     []string{"https://callback.example/cb"},
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		ResponseTypes:    []string{"code"},
		ApplicationType:  "native",
		AuthMethodType:   "none",
		DCRMeta:          dcrMeta,
	}
	rec := serveGET(newGETDeps(meta, nil), "client-1")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "R4 AC5: no-store")
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"), "R4 AC5: no-cache")

	var body ManageReadResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	assert.Equal(t, "client-1", body.ClientID)
	assert.Equal(t, fixedIssued.Unix(), body.ClientIDIssuedAt)
	assert.Equal(t, "Claude Code", body.ClientName)
	assert.Equal(t, []string{"https://callback.example/cb"}, body.RedirectURIs)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, body.GrantTypes)
	assert.Equal(t, []string{"code"}, body.ResponseTypes)
	assert.Equal(t, "none", body.TokenEndpointAuthMethod)
	assert.Equal(t, "native", body.ApplicationType)

	// dcr_meta pass-through fields.
	assert.Equal(t, []string{"ops@example.com"}, body.Contacts)
	assert.Equal(t, "https://example.com/logo.png", body.LogoURI)
	assert.Equal(t, "https://example.com", body.ClientURI)
	assert.Equal(t, "claude-code", body.SoftwareID)
	assert.Equal(t, "openid profile", body.Scope)
}

// TestGetClient_OmitsClientSecretAndRAT covers R4 AC3 — the GET
// response body MUST NOT carry `client_secret` or
// `registration_access_token` (RFC 7592 §2 MAY-omit allowance — we
// take it). Asserts on the RAW JSON because the strongly-typed
// struct doesn't even define those fields.
func TestGetClient_OmitsClientSecretAndRAT(t *testing.T) {
	meta := &ManageMetaRow{
		AppID: "app-1", ClientName: "x", ClientIDIssuedAt: fixedIssued,
		AuthMethodType: "client_secret_basic", // even when secret was issued
	}
	rec := serveGET(newGETDeps(meta, nil), "client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, hasSecret := raw["client_secret"]
	assert.False(t, hasSecret, "R4 AC3: GET MUST omit client_secret")
	_, hasRAT := raw["registration_access_token"]
	assert.False(t, hasRAT, "R4 AC3: GET MUST omit registration_access_token")
}

// TestGetClient_ClientSecretExpiresAtSentinel covers R4 AC2 — the
// `client_secret_expires_at` field stays present (no omitempty) so
// clients can re-discover the RFC 7591 §3.2.1 sentinel `0` (no
// expiry) at GET time. The current implementation always emits 0
// (the projection doesn't store a per-secret expires_at column).
func TestGetClient_ClientSecretExpiresAtSentinel(t *testing.T) {
	meta := &ManageMetaRow{AppID: "app-1", ClientIDIssuedAt: fixedIssued}
	rec := serveGET(newGETDeps(meta, nil), "client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	v, present := raw["client_secret_expires_at"]
	require.True(t, present, "R4 AC2: client_secret_expires_at MUST be present")
	assert.EqualValues(t, 0, v, "R4: 0 == no expiry sentinel (RFC 7591 §3.2.1)")
}

// TestGetClient_RegistrationClientURI covers R4 AC4 — the
// registration_client_uri value MUST match what POST /register
// originally returned. Both paths route through
// [buildRegistrationClientURI] so a regression in the constant /
// HandlerPrefix would diverge them; structurally checking the
// shared helper is the cheapest pin.
func TestGetClient_RegistrationClientURI(t *testing.T) {
	meta := &ManageMetaRow{AppID: "app-1", ClientIDIssuedAt: fixedIssued}
	rec := serveGET(newGETDeps(meta, nil), "client-77")
	require.Equal(t, http.StatusOK, rec.Code)

	var body ManageReadResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	// op.IssuerFromContext returns "" in the test (no OIDC middleware),
	// so the helper falls back to HandlerPrefix + "/" + clientID.
	assert.Equal(t, HandlerPrefix+"/client-77", body.RegistrationClientURI)
}

// TestGetClient_MetadataLookupError_500 — when the projection lookup
// fails AFTER VerifyRAT succeeded, the handler emits 500 server_error
// (not 404 — that would leak the existence-vs-state distinction).
func TestGetClient_MetadataLookupError_500(t *testing.T) {
	rec := serveGET(newGETDeps(nil, errors.New("projection lag — row gone")), "client-1")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"server_error"`)
}

// TestGetClient_MalformedDCRMeta_StillServes200 — a corrupt JSONB
// blob in the dcr_meta column does not block the GET; the handler
// serves the response without the pass-through fields. Better than
// 500 — the core RFC 7591 fields are still useful and partial >
// blocking on a single corrupted column.
func TestGetClient_MalformedDCRMeta_StillServes200(t *testing.T) {
	meta := &ManageMetaRow{
		AppID:            "app-1",
		ClientName:       "x",
		ClientIDIssuedAt: fixedIssued,
		DCRMeta:          []byte("not-valid-json"),
	}
	rec := serveGET(newGETDeps(meta, nil), "client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	var body ManageReadResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "x", body.ClientName)
	assert.Empty(t, body.Contacts, "malformed dcr_meta → pass-through fields stay zero")
	assert.Empty(t, body.LogoURI)
}

// TestGetClient_NoManageContext_500 — defensive: if the handler is
// somehow wired without manageVerifyDispatch (so no ManageContext on
// ctx), the response is 500 not a panic.
func TestGetClient_NoManageContext_500(t *testing.T) {
	deps := newGETDeps(&ManageMetaRow{AppID: "app-1", ClientIDIssuedAt: fixedIssued}, nil)
	h := getClientHandler(deps)
	req := httptest.NewRequest(http.MethodGet, "/client-1", nil) // no ctx wrap
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(context.Background()))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"server_error"`)
}
