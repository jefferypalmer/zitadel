package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUpdate captures the dispatched UpdateRequest and returns a
// programmable result. Used by every PUT-handler test so the tests can
// assert that the dispatcher (a) only calls Update when clamp succeeds
// and (b) passes the resolved (project, org, app) tuple from the
// ManageContext.
type fakeUpdate struct {
	mu     sync.Mutex
	calls  []UpdateRequest
	result *UpdateResult
	err    error
}

func (f *fakeUpdate) fn(_ context.Context, req *UpdateRequest) (*UpdateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, *req)
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &UpdateResult{ClientID: req.AppID}, nil
}

// newPUTDeps wires the manage path with a fakeUpdate and the canonical
// allow-list config used elsewhere in the dcr tests. The RAT lookup
// stub mirrors newGETDeps so manageVerifyDispatch sees a valid row.
func newPUTDeps(u *fakeUpdate) ManageDeps {
	return ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
		},
		RATVerifier:              &fakeRATVerifier{},
		Rehasher:                 (&fakeRehasher{}).fn,
		AntiEnumDummyHash:        "$argon2id$dummy",
		Update:                   u.fn,
		Config:                   defaultStubConfig(),
		SupportedSigAlgs:         []string{"RS256"},
		SoftwareStatementEnabled: false,
		MaxBodyBytes:             8192,
	}
}

// servePUT mounts the PUT route + manageVerifyDispatch and runs one
// request with Bearer set, returning the recorder.
func servePUT(deps ManageDeps, clientID string, body []byte, contentType string) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, choosePUTHandler(deps))).Methods(http.MethodPut)
	req := httptest.NewRequest(http.MethodPut, "/"+clientID, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func validPUTBody(t *testing.T, m *RFC7591Metadata) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// TestPUT_Stub_WhenUpdateNotWired pins the choosePUTHandler fall-back —
// when ManageDeps.Update is nil the PUT route must still serve a clean
// 501 (not panic, not 5xx with a wiring trace), so deployments mid-
// rollout produce a uniform error envelope.
func TestPUT_Stub_WhenUpdateNotWired(t *testing.T) {
	deps := ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
		},
		RATVerifier:       &fakeRATVerifier{},
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: "$argon2id$dummy",
		// Update intentionally nil.
	}
	rec := servePUT(deps, "client-1", []byte(`{}`), "application/json")
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

// TestPUT_Success_HappyPath covers cavekit-manage-handler.md R5 AC1 —
// the full re-clamp succeeds, Update is called with the resolved
// (project, org, app), and the 200 response echoes the clamped body.
func TestPUT_Success_HappyPath(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{ClientID: "client-1"}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "Updated Client",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

	require.Len(t, u.calls, 1, "Update must be called exactly once on success")
	assert.Equal(t, "proj-1", u.calls[0].ProjectID, "project routes from ManageContext")
	assert.Equal(t, "org-1", u.calls[0].OrgID, "org routes from ManageContext (resource_owner)")
	assert.Equal(t, "app-1", u.calls[0].AppID, "app routes from ManageContext")
	require.NotNil(t, u.calls[0].Clamped)
	assert.Equal(t, "Updated Client", u.calls[0].Clamped.ClientName)

	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "client-1", resp.ClientID)
	assert.Equal(t, "Updated Client", resp.ClientName)
	assert.Equal(t, []string{"https://example.com/cb"}, resp.RedirectURIs)
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
	assert.Equal(t, HandlerPrefix+"/client-1", resp.RegistrationClientURI)
}

// TestPUT_AuthMethodMatrix_NoneToBasic_EmitsClientSecret covers R5 AC3 —
// transitioning from `none` to `client_secret_basic` issues a new
// secret and the response body carries it. The fakeUpdate stands in
// for the command layer; the handler's job is simply to echo the
// minted secret back.
func TestPUT_AuthMethodMatrix_NoneToBasic_EmitsClientSecret(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		ClientSecret: "freshly-minted-plaintext", // command minted it on transition
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "freshly-minted-plaintext", resp.ClientSecret,
		"R5 AC3: none → client_secret_basic must echo the new secret")

	// Raw-JSON check too — the dispatcher must NOT omit a non-empty
	// client_secret via stale json:omitempty.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	v, present := raw["client_secret"]
	require.True(t, present)
	assert.Equal(t, "freshly-minted-plaintext", v)
}

// TestPUT_AuthMethodMatrix_BasicToNone_OmitsClientSecret covers R5 AC4 —
// transitioning to `none` clears the stored secret; the response body
// MUST omit `client_secret` entirely (no empty-string echo) so the
// caller can structurally distinguish "secret cleared" from "secret
// rotated to a known value".
func TestPUT_AuthMethodMatrix_BasicToNone_OmitsClientSecret(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		ClientSecret: "", // command-side cleared it on transition
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, present := raw["client_secret"]
	assert.False(t, present, "R5 AC4: client_secret_* → none MUST omit client_secret")
}

// TestPUT_AuthMethodMatrix_PrivateKeyJWT_RequiresJwksURI covers R5 AC5 —
// transitioning to private_key_jwt without jwks_uri is rejected by the
// shared validate.go. The dispatcher MUST NOT call Update because the
// command-layer transition matrix would never see the malformed
// metadata.
func TestPUT_AuthMethodMatrix_PrivateKeyJWT_RequiresJwksURI(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "private_key_jwt",
		ApplicationType:         "web",
		// JwksURI intentionally absent — clamp must reject.
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Contains(t, rec.Body.String(), "jwks_uri")
	assert.Empty(t, u.calls, "clamp failure MUST NOT reach the command layer")
}

// TestPUT_AuthMethodMatrix_PrivateKeyJWT_HappyPath_WithJwksURI completes
// the AC5 contract — when jwks_uri IS supplied, the clamp passes and
// the dispatcher calls Update with the new auth method.
func TestPUT_AuthMethodMatrix_PrivateKeyJWT_HappyPath_WithJwksURI(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{ClientID: "client-1"}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "private_key_jwt",
		ApplicationType:         "web",
		JwksURI:                 "https://example.com/.well-known/jwks.json",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	require.Len(t, u.calls, 1)
	assert.Equal(t, "private_key_jwt", u.calls[0].Clamped.TokenEndpointAuthMethod)
}

// TestPUT_AuthMethodMatrix_ClientSecretJWTRejected covers R5 AC6 — the
// `client_secret_jwt` value is rejected by the shared clamp before it
// ever reaches the command, so a future operator can't accidentally
// allow it by tweaking the auth-method transition matrix in isolation.
func TestPUT_AuthMethodMatrix_ClientSecretJWTRejected(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_jwt",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Contains(t, rec.Body.String(), "client_secret_jwt")
	assert.Empty(t, u.calls)
}

// TestPUT_DisallowedGrantType_400 covers R5 AC2 — clamp rejects values
// outside the operator allow-list. The handler maps the *ClampError
// straight to 400 invalid_client_metadata.
func TestPUT_DisallowedGrantType_400(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"client_credentials"}, // not in defaults
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Contains(t, rec.Body.String(), "grant_types")
	assert.Empty(t, u.calls)
}

// TestPUT_Decode_415_NonJSONContentType covers R5 inheritance from R2:
// re-clamp begins with Decode, so non-JSON content-type → 415 BEFORE
// the Update closure runs.
func TestPUT_Decode_415_NonJSONContentType(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)
	rec := servePUT(deps, "client-1", []byte("not-json"), "text/plain")
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	assert.Empty(t, u.calls)
}

// TestPUT_Decode_400_MalformedJSON — malformed JSON → 400
// invalid_client_metadata (R2 AC).
func TestPUT_Decode_400_MalformedJSON(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)
	rec := servePUT(deps, "client-1", []byte(`{"bad json`), "application/json")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Empty(t, u.calls)
}

// TestPUT_Decode_413_BodyTooLarge — body cap inherited from R2.
func TestPUT_Decode_413_BodyTooLarge(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)
	deps.MaxBodyBytes = 16 // tiny cap for the test
	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:    strings.Repeat("x", 200),
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Empty(t, u.calls)
}

// TestPUT_UpdateError_Mapped500 — when the command-layer Update fails
// with a non-ClampError, the dispatcher writes 500 server_error and
// does NOT echo the error string (R8 fingerprint guard).
func TestPUT_UpdateError_Mapped500(t *testing.T) {
	u := &fakeUpdate{err: errors.New("eventstore push failed: deep internal detail")}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"server_error"`)
	assert.NotContains(t, rec.Body.String(), "deep internal detail",
		"R8: 500 must NOT leak the wrapped error string to the caller")
}

// TestPUT_UpdateClampErrorPropagates — when the command-layer Update
// returns a *ClampError (e.g. a future per-tenant allow-list rejection),
// the dispatcher honours the embedded HTTP status + envelope code
// rather than collapsing to 500. This is the structural pin that keeps
// the command-layer error vocabulary aligned with the handler.
func TestPUT_UpdateClampErrorPropagates(t *testing.T) {
	u := &fakeUpdate{err: &ClampError{
		Status:      http.StatusForbidden,
		Code:        ErrCodeFeatureDisabled,
		Description: "per-tenant override",
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"feature_disabled"`)
}

// TestPUT_NoManageContext_Panics asserts cavekit-manage-handler.md R8:
// ManageFromContext panics when manageVerifyDispatch did not run. The
// recover middleware at internal/api/oidc/op.go catches it in
// production; the dispatcher monopoly guarantees the value is set on
// every real request.
func TestPUT_NoManageContext_Panics(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)
	h := putClientHandler(deps)
	body := validPUTBody(t, validHappyPathMetadata())
	req := httptest.NewRequest(http.MethodPut, "/client-1", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from ManageFromContext, got nil")
		}
		if len(u.calls) != 0 {
			t.Fatalf("Update should not have been called before the panic; got %d calls", len(u.calls))
		}
	}()
	h(rec, req.WithContext(context.Background()))
}

// TestManageDeps_Validate_PUT_RequiresConfigWhenUpdateSet pins the
// extended Validate contract — wiring an Update closure without a
// Config is a programmer error and MUST fail-fast at boot rather
// than 5xxing on the first PUT.
func TestManageDeps_Validate_PUT_RequiresConfigWhenUpdateSet(t *testing.T) {
	good := newPUTDeps(&fakeUpdate{})
	require.NoError(t, good.Validate())

	bad := good
	bad.Config = nil
	err := bad.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Config is required when Update is set")
}

// TestPUT_RATRotation_AlwaysEmitsNewRAT covers cavekit-manage-handler.md
// R5 AC7-9 (T-055): every successful PUT returns a freshly-rotated RAT
// in the response body — independent of whether the auth method
// transitioned. The RegistrationAccessToken field has NO json:omitempty
// tag so a missing rotation in the result would surface as the
// empty-string value and the assertion below would fail.
func TestPUT_RATRotation_AlwaysEmitsNewRAT(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		RATPlaintext: "zdrat_freshly_rotated_xyz",
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "zdrat_freshly_rotated_xyz", resp.RegistrationAccessToken,
		"R5 AC7: every successful PUT MUST emit the new plaintext RAT")

	// Raw-JSON check pins the field is always present (no omitempty
	// shortcut hiding a missing rotation).
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	v, present := raw["registration_access_token"]
	require.True(t, present, "R5 AC7: registration_access_token MUST be present on every PUT 200")
	assert.Equal(t, "zdrat_freshly_rotated_xyz", v)
}

// TestPUT_RATRotation_PresentEvenWithoutAuthMethodTransition pins the
// AC7 contract that rotation is independent of the auth-method matrix.
// A no-op idempotent PUT (same auth method, same metadata) MUST still
// rotate the RAT — that's the whole point: the caller's RAT was
// presented once on this request and is now spent, so the PUT must
// always issue a replacement.
func TestPUT_RATRotation_PresentEvenWithoutAuthMethodTransition(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		RATPlaintext: "zdrat_rotated_on_idempotent_put",
		// ClientSecret deliberately empty — no auth-method change.
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, validHappyPathMetadata())
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "zdrat_rotated_on_idempotent_put", resp.RegistrationAccessToken,
		"R5 AC7: rotation MUST happen even on a no-op PUT")
	assert.Empty(t, resp.ClientSecret, "no auth-method transition → no client_secret echo")
}

// TestPUT_Response_ClientIDIssuedAt_T087 covers cavekit-manage-handler.md
// R5 new AC (T-087, F-001): PUT response MUST emit `client_id_issued_at`
// (Unix seconds, sourced from registration time). RFC 7592 §3.2 mandates
// the PUT body mirror RFC 7591 §3.2.1 client-info shape.
func TestPUT_Response_ClientIDIssuedAt_T087(t *testing.T) {
	issued := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:         "client-1",
		RATPlaintext:     "zdrat_x",
		ClientIDIssuedAt: issued,
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, validHappyPathMetadata())
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	v, present := raw["client_id_issued_at"]
	require.True(t, present, "F-001: client_id_issued_at MUST be present in PUT 200 body")
	assert.EqualValues(t, issued.Unix(), v,
		"F-001: client_id_issued_at MUST equal registration time (Unix seconds)")
}

// TestPUT_Response_ClientIDIssuedAt_OmittedWhenZero — defensive: when
// the upstream lookup couldn't source the registration time the field
// is omitted rather than emitted as 0 (which would be 1970-01-01 — an
// obvious wrong-value).
func TestPUT_Response_ClientIDIssuedAt_OmittedWhenZero(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		RATPlaintext: "zdrat_x",
		// ClientIDIssuedAt deliberately zero
	}}
	deps := newPUTDeps(u)

	body := validPUTBody(t, validHappyPathMetadata())
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, present := raw["client_id_issued_at"]
	assert.False(t, present, "F-001 defensive: zero IssuedAt → field omitted (not emitted as 0)")
}

// TestPUT_Response_ClientSecretExpiresAt_Computed_T088 covers
// cavekit-manage-handler.md R5 new AC (T-088, F-002): when the PUT
// mints a fresh secret AND the AS configures non-zero
// `ClientSecretExpiresIn`, the response MUST emit
// `client_secret_expires_at = ChangedAt + lifetime` (Unix seconds),
// NOT the no-expiry sentinel 0.
func TestPUT_Response_ClientSecretExpiresAt_Computed_T088(t *testing.T) {
	changedAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	lifetime := 90 * 24 * time.Hour // 90 days
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		ClientSecret: "freshly-minted",
		RATPlaintext: "zdrat_x",
		ChangedAt:    changedAt,
	}}
	deps := newPUTDeps(u)
	deps.ClientSecretExpiresIn = lifetime

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	expected := changedAt.Add(lifetime).Unix()
	assert.Equal(t, expected, resp.ClientSecretExpiresAt,
		"F-002: when minting a fresh secret with configured lifetime, expires_at MUST be ChangedAt+lifetime (got %d, want %d)",
		resp.ClientSecretExpiresAt, expected)
	assert.NotEqual(t, int64(0), resp.ClientSecretExpiresAt,
		"F-002: 0 sentinel is reserved for no-expiry; non-zero lifetime MUST yield non-zero")
}

// TestPUT_Response_ClientSecretExpiresAt_ZeroWhenNoSecretMinted pins
// the AC4 path: a transition that does NOT mint a secret (e.g.
// idempotent PUT, or basic→none) MUST emit the 0 no-expiry sentinel.
func TestPUT_Response_ClientSecretExpiresAt_ZeroWhenNoSecretMinted(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		ClientSecret: "", // no transition / no mint
		RATPlaintext: "zdrat_x",
		ChangedAt:    time.Now(),
	}}
	deps := newPUTDeps(u)
	deps.ClientSecretExpiresIn = 90 * 24 * time.Hour // even with lifetime configured

	body := validPUTBody(t, validHappyPathMetadata())
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, int64(0), resp.ClientSecretExpiresAt,
		"F-002: no fresh secret minted → 0 no-expiry sentinel (no client_secret to expire)")
}

// TestPUT_Response_ClientSecretExpiresAt_ZeroWhenLifetimeZero pins the
// AS-policy-no-expiry case: secret WAS minted but the AS configures
// `ClientSecretExpiresIn == 0` ("never expires"). Response MUST emit
// the 0 sentinel as RFC 7591 §3.2.1 specifies.
func TestPUT_Response_ClientSecretExpiresAt_ZeroWhenLifetimeZero(t *testing.T) {
	u := &fakeUpdate{result: &UpdateResult{
		ClientID:     "client-1",
		ClientSecret: "freshly-minted",
		RATPlaintext: "zdrat_x",
		ChangedAt:    time.Now(),
	}}
	deps := newPUTDeps(u)
	deps.ClientSecretExpiresIn = 0 // operator chose no-expiry

	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp ManageUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, int64(0), resp.ClientSecretExpiresAt,
		"F-002: ClientSecretExpiresIn=0 (AS no-expiry policy) → 0 sentinel per RFC 7591 §3.2.1")
}

// TestPUT_RATRotation_NotEmittedOnError pins the negative — error
// responses (clamp / decode / dispatch) MUST NOT carry the rotated
// RAT. A failure path that leaks a non-existent rotated token would
// confuse callers and burn audit-log entries unnecessarily.
func TestPUT_RATRotation_NotEmittedOnError(t *testing.T) {
	u := &fakeUpdate{}
	deps := newPUTDeps(u)

	// Trigger a clamp error — disallowed grant_type.
	body := validPUTBody(t, &RFC7591Metadata{
		ClientName:              "x",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"client_credentials"}, // not in defaults
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	})
	rec := servePUT(deps, "client-1", body, "application/json")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "registration_access_token",
		"R5 error path: rotated RAT MUST NOT appear in 4xx envelope bodies")
	assert.Empty(t, u.calls, "clamp error MUST NOT reach the rotation step")
}
