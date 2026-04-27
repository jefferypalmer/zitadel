package dcr

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// fixedIssuedAt makes the unix-second math deterministic.
var fixedIssuedAt = time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

func newRegistrationOutput() *RegistrationOutput {
	return &RegistrationOutput{
		ClientID:              "client-abc",
		ClientSecret:          "",
		ClientSecretExpiresIn: 0,
		RATPlaintext:          "zdrat_xyz",
		ClientIDIssuedAt:      fixedIssuedAt,
		Clamped: &RFC7591Metadata{
			ClientName:              "test",
			RedirectURIs:            []string{"https://example.com/cb"},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
			ApplicationType:         "native",
		},
	}
}

// withIssuer wraps a context with the OIDC issuer the response writer
// reads via op.IssuerFromContext.
func withIssuer(t *testing.T, issuer string) context.Context {
	t.Helper()
	return op.ContextWithIssuer(context.Background(), issuer)
}

// ──────────────────────────────────────────────────────────────────
// R7 acceptance criteria
// ──────────────────────────────────────────────────────────────────

func TestWriteRegistrationResponse_R7_StatusAndHeaders(t *testing.T) {
	out := newRegistrationOutput()
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	res := w.Result()
	defer res.Body.Close()

	assert.Equal(t, 201, res.StatusCode, "R7 AC: status MUST be 201")
	assert.Equal(t, "application/json;charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
}

func TestWriteRegistrationResponse_R7_OmitsClientSecretWhenAbsent(t *testing.T) {
	out := newRegistrationOutput() // ClientSecret = ""
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	body := w.Body.String()
	assert.NotContains(t, body, "client_secret\":",
		"R7 AC: client_secret MUST be omitted when auth_method=none")

	// `client_secret_expires_at` MUST still be present with the 0 sentinel.
	assert.Contains(t, body, `"client_secret_expires_at":0`,
		"R7 AC: client_secret_expires_at=0 sentinel MUST be present (RFC 7591 §3.2.1)")
}

func TestWriteRegistrationResponse_R7_EmitsClientSecretWhenPresent(t *testing.T) {
	out := newRegistrationOutput()
	out.ClientSecret = "plain-secret-once"
	out.Clamped.TokenEndpointAuthMethod = "client_secret_basic"
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "plain-secret-once", got["client_secret"])
}

func TestWriteRegistrationResponse_R7_ClientSecretExpiresAtSentinel(t *testing.T) {
	cases := []struct {
		name           string
		expiresIn      time.Duration
		wantSentinelOK bool
	}{
		{"zero lifetime → 0 sentinel", 0, true},
		{"non-zero lifetime → unix sum", 24 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := newRegistrationOutput()
			out.ClientSecret = "secret"
			out.ClientSecretExpiresIn = tc.expiresIn
			w := httptest.NewRecorder()

			require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			expiresAt, ok := got["client_secret_expires_at"].(float64)
			require.True(t, ok, "client_secret_expires_at MUST be present")
			if tc.wantSentinelOK {
				assert.Equal(t, float64(0), expiresAt)
			} else {
				assert.Equal(t, float64(fixedIssuedAt.Add(tc.expiresIn).Unix()), expiresAt)
			}
		})
	}
}

func TestWriteRegistrationResponse_R7_RegistrationClientURI(t *testing.T) {
	out := newRegistrationOutput()
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t,
		"https://issuer.example/oidc/v1/register/client-abc",
		got["registration_client_uri"],
		"R7 AC: registration_client_uri = <issuer>/oidc/v1/register/<client_id>")
}

func TestWriteRegistrationResponse_R7_RegistrationClientURI_TrimsTrailingSlash(t *testing.T) {
	out := newRegistrationOutput()
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example/"), w, out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t,
		"https://issuer.example/oidc/v1/register/client-abc",
		got["registration_client_uri"])
}

func TestWriteRegistrationResponse_R7_RAT_PresentInBody(t *testing.T) {
	out := newRegistrationOutput()
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	body := w.Body.String()
	assert.Contains(t, body, `"registration_access_token":"zdrat_xyz"`)
}

func TestWriteRegistrationResponse_R7_EchoesClampedMetadata(t *testing.T) {
	out := newRegistrationOutput()
	out.Clamped.RedirectURIs = []string{"https://a/b", "https://c/d"}
	out.Clamped.GrantTypes = []string{"authorization_code", "refresh_token"}
	out.Clamped.Contacts = []string{"a@example.com"}
	out.Clamped.SoftwareID = "xyz-id"
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, []any{"https://a/b", "https://c/d"}, got["redirect_uris"])
	assert.Equal(t, []any{"authorization_code", "refresh_token"}, got["grant_types"])
	assert.Equal(t, []any{"a@example.com"}, got["contacts"])
	assert.Equal(t, "xyz-id", got["software_id"])
}

func TestWriteRegistrationResponse_R7_ClientIDIssuedAt(t *testing.T) {
	out := newRegistrationOutput()
	w := httptest.NewRecorder()

	require.NoError(t, WriteRegistrationResponse(withIssuer(t, "https://issuer.example"), w, out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, float64(fixedIssuedAt.Unix()), got["client_id_issued_at"])
}

func TestWriteRegistrationResponse_R7_NilOutputErrors(t *testing.T) {
	w := httptest.NewRecorder()
	require.Error(t, WriteRegistrationResponse(context.Background(), w, nil))

	require.Error(t, WriteRegistrationResponse(context.Background(), w, &RegistrationOutput{}))
}

// TestWriteRegistrationResponse_NeverEmitsRegistrationEndpointNull
// guards against the same Zod-parser-bug class as the discovery
// response: if registration_client_uri were ever empty, an
// `omitempty`-less string field would emit `"registration_client_uri":""`
// and break Claude-Code-style parsers. Defence in depth.
func TestWriteRegistrationResponse_NeverEmitsEmptyRegistrationClientURI(t *testing.T) {
	// Force the issuer-empty fallback path. The fallback returns a
	// relative URL ("/oidc/v1/register/<id>") so the field is still
	// non-empty.
	out := newRegistrationOutput()
	w := httptest.NewRecorder()
	require.NoError(t, WriteRegistrationResponse(context.Background(), w, out))

	body := w.Body.String()
	assert.False(t, strings.Contains(body, `"registration_client_uri":""`),
		"empty registration_client_uri MUST never appear in body")
	assert.Contains(t, body, `"registration_client_uri":"/oidc/v1/register/client-abc"`,
		"issuer-empty fallback yields relative URL")
}

// TestBuildRegistrationResponse_DoesNotMutateInput pins the no-aliasing
// contract — the writer reads from RegistrationOutput.Clamped but MUST
// NOT swap any pointer in it (otherwise a retry / async OTel span
// reading the same struct sees a corrupted state).
func TestBuildRegistrationResponse_DoesNotMutateInput(t *testing.T) {
	out := newRegistrationOutput()
	originalRedirects := append([]string{}, out.Clamped.RedirectURIs...)
	originalGrants := append([]string{}, out.Clamped.GrantTypes...)

	_ = buildRegistrationResponse(withIssuer(t, "https://issuer.example"), out)

	assert.Equal(t, originalRedirects, out.Clamped.RedirectURIs)
	assert.Equal(t, originalGrants, out.Clamped.GrantTypes)
}
