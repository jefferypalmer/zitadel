package dcr

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ───────────────────────────────────────────────────────────────────────
// SynthesiseClientName — R2 AC: empty client_name → synthesised string
// ───────────────────────────────────────────────────────────────────────

func TestSynthesiseClientName(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
		want     string
	}{
		{"long snowflake → trim to 8", "abc12345xyz", "Dynamically Registered Client abc12345"},
		{"exactly 8 chars", "abcdefgh", "Dynamically Registered Client abcdefgh"},
		{"shorter than 8", "abc", "Dynamically Registered Client abc"},
		{"empty client_id (defensive)", "", "Dynamically Registered Client "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SynthesiseClientName(tc.clientID))
		})
	}
}

// ───────────────────────────────────────────────────────────────────────
// Decode — R2 happy path + defaults
// ───────────────────────────────────────────────────────────────────────

func newJSONReq(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestDecode_HappyPath(t *testing.T) {
	body := `{
		"client_name": "Test Client",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Test Client", got.ClientName)
	assert.Equal(t, []string{"https://example.com/cb"}, got.RedirectURIs)
}

func TestDecode_R2_DefaultsApplied(t *testing.T) {
	// All R2-defaulted fields omitted → values populated from R2 ACs.
	body := `{"redirect_uris": ["https://example.com/cb"]}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code"}, got.GrantTypes, "R2 default: grant_types")
	assert.Equal(t, []string{"code"}, got.ResponseTypes, "R2 default: response_types")
	assert.Equal(t, "client_secret_basic", got.TokenEndpointAuthMethod, "R2 default: auth_method")
	assert.Equal(t, "web", got.ApplicationType, "R2 default (OIDC Reg 1.0 §2): application_type")
}

func TestDecode_R2_DefaultsLeaveExplicitValuesAlone(t *testing.T) {
	body := `{
		"grant_types": ["refresh_token"],
		"response_types": ["token"],
		"token_endpoint_auth_method": "none",
		"application_type": "native",
		"redirect_uris": ["http://localhost:1234/cb"]
	}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"refresh_token"}, got.GrantTypes)
	assert.Equal(t, []string{"token"}, got.ResponseTypes)
	assert.Equal(t, "none", got.TokenEndpointAuthMethod)
	assert.Equal(t, "native", got.ApplicationType)
}

func TestDecode_R2_UnknownFieldsSilentlyDropped(t *testing.T) {
	// R2 last AC: unknown fields are silently dropped, NOT rejected.
	body := `{
		"redirect_uris": ["https://example.com/cb"],
		"unknown_field_xyz": "should be dropped",
		"another_unknown": {"nested": true}
	}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/cb"}, got.RedirectURIs)
}

func TestDecode_R2_LocalizedClientNameDropped(t *testing.T) {
	// `client_name#<lang>` variants have no struct field → dropped.
	body := `{
		"client_name": "EN Name",
		"client_name#de": "DE Name",
		"client_name#fr": "FR Name",
		"redirect_uris": ["https://example.com/cb"]
	}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	assert.Equal(t, "EN Name", got.ClientName, "only the canonical client_name survives")
}

// ───────────────────────────────────────────────────────────────────────
// Decode — R2 error matrix
// ───────────────────────────────────────────────────────────────────────

func TestDecode_R2_415_NoContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", strings.NewReader(`{}`))
	// Header.Set in httptest.NewRequest auto-detects body Content-Type as
	// text/plain when not set; clear it explicitly.
	req.Header.Del("Content-Type")

	_, err := Decode(req, DecodeOptions{})
	requireClampStatus(t, err, http.StatusUnsupportedMediaType, ErrCodeUnsupportedMediaType)
}

func TestDecode_R2_415_WrongContentType(t *testing.T) {
	cases := []struct {
		name string
		ct   string
	}{
		{"text/plain", "text/plain"},
		{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"},
		{"application/xml", "application/xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", tc.ct)
			_, err := Decode(req, DecodeOptions{})
			requireClampStatus(t, err, http.StatusUnsupportedMediaType, ErrCodeUnsupportedMediaType)
		})
	}
}

func TestDecode_R2_415_AcceptsCharsetParam(t *testing.T) {
	// `application/json; charset=utf-8` MUST be accepted (RFC 7231 mime
	// param semantics; the charset is informational).
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"redirect_uris":["https://e/c"]}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	_, err := Decode(req, DecodeOptions{})
	require.NoError(t, err)
}

func TestDecode_R2_415_AcceptsCaseInsensitive(t *testing.T) {
	// RFC 7231 §3.1.1.1: media types are case-insensitive.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"redirect_uris":["https://e/c"]}`))
	req.Header.Set("Content-Type", "Application/JSON")
	_, err := Decode(req, DecodeOptions{})
	require.NoError(t, err)
}

func TestDecode_R2_413_BodyTooLarge(t *testing.T) {
	// Body exceeds the cap.
	huge := strings.Repeat("x", 200)
	body := `{"client_name":"` + huge + `","redirect_uris":["https://e/c"]}`
	req := newJSONReq(t, body)
	_, err := Decode(req, DecodeOptions{MaxBodyBytes: 50})
	requireClampStatus(t, err, http.StatusRequestEntityTooLarge, ErrCodePayloadTooLarge)
}

func TestDecode_R2_413_DefaultCap(t *testing.T) {
	// 200KB body well above DefaultMaxBodyBytes (64KB).
	huge := strings.Repeat("x", 200_000)
	req := newJSONReq(t, `{"client_name":"`+huge+`"}`)
	_, err := Decode(req, DecodeOptions{}) // MaxBodyBytes unset → default 64KB
	requireClampStatus(t, err, http.StatusRequestEntityTooLarge, ErrCodePayloadTooLarge)
}

func TestDecode_R2_400_MalformedJSON(t *testing.T) {
	cases := []string{
		`{`,
		`{"redirect_uris":}`,
		`not json at all`,
		`{"client_name":"x"`,
	}
	for _, b := range cases {
		t.Run(b, func(t *testing.T) {
			_, err := Decode(newJSONReq(t, b), DecodeOptions{})
			requireClampStatus(t, err, http.StatusBadRequest, ErrCodeInvalidClientMetadata)
		})
	}
}

func TestDecode_R2_400_EmptyBody(t *testing.T) {
	_, err := Decode(newJSONReq(t, ""), DecodeOptions{})
	requireClampStatus(t, err, http.StatusBadRequest, ErrCodeInvalidClientMetadata)
}

func TestDecode_R2_400_NilRequest(t *testing.T) {
	_, err := Decode(nil, DecodeOptions{})
	requireClampStatus(t, err, http.StatusBadRequest, ErrCodeInvalidClientMetadata)
}

func TestDecode_R2_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
	req.Body = nil
	_, err := Decode(req, DecodeOptions{})
	requireClampStatus(t, err, http.StatusBadRequest, ErrCodeInvalidClientMetadata)
}

// ───────────────────────────────────────────────────────────────────────
// ApplyDefaults — pure function
// ───────────────────────────────────────────────────────────────────────

func TestApplyDefaults_AllPathsCovered(t *testing.T) {
	m := &RFC7591Metadata{}
	ApplyDefaults(m)
	assert.Equal(t, []string{"authorization_code"}, m.GrantTypes)
	assert.Equal(t, []string{"code"}, m.ResponseTypes)
	assert.Equal(t, "client_secret_basic", m.TokenEndpointAuthMethod)
	assert.Equal(t, "web", m.ApplicationType)
	assert.Equal(t, "", m.ClientName, "ClientName MUST stay empty — synthesised by handler post-mint")
}

func TestApplyDefaults_NilSafe(t *testing.T) {
	// no panic
	ApplyDefaults(nil)
}

// ───────────────────────────────────────────────────────────────────────
// Claude Code happy-path: pin the literal payload from R9 / cavekit-overview
// ───────────────────────────────────────────────────────────────────────

func TestDecode_ClaudeCode_LiteralPayload_DecodesAndDefaults(t *testing.T) {
	// The exact body Claude Code sends today (R9 AC).
	body := `{
		"client_name": "Claude Code",
		"redirect_uris": ["http://localhost:54212/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "none",
		"application_type": "native",
		"scope": "openid profile email offline_access"
	}`
	got, err := Decode(newJSONReq(t, body), DecodeOptions{})
	require.NoError(t, err)
	assert.Equal(t, "Claude Code", got.ClientName)
	assert.Equal(t, []string{"http://localhost:54212/callback"}, got.RedirectURIs)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, got.GrantTypes)
	assert.Equal(t, "none", got.TokenEndpointAuthMethod)
	assert.Equal(t, "native", got.ApplicationType)
	assert.Equal(t, "openid profile email offline_access", got.Scope)
}

// ───────────────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────────────

func requireClampStatus(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	require.Error(t, err)
	var ce *ClampError
	require.True(t, errors.As(err, &ce), "expected *ClampError, got %T", err)
	assert.Equal(t, wantStatus, ce.HTTPStatus())
	assert.Equal(t, wantCode, ce.Code)
}

// _ anchors io.ReadAll so the test compile-link is exercised.
var _ = io.ReadAll

// TestDecode_R2_F301_AbsoluteCeilingEnforcedEvenWithNoCap pins
// cavekit-config.md R1 amendment 2026-04-27 / F-301 — the operator's
// `MaxRequestBodyBytes=-1` opt-out disables the per-request cap but
// the dcr.AbsoluteMaxBodyBytes (100 MiB) safety net still applies.
// Without this defence-in-depth, an unauthenticated POST endpoint
// with no upper bound is a memory-exhaustion DoS one config typo away.
func TestDecode_R2_F301_AbsoluteCeilingEnforcedEvenWithNoCap(t *testing.T) {
	t.Run("MaxBodyBytes=-1 still rejects body > AbsoluteMaxBodyBytes", func(t *testing.T) {
		// Synthesize a 101 MiB body via a strings.Repeat — no actual
		// allocation needed at MaxBytesReader level, but io.ReadAll
		// will allocate. Test runs fine with allocation; if memory is
		// tight, replace with a custom io.Reader that returns infinite
		// bytes.
		oversized := strings.Repeat("x", int(AbsoluteMaxBodyBytes)+1)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")

		_, err := Decode(req, DecodeOptions{MaxBodyBytes: -1})
		require.Error(t, err)
		var ce *ClampError
		require.True(t, errors.As(err, &ce))
		assert.Equal(t, http.StatusRequestEntityTooLarge, ce.HTTPStatus(),
			"F-301: body > AbsoluteMaxBodyBytes MUST 413 even with MaxBodyBytes=-1")
		assert.Equal(t, ErrCodePayloadTooLarge, ce.Code)
	})

	t.Run("MaxBodyBytes=-1 accepts body <= AbsoluteMaxBodyBytes", func(t *testing.T) {
		// 1 MiB body — well under the 100 MiB ceiling.
		body := `{"client_name":"` + strings.Repeat("x", 1024*1024) + `","redirect_uris":["https://e/c"]}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		got, err := Decode(req, DecodeOptions{MaxBodyBytes: -1})
		require.NoError(t, err)
		require.NotNil(t, got)
	})

	t.Run("operator-set positive cap above absolute ceiling clamped down", func(t *testing.T) {
		oversized := strings.Repeat("x", int(AbsoluteMaxBodyBytes)+1)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")

		_, err := Decode(req, DecodeOptions{MaxBodyBytes: AbsoluteMaxBodyBytes * 10}) // 1 GB
		require.Error(t, err)
		var ce *ClampError
		require.True(t, errors.As(err, &ce))
		assert.Equal(t, http.StatusRequestEntityTooLarge, ce.HTTPStatus(),
			"F-301 defensive: operator caps above ceiling are clamped to ceiling")
	})
}
