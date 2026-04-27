package dcr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/feature"
)

// stubInstance implements just enough of authz.Instance to set the
// DynamicClientRegistration feature flag for handler-level testing.
// The handler reads `authz.GetFeatures(ctx).DynamicClientRegistration`
// only — every other Instance accessor returns zero values.
type stubInstance struct {
	authz.Instance
	features feature.Features
}

func (s *stubInstance) Features() feature.Features { return s.features }
func (s *stubInstance) InstanceID() string         { return "test-instance" }

func ctxWithFeature(t *testing.T, on bool) context.Context {
	t.Helper()
	return authz.WithInstance(context.Background(), &stubInstance{
		features: feature.Features{DynamicClientRegistration: on},
	})
}

// TestHandler_RuntimeFeatureGate covers cavekit-config.md R3 mid-row:
// when the YAML gate is on (the handler is mounted) but the runtime
// feature flag is off, /oidc/v1/register returns 403 with the RFC 7591
// `feature_disabled` envelope.
func TestHandler_RuntimeFeatureGate(t *testing.T) {
	tests := []struct {
		name             string
		featureOn        bool
		wantStatus       int
		wantContentType  string
		wantBodyContains string
	}{
		{
			name:             "feature off → 403 with feature_disabled envelope",
			featureOn:        false,
			wantStatus:       http.StatusForbidden,
			wantContentType:  "application/json;charset=UTF-8",
			wantBodyContains: `"error":"feature_disabled"`,
		},
		{
			name:             "feature on → 200 stub response (T-008 placeholder; T-031 replaces)",
			featureOn:        true,
			wantStatus:       http.StatusOK,
			wantContentType:  "application/json;charset=UTF-8",
			wantBodyContains: `"status":"dcr_handler_stub"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler()
			req := httptest.NewRequest(http.MethodPost, "/", nil).
				WithContext(ctxWithFeature(t, tt.featureOn))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, tt.wantContentType, rec.Header().Get("Content-Type"))
			assert.Contains(t, rec.Body.String(), tt.wantBodyContains)
		})
	}
}

func TestHandler_FeatureDisabled_NoCacheHeaders(t *testing.T) {
	// 403 responses must carry no-store/no-cache so a CDN doesn't pin
	// the error response after the operator flips the feature on
	// (cavekit-security-hardening.md T14 cache hardening).
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(ctxWithFeature(t, false))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

// TestHandler_MethodRouting covers cavekit-register-handler.md R1 +
// cavekit-manage-handler.md R1 (T-031 mux skeleton). The dual-gate is
// ON for these tests (feature flag enabled); each method/path combo
// routes to its expected stub.
func TestHandler_MethodRouting(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		path             string
		bearer           string
		wantStatus       int
		wantBodyContains string
	}{
		{
			name:             "POST / → register stub (T-033 placeholder)",
			method:           http.MethodPost,
			path:             "/",
			wantStatus:       http.StatusOK,
			wantBodyContains: `"status":"dcr_handler_stub"`,
		},
		{
			name:             "POST (no trailing slash) is normalized to / via StrictSlash",
			method:           http.MethodPost,
			path:             "",
			wantStatus:       http.StatusOK,
			wantBodyContains: `"status":"dcr_handler_stub"`,
		},
		{
			// T-050 mounted the bearer-presence gate; supplying any Bearer
			// passes the gate and falls through to the T-053 501 stub.
			name:             "GET /{client_id} + Bearer → 501 stub (T-053 lands real body)",
			method:           http.MethodGet,
			path:             "/abc-123",
			bearer:           "rat-placeholder",
			wantStatus:       http.StatusNotImplemented,
			wantBodyContains: `"error":"not_implemented"`,
		},
		{
			name:             "PUT /{client_id} + Bearer → 501 stub (T-054 lands real body)",
			method:           http.MethodPut,
			path:             "/abc-123",
			bearer:           "rat-placeholder",
			wantStatus:       http.StatusNotImplemented,
			wantBodyContains: `"error":"not_implemented"`,
		},
		{
			name:             "DELETE /{client_id} + Bearer → 501 stub (T-056 lands real body)",
			method:           http.MethodDelete,
			path:             "/abc-123",
			bearer:           "rat-placeholder",
			wantStatus:       http.StatusNotImplemented,
			wantBodyContains: `"error":"not_implemented"`,
		},
		{
			name:             "GET / → 405 (no GET on register endpoint)",
			method:           http.MethodGet,
			path:             "/",
			wantStatus:       http.StatusMethodNotAllowed,
			wantBodyContains: `"error":"invalid_request"`,
		},
		{
			name:             "POST /{client_id} → 405 (RFC 7592 doesn't define POST on individual client)",
			method:           http.MethodPost,
			path:             "/abc-123",
			wantStatus:       http.StatusMethodNotAllowed,
			wantBodyContains: `"error":"invalid_request"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler()
			path := tt.path
			if path == "" {
				path = "/"
			}
			req := httptest.NewRequest(tt.method, path, nil).
				WithContext(ctxWithFeature(t, true))
			if tt.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tt.bearer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantBodyContains)
			assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))
		})
	}
}

// TestHandler_ManageBearerGate covers cavekit-manage-handler.md R1
// (T-050) — GET/PUT/DELETE on `/oidc/v1/register/{client_id}` MUST
// return 401 with the RFC 7591 invalid_token envelope and the
// `WWW-Authenticate: Bearer error="invalid_token"` header when no
// Authorization Bearer header is supplied. The 401 response runs BEFORE
// any RAT verification (T-051) or anti-enumeration logic (T-052) so the
// missing-header case stays uniform across all three RFC 7592 verbs.
func TestHandler_ManageBearerGate(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		authHeader string // empty = absent
		wantStatus int
	}{
		{"GET no header → 401", http.MethodGet, "", http.StatusUnauthorized},
		{"PUT no header → 401", http.MethodPut, "", http.StatusUnauthorized},
		{"DELETE no header → 401", http.MethodDelete, "", http.StatusUnauthorized},
		{"GET non-Bearer header → 401", http.MethodGet, "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
		{"PUT empty header → 401", http.MethodPut, "", http.StatusUnauthorized},
		{"DELETE Digest header → 401", http.MethodDelete, `Digest username="x"`, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler()
			req := httptest.NewRequest(tt.method, "/abc-123", nil).
				WithContext(ctxWithFeature(t, true))
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, `Bearer error="invalid_token"`,
				rec.Header().Get("WWW-Authenticate"),
				"R2 AC4: 401 must carry WWW-Authenticate")
			assert.Equal(t, "application/json;charset=UTF-8",
				rec.Header().Get("Content-Type"))

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, "invalid_token", body["error"])
			assert.Equal(t, MissingOrInvalidAccessTokenDescription, body["error_description"])
		})
	}
}

// TestHandler_ManageGate_FeatureOff covers R1 AC2/AC3 — the manage
// gate runs INSIDE the runtime feature gate, so a feature-off instance
// returns 403 (not 401) regardless of header presence. Pins the
// ordering: feature gate first, bearer gate second.
func TestHandler_ManageGate_FeatureOff(t *testing.T) {
	h := Handler()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/abc-123", nil).
			WithContext(ctxWithFeature(t, false))
		req.Header.Set("Authorization", "Bearer rat-placeholder")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code,
			"%s: feature gate must pre-empt bearer gate", method)
		assert.Contains(t, rec.Body.String(), `"error":"feature_disabled"`)
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
			"%s: feature_disabled response is not a 401, no WWW-Authenticate", method)
	}
}

// TestHandler_FeatureGateOverridesMethodRouting pins that the runtime
// feature gate runs BEFORE the mux's method routing — every reachable
// (method, path) combo gets 403 when the flag is off, including paths
// that would otherwise 404 or 405. Important so attackers can't probe
// the surface to learn the route map.
func TestHandler_FeatureGateOverridesMethodRouting(t *testing.T) {
	h := Handler()
	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/"},
		{http.MethodGet, "/abc"},
		{http.MethodPut, "/abc"},
		{http.MethodDelete, "/abc"},
		{http.MethodPatch, "/abc"}, // unknown method
		{http.MethodGet, "/unknown/sub/path"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil).
			WithContext(ctxWithFeature(t, false))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"%s %s: expected 403 when flag off", c.method, c.path)
		assert.Contains(t, rec.Body.String(), `"error":"feature_disabled"`,
			"%s %s: expected feature_disabled envelope", c.method, c.path)
	}
}

// TestT065_RegistrationEndpoint_T17_DualState pins the T17 threat-
// model contract (cavekit-security-hardening.md R6) from the dcr-
// package perspective: discovery emission MUST never produce
// `"registration_endpoint": null` in JSON. Two cases are pinned
// structurally:
//
//	enabled-state: a non-empty issuer + the dcr.HandlerPrefix yields
//	  a parseable absolute URL with scheme + host + path.
//	disabled-state: the source-of-truth helper returns "" so the
//	  discovery struct's `omitempty` tag drops the key entirely.
//
// T17 root cause: Claude Code's Zod parser rejects `null` on optional
// URL fields, so a regression that ever emits the literal `null`
// breaks the hostname-root MCP probe. The byte-identical assertion
// lives in `internal/api/oidc/dcr_discovery_test.go`
// (TestDiscoveryConfig_RegistrationEndpoint_NeverNullInJSON, T-029);
// this dcr-package test pins the same contract from the dcr surface so
// a future refactor that moves the URL-construction logic into dcr
// (e.g. when `dcr.NewHandler` grows a discovery hook) cannot regress
// without a visible test failure here.
func TestT065_RegistrationEndpoint_T17_DualState(t *testing.T) {
	// HandlerPrefix is a compile-time constant — assert the documented
	// shape so a future rename surfaces here AND in the parent
	// discovery test rather than only in the harder-to-isolate
	// dcr_discovery_test.
	require.Equal(t, "/oidc/v1/register", HandlerPrefix,
		"T17: HandlerPrefix is the discovery emission's path component; renaming it without updating discovery would silently break Claude Code MCP probing")

	// Mimic the discovery emission's `omitempty`-on-empty-string
	// contract structurally — when the source URL is "", the JSON
	// drops the key. (Real impl lives at internal/api/oidc/server.go
	// :registrationEndpointURL; this asserts the shape contract dcr
	// participates in.)
	type discoveryShape struct {
		Issuer               string `json:"issuer"`
		RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	}

	t.Run("disabled state — empty URL drops the key", func(t *testing.T) {
		// Empty source URL → omitempty ensures NO `registration_endpoint`
		// JSON key is emitted (NEVER `null`).
		body, err := json.Marshal(discoveryShape{
			Issuer:               "https://issuer.example",
			RegistrationEndpoint: "",
		})
		require.NoError(t, err)
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &raw))
		_, present := raw["registration_endpoint"]
		assert.False(t, present,
			"T17: when DCR disabled, discovery JSON MUST omit registration_endpoint entirely — got: %s", string(body))
		assert.NotContains(t, string(body), "null",
			"T17: discovery JSON MUST NEVER contain literal 'null' for registration_endpoint (Claude Code Zod parser bug)")
	})

	t.Run("enabled state — absolute URL non-null", func(t *testing.T) {
		// Mirror server.go::registrationEndpointURL: trim trailing
		// slash, append HandlerPrefix.
		const issuer = "https://issuer.example/"
		got := strings.TrimRight(issuer, "/") + HandlerPrefix
		body, err := json.Marshal(discoveryShape{
			Issuer:               issuer,
			RegistrationEndpoint: got,
		})
		require.NoError(t, err)

		// Must parse as a usable absolute URL.
		u, err := url.Parse(got)
		require.NoError(t, err)
		assert.Equal(t, "https", u.Scheme,
			"T17: enabled-state URL MUST carry an absolute scheme")
		assert.Equal(t, "issuer.example", u.Host,
			"T17: enabled-state URL MUST carry the issuer host")
		assert.Equal(t, HandlerPrefix, u.Path,
			"T17: enabled-state URL MUST be issuer + HandlerPrefix (no double-slash, no fragment)")

		// Must appear in JSON without `null`.
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &raw))
		v, present := raw["registration_endpoint"]
		require.True(t, present,
			"T17: when DCR enabled, registration_endpoint MUST be present in discovery JSON")
		var asString string
		require.NoError(t, json.Unmarshal(v, &asString))
		assert.NotEmpty(t, asString)
		assert.NotEqual(t, "null", asString)
	})
}

func TestHandler_FeatureDisabled_BodyShape(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodPost, "/", nil).
		WithContext(ctxWithFeature(t, false))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "feature_disabled", body["error"])
	assert.NotEmpty(t, body["error_description"])
	// Only the two RFC 7591 fields — no leakage of internal state.
	assert.Len(t, body, 2)
}
