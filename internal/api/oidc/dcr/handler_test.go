package dcr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", nil).
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
	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/register", nil).
		WithContext(ctxWithFeature(t, false))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

func TestHandler_FeatureDisabled_BodyShape(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", nil).
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
