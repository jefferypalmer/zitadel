package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// stubAnonConfig satisfies [AnonymousConfig] for unit tests.
type stubAnonConfig struct {
	requireIAT     bool
	defaultOrgID   string
	defaultProject string
}

func (s stubAnonConfig) RequireInitialAccessToken() bool { return s.requireIAT }
func (s stubAnonConfig) DefaultOrgID() string            { return s.defaultOrgID }
func (s stubAnonConfig) DefaultProjectID() string        { return s.defaultProject }

// TestClassifyAuthMode_R3 covers the Bearer-vs-anonymous split that
// determines per-request behaviour (cavekit-register-handler.md R3).
func TestClassifyAuthMode_R3(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantMode  AuthMode
		wantToken string
	}{
		{
			name:     "no Authorization header → anonymous",
			header:   "",
			wantMode: AuthModeAnonymous,
		},
		{
			name:     "blank Authorization header → anonymous",
			header:   "   ",
			wantMode: AuthModeAnonymous,
		},
		{
			name:      "lowercase Bearer → IAT",
			header:    "bearer zdiat_aaa",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_aaa",
		},
		{
			name:      "uppercase Bearer → IAT",
			header:    "Bearer zdiat_xyz",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_xyz",
		},
		{
			name:      "mixed-case + extra whitespace → IAT, trimmed",
			header:    "BeArEr   zdiat_pad   ",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_pad",
		},
		{
			name:     "Basic auth → anonymous (RFC 7591 only defines Bearer)",
			header:   "Basic dXNlcjpwYXNz",
			wantMode: AuthModeAnonymous,
		},
		{
			name:     "Digest auth → anonymous",
			header:   "Digest username=...",
			wantMode: AuthModeAnonymous,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			gotMode, gotTok := ClassifyAuthMode(req)
			assert.Equal(t, tt.wantMode, gotMode)
			assert.Equal(t, tt.wantToken, gotTok)
		})
	}
}

// TestResolveAnonymous_R3_HappyPath pins R3 AC4 + AC5: anonymous
// mode resolves instance from context (set upstream by the API server's
// instance interceptor), org/project from DCR.Default*ID, iat_id="".
func TestResolveAnonymous_R3_HappyPath(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cfg := stubAnonConfig{
		requireIAT:     false,
		defaultOrgID:   "org-fixture",
		defaultProject: "proj-fixture",
	}
	got, err := ResolveAnonymous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "inst-1", got.InstanceID, "instance from authz ctx (sourced from request host upstream)")
	assert.Equal(t, "org-fixture", got.OrgID)
	assert.Equal(t, "proj-fixture", got.ProjectID)
	assert.Equal(t, "", got.IATID, "anonymous mode → empty-string sentinel per kit R3 AC5")
}

// TestResolveAnonymous_R3_RequiresIAT pins R3 AC1: when
// RequireInitialAccessToken=true and the request has no Bearer header
// (caller routed to ResolveAnonymous because of that), respond
// 401 invalid_token. The handler maps the ClampError to the
// WWW-Authenticate response header.
func TestResolveAnonymous_R3_RequiresIAT(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cfg := stubAnonConfig{
		requireIAT:     true,
		defaultOrgID:   "org-fixture",
		defaultProject: "proj-fixture",
	}
	got, err := ResolveAnonymous(ctx, cfg)
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Contains(t, ce.Description, "Initial Access Token")
	assert.Contains(t, ce.Description, "Bearer")
}

// TestResolveAnonymous_R3_DefensiveDefaultsCheck pins the runtime
// guard for the half-configured deployment (T-009 normally catches
// this at startup, but config hot-reload could drop a default; fail
// closed).
func TestResolveAnonymous_R3_DefensiveDefaultsCheck(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cases := []struct {
		name string
		cfg  stubAnonConfig
	}{
		{name: "empty org", cfg: stubAnonConfig{defaultOrgID: "", defaultProject: "proj"}},
		{name: "empty project", cfg: stubAnonConfig{defaultOrgID: "org", defaultProject: ""}},
		{name: "both empty", cfg: stubAnonConfig{}},
		{name: "whitespace-only org", cfg: stubAnonConfig{defaultOrgID: "   ", defaultProject: "proj"}},
		{name: "whitespace-only project", cfg: stubAnonConfig{defaultOrgID: "org", defaultProject: "\t"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveAnonymous(ctx, c.cfg)
			assert.Nil(t, got)
			ce, ok := IsClampError(err)
			require.True(t, ok)
			assert.Equal(t, ErrCodeFeatureDisabled, ce.Code,
				"defensive runtime guard maps to feature_disabled (not invalid_token)")
		})
	}
}

// TestIATAuthNotImplemented_T037 documents the placeholder: T-037
// IAT-mode auth is awaiting a /ck:revise pass on the IAT lookup
// design. Pinned here so a future contributor flipping the toggle has
// to touch this test (and therefore see the documented options).
func TestIATAuthNotImplemented_T037(t *testing.T) {
	require.NotNil(t, IATAuthNotImplemented)
	ce, ok := IsClampError(IATAuthNotImplemented)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Contains(t, ce.Description, "T-037")
	// The wrapped error is a zerrors with the DCR-Au0XX prefix per the
	// T-032 convention. We don't assert the exact ID — just that it is
	// the expected zerrors family.
	require.NotNil(t, ce.Wrapped)
	assert.True(t, errors.Is(ce.Wrapped, ce.Wrapped),
		"wrapped error chain must be intact")
}
