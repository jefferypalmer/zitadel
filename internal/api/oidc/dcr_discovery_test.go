package oidc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/feature"
)

// TestServer_registrationEndpointURL pins cavekit-discovery-and-as-metadata.md
// R1 (T-029) dual-gate behavior at the helper level: yaml-off → "",
// yaml-on + flag-off → "", both-on → issuer + dcr.HandlerPrefix.
func TestServer_registrationEndpointURL(t *testing.T) {
	tests := []struct {
		name       string
		dcrEnabled bool
		flag       bool
		issuer     string
		want       string
	}{
		{
			name:       "yaml off → empty (omitempty drops the JSON key)",
			dcrEnabled: false,
			flag:       true,
			issuer:     "https://issuer.example.com",
			want:       "",
		},
		{
			name:       "yaml on, runtime flag off → empty",
			dcrEnabled: true,
			flag:       false,
			issuer:     "https://issuer.example.com",
			want:       "",
		},
		{
			name:       "both gates on → issuer + register prefix",
			dcrEnabled: true,
			flag:       true,
			issuer:     "https://issuer.example.com",
			want:       "https://issuer.example.com/oidc/v1/register",
		},
		{
			name:       "issuer with trailing slash is normalized",
			dcrEnabled: true,
			flag:       true,
			issuer:     "https://issuer.example.com/",
			want:       "https://issuer.example.com/oidc/v1/register",
		},
		{
			name:       "no issuer in ctx → empty (defensive)",
			dcrEnabled: true,
			flag:       true,
			issuer:     "",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{dcrEnabled: tt.dcrEnabled}
			ctx := context.Background()
			if tt.issuer != "" {
				ctx = op.ContextWithIssuer(ctx, tt.issuer)
			}
			ctx = authz.WithFeatures(ctx, feature.Features{DynamicClientRegistration: tt.flag})
			assert.Equal(t, tt.want, s.registrationEndpointURL(ctx))
		})
	}
}

// TestDiscoveryConfig_RegistrationEndpoint_NeverNullInJSON pins R1 AC3:
// the JSON body NEVER contains `"registration_endpoint": null` — only an
// absolute URL string or absence (Claude Code Zod parser bug GH#38102).
func TestDiscoveryConfig_RegistrationEndpoint_NeverNullInJSON(t *testing.T) {
	tests := []struct {
		name       string
		dcrEnabled bool
		flag       bool
		wantKey    bool
		wantValue  string
	}{
		{
			name:       "DCR disabled — key absent",
			dcrEnabled: false,
			flag:       true,
			wantKey:    false,
		},
		{
			name:       "yaml on, flag off — key absent",
			dcrEnabled: true,
			flag:       false,
			wantKey:    false,
		},
		{
			name:       "both gates on — key present with absolute URL",
			dcrEnabled: true,
			flag:       true,
			wantKey:    true,
			wantValue:  "https://issuer.example.com/oidc/v1/register",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{dcrEnabled: tt.dcrEnabled}
			ctx := op.ContextWithIssuer(context.Background(), "https://issuer.example.com")
			ctx = authz.WithFeatures(ctx, feature.Features{DynamicClientRegistration: tt.flag})

			cfg := &oidc.DiscoveryConfiguration{
				Issuer:               "https://issuer.example.com",
				RegistrationEndpoint: s.registrationEndpointURL(ctx),
			}
			body, err := json.Marshal(cfg)
			require.NoError(t, err)

			var raw map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(body, &raw))

			if !tt.wantKey {
				assert.NotContains(t, raw, "registration_endpoint",
					"json must omit the key entirely (omitempty), got: %s", body)
				assert.False(t, strings.Contains(string(body), "registration_endpoint"),
					"raw body should not even mention the key, got: %s", body)
				return
			}
			require.Contains(t, raw, "registration_endpoint")
			var got string
			require.NoError(t, json.Unmarshal(raw["registration_endpoint"], &got))
			assert.Equal(t, tt.wantValue, got)
			assert.True(t, strings.HasPrefix(got, "https://"), "must be absolute URL")
		})
	}
}

// TestDiscoveryAndAsMetadata_R3_SharedFieldsByteIdentical pins
// cavekit-discovery-and-as-metadata.md R3: when DCR is enabled, the
// OIDC discovery and RFC 8414 AS metadata documents MUST share byte-
// identical values for the five fields that overlap (issuer,
// authorization_endpoint, token_endpoint, jwks_uri,
// registration_endpoint). Divergence breaks Claude Code MCP probing.
//
// Both documents are produced from the same Server fixture (same
// Endpoints + same op.IssuerFromContext) so a byte-identity assertion
// here will catch anyone who later wires one document to a different
// source than the other.
func TestDiscoveryAndAsMetadata_R3_SharedFieldsByteIdentical(t *testing.T) {
	s := newServerFixtureForR3(t, true /*dcrEnabled*/)
	ctx := op.ContextWithIssuer(context.Background(), "https://issuer.example.com")
	ctx = authz.WithFeatures(ctx, feature.Features{DynamicClientRegistration: true})

	disc := s.createDiscoveryConfig(ctx, nil)
	asMd := s.AsMetadata(ctx)

	// Direct struct-field byte equality on the five shared fields.
	assert.Equal(t, disc.Issuer, asMd.Issuer, "issuer must match")
	assert.Equal(t, disc.AuthorizationEndpoint, asMd.AuthorizationEndpoint, "authorization_endpoint must match")
	assert.Equal(t, disc.TokenEndpoint, asMd.TokenEndpoint, "token_endpoint must match")
	assert.Equal(t, disc.JwksURI, asMd.JwksURI, "jwks_uri must match")
	assert.Equal(t, disc.RegistrationEndpoint, asMd.RegistrationEndpoint, "registration_endpoint must match")

	// Cross-check via JSON: marshal each, then assert the five shared
	// keys carry byte-identical RawMessage values. This catches a future
	// regression where a struct-tag rename or custom MarshalJSON would
	// produce different on-the-wire bytes for the same field.
	discJSON, err := json.Marshal(disc)
	require.NoError(t, err)
	asJSON, err := json.Marshal(asMd)
	require.NoError(t, err)

	var discRaw, asRaw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(discJSON, &discRaw))
	require.NoError(t, json.Unmarshal(asJSON, &asRaw))

	shared := []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "registration_endpoint"}
	for _, key := range shared {
		discVal, hasDisc := discRaw[key]
		asVal, hasAs := asRaw[key]
		require.True(t, hasDisc, "discovery doc missing %q", key)
		require.True(t, hasAs, "AS metadata doc missing %q", key)
		assert.JSONEq(t, string(discVal), string(asVal), "shared field %q must be byte-identical", key)
	}
}

// TestDiscoveryAndAsMetadata_R3_BothOmitRegistrationWhenDisabled pins
// cavekit-discovery-and-as-metadata.md R3 AC3: when DCR is disabled by
// EITHER gate (yaml-off or runtime-flag-off), BOTH documents must omit
// the `registration_endpoint` key (key absent, never `null` per Claude
// Code Zod parser bug GH#38102).
func TestDiscoveryAndAsMetadata_R3_BothOmitRegistrationWhenDisabled(t *testing.T) {
	cases := []struct {
		name       string
		dcrEnabled bool
		flag       bool
	}{
		{name: "yaml off, flag on", dcrEnabled: false, flag: true},
		{name: "yaml on, flag off", dcrEnabled: true, flag: false},
		{name: "both gates off", dcrEnabled: false, flag: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServerFixtureForR3(t, c.dcrEnabled)
			ctx := op.ContextWithIssuer(context.Background(), "https://issuer.example.com")
			ctx = authz.WithFeatures(ctx, feature.Features{DynamicClientRegistration: c.flag})

			disc := s.createDiscoveryConfig(ctx, nil)
			asMd := s.AsMetadata(ctx)

			// Helper-level assertion: builder returned "" so omitempty drops the key.
			assert.Equal(t, "", disc.RegistrationEndpoint, "discovery RegistrationEndpoint must be empty when dual-gate fails")
			assert.Equal(t, "", asMd.RegistrationEndpoint, "AS metadata RegistrationEndpoint must be empty when dual-gate fails")

			// JSON-level assertion: the key is absent and the literal
			// substring "registration_endpoint" never appears in either body.
			discJSON, err := json.Marshal(disc)
			require.NoError(t, err)
			asJSON, err := json.Marshal(asMd)
			require.NoError(t, err)

			assert.False(t, strings.Contains(string(discJSON), "registration_endpoint"),
				"discovery body must omit key entirely, body=%s", discJSON)
			assert.False(t, strings.Contains(string(asJSON), "registration_endpoint"),
				"AS metadata body must omit key entirely, body=%s", asJSON)

			// Defensive: never `"registration_endpoint": null`.
			assert.False(t, strings.Contains(string(discJSON), `"registration_endpoint":null`),
				"discovery must never emit null, body=%s", discJSON)
			assert.False(t, strings.Contains(string(asJSON), `"registration_endpoint":null`),
				"AS metadata must never emit null, body=%s", asJSON)
		})
	}
}

// newServerFixtureForR3 builds the minimum Server needed to exercise
// both createDiscoveryConfig and AsMetadata. Mirrors the fixture in
// TestServer_createDiscoveryConfig (server_test.go) so the two test
// surfaces stay aligned.
func newServerFixtureForR3(t *testing.T, dcrEnabled bool) *Server {
	t.Helper()
	//nolint:staticcheck // op.NewForwardedOpenIDProvider is the
	// codebase-standard fixture path; the linter flags it as deprecated
	// but server_test.go uses it for the same reason.
	provider, _ := op.NewForwardedOpenIDProvider("path",
		&op.Config{
			CodeMethodS256:          true,
			AuthMethodPost:          true,
			AuthMethodPrivateKeyJWT: true,
			GrantTypeRefreshToken:   true,
			RequestObjectSupported:  true,
		},
		nil,
	)
	return &Server{
		LegacyServer: op.NewLegacyServer(
			provider,
			op.Endpoints{
				Authorization:       op.NewEndpoint("auth"),
				Token:               op.NewEndpoint("token"),
				Introspection:       op.NewEndpoint("introspect"),
				Userinfo:            op.NewEndpoint("userinfo"),
				Revocation:          op.NewEndpoint("revoke"),
				EndSession:          op.NewEndpoint("logout"),
				JwksURI:             op.NewEndpoint("keys"),
				DeviceAuthorization: op.NewEndpoint("device"),
			},
		),
		signingKeyAlgorithm: "RS256",
		dcrEnabled:          dcrEnabled,
	}
}

// TestDcrAdvertised_DualGateMatrix is the symmetric dual-gate truth table.
// Both /authorize discovery (R1) and the AS metadata handler (R2 / T-030)
// will share this predicate so the two documents cannot diverge (R3).
func TestDcrAdvertised_DualGateMatrix(t *testing.T) {
	cases := []struct {
		yaml bool
		flag bool
		want bool
	}{
		{yaml: false, flag: false, want: false},
		{yaml: false, flag: true, want: false},
		{yaml: true, flag: false, want: false},
		{yaml: true, flag: true, want: true},
	}
	for _, c := range cases {
		s := &Server{dcrEnabled: c.yaml}
		ctx := authz.WithFeatures(context.Background(), feature.Features{DynamicClientRegistration: c.flag})
		assert.Equal(t, c.want, s.dcrAdvertised(ctx),
			"yaml=%v flag=%v → want %v", c.yaml, c.flag, c.want)
	}
}
