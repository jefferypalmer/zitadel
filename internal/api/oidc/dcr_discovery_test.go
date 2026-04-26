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
