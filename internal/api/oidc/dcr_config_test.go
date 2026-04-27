package oidc

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDCRConfig_Validate_R4_AnonymousModeNeedsDefaults(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DCRConfig
		wantErr bool
		wantMsg string
	}{
		{
			name:    "disabled — no validation",
			cfg:     DCRConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "enabled + IAT-required — defaults optional",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: true,
			},
			wantErr: false,
		},
		{
			name: "enabled + anonymous + both defaults — ok",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: false,
				DefaultProjectID:          "p",
				DefaultOrgID:              "o",
			},
			wantErr: false,
		},
		{
			name: "enabled + anonymous + empty DefaultProjectID — refuse",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: false,
				DefaultProjectID:          "",
				DefaultOrgID:              "o",
			},
			wantErr: true,
			wantMsg: "OIDC.DCR.DefaultProjectID",
		},
		{
			name: "enabled + anonymous + empty DefaultOrgID — refuse",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: false,
				DefaultProjectID:          "p",
				DefaultOrgID:              "",
			},
			wantErr: true,
			wantMsg: "OIDC.DCR.DefaultOrgID",
		},
		{
			name: "enabled + anonymous + both empty — refuse, names both",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: false,
			},
			wantErr: true,
			wantMsg: "DefaultProjectID, OIDC.DCR.DefaultOrgID",
		},
		{
			name: "whitespace-only defaults treated as empty",
			cfg: DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: false,
				DefaultProjectID:          "   ",
				DefaultOrgID:              "\t\n",
			},
			wantErr: true,
			wantMsg: "OIDC.DCR.DefaultProjectID, OIDC.DCR.DefaultOrgID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate called with a harmless externalDomain (R5 does not fire).
			err := tt.cfg.Validate(context.Background(), true, "example.com", 443)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDCRConfig_Validate_R5_IssuerPathWarning(t *testing.T) {
	type wantWarn struct {
		emit        bool
		substrURL   string
		substrIssue string
	}
	tests := []struct {
		name           string
		enabled        bool
		externalDomain string
		externalSecure bool
		externalPort   uint16
		want           wantWarn
	}{
		{
			name:           "disabled — never warn",
			enabled:        false,
			externalDomain: "example.com/zitadel",
			externalSecure: true,
			externalPort:   443,
			want:           wantWarn{emit: false},
		},
		{
			name:           "enabled + hostname-root — no warn",
			enabled:        true,
			externalDomain: "example.com",
			externalSecure: true,
			externalPort:   443,
			want:           wantWarn{emit: false},
		},
		{
			name:           "enabled + ExternalDomain with slash — warn, names hostname-root probe URL",
			enabled:        true,
			externalDomain: "example.com/zitadel",
			externalSecure: true,
			externalPort:   443,
			want: wantWarn{
				emit:        true,
				substrURL:   "https://example.com/.well-known/oauth-authorization-server",
				substrIssue: "hostname ROOT",
			},
		},
		{
			name:           "enabled + slash + non-standard port — warn keeps host:port, strips path",
			enabled:        true,
			externalDomain: "example.com/zitadel",
			externalSecure: true,
			externalPort:   8443,
			want: wantWarn{
				emit:        true,
				substrURL:   "https://example.com:8443/.well-known/oauth-authorization-server",
				substrIssue: "hostname ROOT",
			},
		},
		{
			name:           "enabled + slash + plain http + standard 80 — scheme/port correct",
			enabled:        true,
			externalDomain: "example.com/zitadel",
			externalSecure: false,
			externalPort:   80,
			want: wantWarn{
				emit:        true,
				substrURL:   "http://example.com/.well-known/oauth-authorization-server",
				substrIssue: "hostname ROOT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DCRConfig{
				Enabled:                   tt.enabled,
				RequireInitialAccessToken: true, // bypass R4
				MaxRequestBodyBytes:       65536,
			}
			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			old := slog.Default()
			slog.SetDefault(logger)
			defer slog.SetDefault(old)

			err := cfg.Validate(context.Background(), tt.externalSecure, tt.externalDomain, tt.externalPort)
			require.NoError(t, err)

			got := buf.String()
			if tt.want.emit {
				assert.Contains(t, got, `level=WARN`, "expected a WARN line")
				assert.Contains(t, got, tt.want.substrURL)
				assert.Contains(t, got, tt.want.substrIssue)
			} else {
				assert.False(t, strings.Contains(got, "level=WARN"),
					"did not expect a WARN line; got: %s", got)
			}
		})
	}
}

// TestDCRConfig_NoTLSKnobs_R10 pins cavekit-register-handler.md R10
// AC2: "No DCR-specific TLS configuration knobs exist." The DCR handler
// inherits Zitadel's overall TLS posture from cmd/start (config.TLS,
// config.ExternalSecure, the http.Server TLSConfig) — adding a
// DCR-specific TLS field would break the R10 invariant by allowing
// /oidc/v1/register to be served over a different TLS configuration
// than /oidc/v1/userinfo.
//
// This test scans the DCRConfig fields by reflection and fails if any
// future field name contains "TLS", "Cert", "Key" (in a transport
// sense), or "HTTPS". The whitelist below tracks legitimate non-TLS
// uses of "Key" (cf. RegistrationAccessToken) so the substring scan
// remains tight.
func TestDCRConfig_NoTLSKnobs_R10(t *testing.T) {
	cfg := DCRConfig{}
	rt := reflect.TypeOf(cfg)
	tlsIsh := []string{"TLS", "Cert", "HTTPS", "Insecure", "MTLS", "Mtls"}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		for _, needle := range tlsIsh {
			assert.False(t, strings.Contains(name, needle),
				"DCRConfig.%s appears to be a TLS knob (%q); R10 forbids DCR-specific TLS configuration. "+
					"DCR inherits Zitadel's overall TLS posture (cmd/start config.TLS / config.ExternalSecure).",
				name, needle)
		}
	}
	// Same scan on the nested DCRJwksURIConfig — the only sub-struct that
	// could plausibly grow a TLS knob (because it makes outbound HTTPS
	// calls). The SSRF guard from T-015 governs JWKS-fetch hardening; the
	// Zitadel host's inbound TLS posture is unaffected.
	jt := reflect.TypeOf(DCRJwksURIConfig{})
	for i := 0; i < jt.NumField(); i++ {
		name := jt.Field(i).Name
		for _, needle := range tlsIsh {
			assert.False(t, strings.Contains(name, needle),
				"DCRJwksURIConfig.%s contains %q — outbound JWKS-fetch hardening lives in the SSRF guard, "+
					"not in TLS-specific DCR config (R10 forbids DCR-specific TLS knobs).",
				name, needle)
		}
	}
}

// TestDCRConfig_Validate_R1_F204_MaxRequestBodyBytes_Sentinel pins the
// cavekit-config.md R1 amendment 2026-04-27 / F-204 — MaxRequestBodyBytes
// sentinel semantics. 0 is INVALID at startup (it silently triggered a
// 64 KiB default fallback in earlier builds, hiding operator intent).
// To disable the cap entirely, set -1. Any other negative is invalid.
func TestDCRConfig_Validate_R1_F204_MaxRequestBodyBytes_Sentinel(t *testing.T) {
	tests := []struct {
		name    string
		v       int64
		wantErr bool
		errSubs string
	}{
		{"positive cap (default 65536) — accepted", 65536, false, ""},
		{"positive cap (small) — accepted", 1024, false, ""},
		{"-1 = no cap — accepted", -1, false, ""},
		{"0 — REJECTED (silent default fallback was the F-204 bug)", 0, true, "must be > 0"},
		{"-2 — REJECTED (only -1 disables cap)", -2, true, "is invalid"},
		{"-65536 — REJECTED", -65536, true, "is invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DCRConfig{
				Enabled:                   true,
				RequireInitialAccessToken: true, // bypass R4
				MaxRequestBodyBytes:       tt.v,
			}
			err := cfg.Validate(context.Background(), true, "example.com", 443)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubs)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestDCRConfig_Validate_R1_F300_ClientSecretExpiresIn_NonNegative pins
// the cavekit-config.md R1 amendment 2026-04-27 / F-300 — negative
// ClientSecretExpiresIn MUST be refused at startup. A misconfigured
// `-24h` would otherwise flow through F-201's plumbing and advertise
// a freshly-issued secret as already expired (RFC 7591 §3.2.1 spec
// breach + RP availability bug).
func TestDCRConfig_Validate_R1_F300_ClientSecretExpiresIn_NonNegative(t *testing.T) {
	tests := []struct {
		name    string
		v       time.Duration
		wantErr bool
	}{
		{"zero — accepted (no expiry sentinel)", 0, false},
		{"positive 24h — accepted", 24 * time.Hour, false},
		{"positive small — accepted", 1 * time.Second, false},
		{"-1ns — REJECTED (any negative is invalid)", -1 * time.Nanosecond, true},
		{"-24h — REJECTED", -24 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DCRConfig{
				Enabled:                   true,
				MaxRequestBodyBytes:       65536,
				RequireInitialAccessToken: true,
				ClientSecretExpiresIn:     tt.v,
			}
			err := cfg.Validate(context.Background(), true, "example.com", 443)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "ClientSecretExpiresIn")
				assert.Contains(t, err.Error(), "non-negative")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestDCRConfig_Validate_R1_F402_PositiveExceedsCeiling pins the
// cavekit-config.md R1 amendment 2026-04-27 / F-402 — positive
// MaxRequestBodyBytes values that exceed dcr.AbsoluteMaxBodyBytes
// (100 MiB) MUST refuse at startup, NOT silently runtime-clamp.
// Mirrors the F-204 precedent: operator-set value the package
// cannot honour is a startup-refuse condition.
func TestDCRConfig_Validate_R1_F402_PositiveExceedsCeiling(t *testing.T) {
	const ceiling int64 = 100 * 1024 * 1024
	tests := []struct {
		name    string
		v       int64
		wantErr bool
	}{
		{"exactly at ceiling — accepted", ceiling, false},
		{"1 byte under ceiling — accepted", ceiling - 1, false},
		{"1 byte over ceiling — REJECTED", ceiling + 1, true},
		{"1 GB — REJECTED", 1024 * 1024 * 1024, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DCRConfig{
				Enabled:                   true,
				RequireInitialAccessToken: true,
				MaxRequestBodyBytes:       tt.v,
			}
			err := cfg.Validate(context.Background(), true, "example.com", 443)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "exceeds the package safety ceiling")
				assert.Contains(t, err.Error(), "F-402")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestDCRConfig_Validate_R1_F301_StartupWARN_OnNoCap pins the
// cavekit-config.md R1 amendment 2026-04-27 / F-301 startup-WARN AC.
// When MaxRequestBodyBytes=-1 is configured, Validate MUST emit a
// WARN log naming OIDC.DCR.MaxRequestBodyBytes and the absolute
// ceiling value, so an operator who set -1 accidentally sees the
// trade-off at boot. Without this test, F-301c had no regression
// guard (flagged in the 4th /ck:check pass).
func TestDCRConfig_Validate_R1_F301_StartupWARN_OnNoCap(t *testing.T) {
	t.Run("MaxRequestBodyBytes=-1 emits WARN", func(t *testing.T) {
		cfg := DCRConfig{
			Enabled:                   true,
			RequireInitialAccessToken: true,
			MaxRequestBodyBytes:       -1,
		}
		buf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		old := slog.Default()
		slog.SetDefault(logger)
		defer slog.SetDefault(old)

		err := cfg.Validate(context.Background(), true, "example.com", 443)
		require.NoError(t, err)

		got := buf.String()
		assert.Contains(t, got, "level=WARN", "F-301c: WARN line MUST emit on -1")
		assert.Contains(t, got, "OIDC.DCR.MaxRequestBodyBytes",
			"F-301c: WARN MUST name the field for operator triage")
		assert.Contains(t, got, "absolute_ceiling_bytes=104857600",
			"F-301c: WARN MUST name the absolute ceiling so operator sees the safety net value")
		assert.Contains(t, got, "F-301", "F-301c: WARN MUST cross-reference the kit AC")
	})

	t.Run("positive value (default 65536) does NOT emit WARN", func(t *testing.T) {
		cfg := DCRConfig{
			Enabled:                   true,
			RequireInitialAccessToken: true,
			MaxRequestBodyBytes:       65536,
		}
		buf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		old := slog.Default()
		slog.SetDefault(logger)
		defer slog.SetDefault(old)

		err := cfg.Validate(context.Background(), true, "example.com", 443)
		require.NoError(t, err)
		assert.False(t, strings.Contains(buf.String(), "MaxRequestBodyBytes"),
			"WARN MUST NOT fire for normal positive values")
	})
}
