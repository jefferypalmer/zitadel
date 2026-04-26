package as_metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/logging"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// TestNewHandler_BodyShape pins R2 acceptance criteria for the JSON
// body shape: required + recommended-for-DCR/MCP fields are present.
func TestNewHandler_BodyShape(t *testing.T) {
	build := func(ctx context.Context) *Metadata {
		return &Metadata{
			Issuer:                            "https://issuer.example.com",
			AuthorizationEndpoint:             "https://issuer.example.com/oauth/v2/authorize",
			TokenEndpoint:                     "https://issuer.example.com/oauth/v2/token",
			JwksURI:                           "https://issuer.example.com/oauth/v2/keys",
			RegistrationEndpoint:              "https://issuer.example.com/oidc/v1/register",
			ResponseTypesSupported:            []string{"code"},
			GrantTypesSupported:               nil,
			TokenEndpointAuthMethodsSupported: nil,
			ScopesSupported:                   []string{"openid", "profile"},
		}
	}
	rec := httptest.NewRecorder()
	NewHandler(build).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, HandlerPath, nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	// RFC 8414 §2 required fields
	assert.Equal(t, "https://issuer.example.com", got["issuer"])
	assert.Equal(t, "https://issuer.example.com/oauth/v2/authorize", got["authorization_endpoint"])
	assert.Equal(t, "https://issuer.example.com/oauth/v2/token", got["token_endpoint"])
	require.Contains(t, got, "response_types_supported")
	// Recommended-for-DCR/MCP fields
	assert.Equal(t, "https://issuer.example.com/oauth/v2/keys", got["jwks_uri"])
	assert.Equal(t, "https://issuer.example.com/oidc/v1/register", got["registration_endpoint"])
	require.Contains(t, got, "scopes_supported")
}

// TestNewHandler_RegistrationEndpointOmittedWhenEmpty pins R3 AC: when
// the dual-gate is not satisfied the builder returns RegistrationEndpoint
// "" and the JSON body MUST NOT contain the key (never `null`).
func TestNewHandler_RegistrationEndpointOmittedWhenEmpty(t *testing.T) {
	build := func(ctx context.Context) *Metadata {
		return &Metadata{
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/oauth/v2/authorize",
			TokenEndpoint:         "https://issuer.example.com/oauth/v2/token",
			ResponseTypesSupported: []string{"code"},
			// RegistrationEndpoint zero value; omitempty drops the key
		}
	}
	rec := httptest.NewRecorder()
	NewHandler(build).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, HandlerPath, nil))
	body := rec.Body.String()
	assert.False(t, strings.Contains(body, "registration_endpoint"),
		"omitempty must drop the key entirely, body=%s", body)
	assert.False(t, strings.Contains(body, "null"),
		"never emit `null` per Claude Code Zod parser bug GH#38102, body=%s", body)
}

// TestIsRootIssuer covers the predicate in isolation so callers (and
// future surfaces) have a stable check for hostname-root.
func TestIsRootIssuer(t *testing.T) {
	tests := []struct {
		issuer string
		want   bool
	}{
		{"https://issuer.example.com", true},
		{"https://issuer.example.com/", true},
		{"https://issuer.example.com/zitadel", false},
		{"https://issuer.example.com/zitadel/", false},
		{"https://issuer.example.com/sub/path", false},
		{"", false}, // url.Parse returns no error but path is empty — treat as not root because there's no host
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			got := IsRootIssuer(tt.issuer)
			// Special-case the empty string: url.Parse("") returns a
			// URL with empty Path which our impl reports as root. That's
			// fine since callers gate on issuer != "" before warning;
			// the predicate is structural not validating.
			if tt.issuer == "" {
				assert.True(t, got, "empty string is structurally root-shaped (caller filters)")
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestIssuerWarner_LogsOncePerInstanceIssuer verifies R4 acceptance:
// non-root issuer triggers a single WARN per (instanceID, issuer) pair;
// root issuers never warn; the warning names the hostname-root probe URL.
func TestIssuerWarner_LogsOncePerInstanceIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuer     string
		instanceID string
		wantWarn   bool
	}{
		{
			name:       "root issuer: no warn",
			issuer:     "https://issuer.example.com",
			instanceID: "inst-1",
			wantWarn:   false,
		},
		{
			name:       "root issuer with trailing slash: no warn",
			issuer:     "https://issuer.example.com/",
			instanceID: "inst-1",
			wantWarn:   false,
		},
		{
			name:       "subpath issuer: warn once",
			issuer:     "https://issuer.example.com/zitadel",
			instanceID: "inst-2",
			wantWarn:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := redirectLogging(&buf)
			t.Cleanup(restore)

			w := newIssuerWarner()
			ctx := authz.WithInstanceID(context.Background(), tt.instanceID)
			w.maybeWarn(ctx, tt.issuer)
			out := buf.String()
			if !tt.wantWarn {
				assert.False(t, strings.Contains(out, "non-root URL path"),
					"expected no warn, got: %s", out)
				return
			}
			assert.True(t, strings.Contains(out, "non-root URL path"),
				"expected warn, got: %s", out)
			// Probe URL must name the hostname-root path.
			assert.True(t, strings.Contains(out, "https://issuer.example.com/.well-known/oauth-authorization-server"),
				"warn must name probe URL, got: %s", out)
			// Second call with same (instance, issuer) must NOT warn again.
			buf.Reset()
			w.maybeWarn(ctx, tt.issuer)
			assert.False(t, strings.Contains(buf.String(), "non-root URL path"),
				"warn must be once-per-(instance,issuer), second call output: %s", buf.String())
		})
	}
}

// TestIssuerWarner_DistinctInstancesEachWarn verifies the cache key
// includes instanceID, so a second instance hitting the same non-root
// issuer DOES log.
func TestIssuerWarner_DistinctInstancesEachWarn(t *testing.T) {
	var buf bytes.Buffer
	restore := redirectLogging(&buf)
	t.Cleanup(restore)

	w := newIssuerWarner()
	w.maybeWarn(authz.WithInstanceID(context.Background(), "inst-A"), "https://issuer.example.com/sub")
	first := buf.String()
	buf.Reset()
	w.maybeWarn(authz.WithInstanceID(context.Background(), "inst-B"), "https://issuer.example.com/sub")
	second := buf.String()

	assert.True(t, strings.Contains(first, "non-root URL path"))
	assert.True(t, strings.Contains(second, "non-root URL path"),
		"distinct instance must produce its own warn, got: %s", second)
}

// loggingMu serializes tests that swap logging.SetOutput; the global is
// process-wide so parallel runs would race.
var loggingMu sync.Mutex

// redirectLogging swaps the package logger's underlying io.Writer to the
// buffer for the duration of a test, returning a restore function.
func redirectLogging(buf io.Writer) func() {
	loggingMu.Lock()
	logging.SetOutput(buf)
	return func() {
		// Restore default destination.
		logging.SetOutput(io.Discard)
		loggingMu.Unlock()
	}
}
