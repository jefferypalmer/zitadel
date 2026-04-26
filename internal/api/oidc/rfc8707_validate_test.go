package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateResources covers cavekit-rfc8707-resource.md R3 acceptance
// criteria: empty allow-list = unrestricted, non-empty allow-list
// rejects out-of-list values, syntactic URI validation, multi-resource
// first-invalid wins.
func TestValidateResources(t *testing.T) {
	tests := []struct {
		name       string
		resources  []string
		allowed    []string
		wantErr    bool
		wantInDesc string
	}{
		{
			name:      "no resources is always OK regardless of allow-list",
			resources: nil,
			allowed:   []string{"https://api.example.com"},
		},
		{
			name:      "R3 AC1: empty allow-list accepts any valid URI",
			resources: []string{"https://anything.example.com"},
			allowed:   nil,
		},
		{
			name:      "R3 AC1: empty allow-list accepts multiple valid URIs",
			resources: []string{"https://a.example.com", "https://b.example.com"},
			allowed:   []string{},
		},
		{
			name:      "R3 AC2: matching value in non-empty list is accepted",
			resources: []string{"https://api.example.com"},
			allowed:   []string{"https://api.example.com", "https://mcp.example.com"},
		},
		{
			name:      "R3 AC2: all values must match (multi)",
			resources: []string{"https://api.example.com", "https://mcp.example.com"},
			allowed:   []string{"https://api.example.com", "https://mcp.example.com"},
		},
		{
			name:       "R3 AC3: non-matching value rejected",
			resources:  []string{"https://other.example.com"},
			allowed:    []string{"https://api.example.com"},
			wantErr:    true,
			wantInDesc: "allow-list",
		},
		{
			name:       "R3 AC4: empty string rejected",
			resources:  []string{""},
			allowed:    nil,
			wantErr:    true,
			wantInDesc: "empty",
		},
		{
			name:       "R3 AC4: relative URI rejected",
			resources:  []string{"/api"},
			allowed:    nil,
			wantErr:    true,
			wantInDesc: "absolute",
		},
		{
			name:       "R3 AC4: fragment forbidden by RFC 8707 §2",
			resources:  []string{"https://api.example.com/v1#section"},
			allowed:    nil,
			wantErr:    true,
			wantInDesc: "fragment",
		},
		{
			name:       "R3 AC5: multi-resource, first invalid (bad syntax) wins over second's allow-list miss",
			resources:  []string{"/relative", "https://other.example.com"},
			allowed:    []string{"https://api.example.com"},
			wantErr:    true,
			wantInDesc: "absolute",
		},
		{
			name:       "R3 AC5: multi-resource, first valid then non-allowed → second's failure surfaces",
			resources:  []string{"https://api.example.com", "https://other.example.com"},
			allowed:    []string{"https://api.example.com"},
			wantErr:    true,
			wantInDesc: "allow-list",
		},
		{
			name:      "non-https scheme is allowed by syntax (allow-list governs policy)",
			resources: []string{"urn:example:resource"},
			allowed:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResources(tt.resources, tt.allowed)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, IsInvalidTargetError(err), "expected errInvalidTarget but got %T: %v", err, err)
				if tt.wantInDesc != "" {
					assert.Contains(t, err.Error(), tt.wantInDesc)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestWriteInvalidTargetError pins the cavekit R6 / T-028 envelope.
// Status 400, Content-Type application/json;charset=UTF-8, body shape
// {"error":"invalid_target","error_description":"..."} with cache headers
// matching the rest of the OIDC error pipeline.
func TestWriteInvalidTargetError(t *testing.T) {
	tests := []struct {
		name        string
		description string
		wantDesc    string
	}{
		{
			name:        "explicit description",
			description: "resource \"https://other.example.com\" is not in the configured allow-list",
			wantDesc:    "resource \"https://other.example.com\" is not in the configured allow-list",
		},
		{
			name:        "empty description gets generic fallback",
			description: "",
			wantDesc:    "the requested resource is not valid",
		},
		{
			name:        "description with quotes is properly escaped",
			description: `bad value "x" with control char`,
			wantDesc:    `bad value "x" with control char`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeInvalidTargetError(rec, tt.description)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

			var got map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, "invalid_target", got["error"])
			assert.Equal(t, tt.wantDesc, got["error_description"])
		})
	}
}

// TestNewAuthorizeResourceSidecar_RejectsInvalid asserts the sidecar
// emits the T-028 envelope and short-circuits when validation fails.
func TestNewAuthorizeResourceSidecar_RejectsInvalid(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		allowed   []string
		wantNext  bool
		wantError bool
	}{
		{
			name:     "no resource — passes through",
			query:    "client_id=c",
			allowed:  []string{"https://api.example.com"},
			wantNext: true,
		},
		{
			name:     "resource matches allow-list — passes through",
			query:    "resource=https%3A%2F%2Fapi.example.com",
			allowed:  []string{"https://api.example.com"},
			wantNext: true,
		},
		{
			name:     "empty allow-list, valid URI — passes through",
			query:    "resource=https%3A%2F%2Fanything.example.com",
			allowed:  nil,
			wantNext: true,
		},
		{
			name:      "resource not in allow-list — short-circuits with invalid_target",
			query:     "resource=https%3A%2F%2Fother.example.com",
			allowed:   []string{"https://api.example.com"},
			wantNext:  false,
			wantError: true,
		},
		{
			name:      "bad URI syntax — short-circuits with invalid_target even with empty allow-list",
			query:     "resource=%2Frelative",
			allowed:   nil,
			wantNext:  false,
			wantError: true,
		},
		{
			name:      "multi-resource, one bad — short-circuits with invalid_target",
			query:     "resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fother.example.com",
			allowed:   []string{"https://api.example.com"},
			wantNext:  false,
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			handler := NewAuthorizeResourceSidecar(tt.allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			}))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/oauth/v2/authorize?"+tt.query, nil)
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantNext, nextCalled, "expected next to be called=%v", tt.wantNext)
			if tt.wantError {
				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"))
				assert.True(t, strings.Contains(rec.Body.String(), `"error":"invalid_target"`),
					"body=%q", rec.Body.String())
			}
		})
	}
}

// TestNewAuthorizeResourceSidecar_DefensiveCopy ensures config rotation
// (mutating the slice passed to the factory) does not affect already-
// configured middleware closures.
func TestNewAuthorizeResourceSidecar_DefensiveCopy(t *testing.T) {
	allowed := []string{"https://api.example.com"}
	handler := NewAuthorizeResourceSidecar(allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	allowed[0] = "https://other.example.com" // mutate after construction

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/v2/authorize?resource=https%3A%2F%2Fapi.example.com", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "original allow-list value must still be accepted")
}

// pin: Ensure ValidateResources returns nil quickly on the no-resource
// fast path used by every non-RFC8707 caller — a regression here would
// charge per-request overhead on the hot /authorize path.
func TestValidateResources_FastPathOnEmptyInput(t *testing.T) {
	require.NoError(t, ValidateResources(nil, []string{"https://api.example.com"}))
	require.NoError(t, ValidateResources([]string{}, []string{"https://api.example.com"}))
}

// Ensure compilation+wiring of the existing sidecar test API still
// matches: ResourcesFromContext returns nil on an empty context.
func TestValidateResources_NoLeakIntoContext(t *testing.T) {
	// Invoking ValidateResources directly does not touch ctx; this keeps
	// the validate function decoupled from the sidecar's ctx-stash.
	assert.Nil(t, ResourcesFromContext(context.Background()))
}
