package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourcesFromContext_Empty(t *testing.T) {
	assert.Nil(t, ResourcesFromContext(context.Background()))
}

func TestWithAuthorizeResources_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil in, nil out", in: nil, want: nil},
		{name: "empty in, nil out (no context slot written)", in: []string{}, want: nil},
		{
			name: "single value",
			in:   []string{"https://api.example.com"},
			want: []string{"https://api.example.com"},
		},
		{
			name: "multiple values — order preserved",
			in:   []string{"https://api.example.com", "https://mcp.example.com"},
			want: []string{"https://api.example.com", "https://mcp.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAuthorizeResources(context.Background(), tt.in)
			assert.Equal(t, tt.want, ResourcesFromContext(ctx))
		})
	}
}

func TestAuthorizeResourceSidecar(t *testing.T) {
	tests := []struct {
		name   string
		method string
		query  string
		body   string
		want   []string
	}{
		{
			name:   "no resource — nil slice",
			method: http.MethodGet,
			query:  "client_id=c",
			want:   nil,
		},
		{
			name:   "single resource in query string",
			method: http.MethodGet,
			query:  "resource=https%3A%2F%2Fapi.example.com&client_id=c",
			want:   []string{"https://api.example.com"},
		},
		{
			name:   "multiple resource values in query string",
			method: http.MethodGet,
			query:  "resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fmcp.example.com",
			want:   []string{"https://api.example.com", "https://mcp.example.com"},
		},
		{
			name:   "resource in POST form body",
			method: http.MethodPost,
			body:   "resource=" + url.QueryEscape("https://api.example.com"),
			want:   []string{"https://api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			handler := NewAuthorizeResourceSidecar(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = ResourcesFromContext(r.Context())
			}))

			var r *http.Request
			switch tt.method {
			case http.MethodGet:
				r = httptest.NewRequest(http.MethodGet, "/oauth/v2/authorize?"+tt.query, nil)
			case http.MethodPost:
				r = httptest.NewRequest(http.MethodPost, "/oauth/v2/token", strings.NewReader(tt.body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			handler.ServeHTTP(httptest.NewRecorder(), r)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthorizeResourceSidecar_DoesNotConsumeBody(t *testing.T) {
	// The library will call ParseForm again. If the sidecar consumed the body
	// without making it re-readable, downstream handlers would see an empty
	// form. net/http.ParseForm is documented as safe to call multiple times.
	handler := NewAuthorizeResourceSidecar(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "https://api.example.com", r.Form.Get("resource"))
		assert.Equal(t, "c", r.Form.Get("client_id"))
	}))
	body := "resource=" + url.QueryEscape("https://api.example.com") + "&client_id=c"
	r := httptest.NewRequest(http.MethodPost, "/oauth/v2/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(httptest.NewRecorder(), r)
}
