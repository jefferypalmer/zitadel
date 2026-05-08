package dcr

import (
	"reflect"
	"testing"
)

func TestApplyMCPProfileDefaults_FillsOmittedFields(t *testing.T) {
	meta := &RFC7591Metadata{
		ClientName:   "minimal",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}
	applyMCPProfileDefaults(meta)
	if !reflect.DeepEqual(meta.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("grant_types: %v", meta.GrantTypes)
	}
	if !reflect.DeepEqual(meta.ResponseTypes, []string{"code"}) {
		t.Errorf("response_types: %v", meta.ResponseTypes)
	}
	if meta.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method: %q", meta.TokenEndpointAuthMethod)
	}
	if meta.ApplicationType != "web" {
		t.Errorf("application_type: %q (https-only redirects → web)", meta.ApplicationType)
	}
}

func TestApplyMCPProfileDefaults_HttpLoopbackPicksNative(t *testing.T) {
	meta := &RFC7591Metadata{RedirectURIs: []string{"http://127.0.0.1:5050/cb"}}
	applyMCPProfileDefaults(meta)
	if meta.ApplicationType != "native" {
		t.Errorf("expected native for loopback redirect, got %q", meta.ApplicationType)
	}
}

func TestApplyMCPProfileDefaults_MixedRedirectsPickNative(t *testing.T) {
	meta := &RFC7591Metadata{RedirectURIs: []string{"https://app.example.com/cb", "http://localhost/cb"}}
	applyMCPProfileDefaults(meta)
	if meta.ApplicationType != "native" {
		t.Errorf("expected native when ANY entry is loopback, got %q", meta.ApplicationType)
	}
}

func TestApplyMCPProfileDefaults_ExplicitGrantTypesWin(t *testing.T) {
	meta := &RFC7591Metadata{GrantTypes: []string{"client_credentials"}}
	applyMCPProfileDefaults(meta)
	if !reflect.DeepEqual(meta.GrantTypes, []string{"client_credentials"}) {
		t.Errorf("explicit grant_types must not be overwritten, got %v", meta.GrantTypes)
	}
}

func TestApplyMCPProfileDefaults_ExplicitTokenAuthMethodWins(t *testing.T) {
	meta := &RFC7591Metadata{TokenEndpointAuthMethod: "private_key_jwt"}
	applyMCPProfileDefaults(meta)
	if meta.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("explicit token_endpoint_auth_method must not be overwritten, got %q", meta.TokenEndpointAuthMethod)
	}
}

func TestApplyMCPProfileDefaults_NilSafe(t *testing.T) {
	applyMCPProfileDefaults(nil) // must not panic
}

func TestApplyMCPProfileDefaults_NoRedirectsPickWeb(t *testing.T) {
	meta := &RFC7591Metadata{}
	applyMCPProfileDefaults(meta)
	if meta.ApplicationType != "web" {
		t.Errorf("expected web when no redirects supplied, got %q", meta.ApplicationType)
	}
}

func TestDeriveDevMode(t *testing.T) {
	tests := []struct {
		name string
		uris []string
		want bool
	}{
		{
			name: "empty list",
			uris: nil,
			want: false,
		},
		{
			name: "all https",
			uris: []string{"https://app.example.com/cb", "https://login.example.com/cb"},
			want: false,
		},
		{
			name: "single loopback http (localhost)",
			uris: []string{"http://localhost:33418/"},
			want: true,
		},
		{
			name: "loopback http (127.0.0.1)",
			uris: []string{"http://127.0.0.1:5050/cb"},
			want: true,
		},
		{
			name: "loopback http (127.x other than .0.0.1)",
			uris: []string{"http://127.5.6.7/"},
			want: true,
		},
		{
			name: "loopback http (::1 bracketed)",
			uris: []string{"http://[::1]:8080/"},
			want: true,
		},
		{
			name: "private RFC 1918 (10.x)",
			uris: []string{"http://10.0.0.5/"},
			want: true,
		},
		{
			name: "private RFC 1918 (192.168.x)",
			uris: []string{"http://192.168.1.50:8000/cb"},
			want: true,
		},
		{
			name: "private RFC 1918 (172.16.x)",
			uris: []string{"http://172.20.0.5/"},
			want: true,
		},
		{
			name: "private RFC 4193 (fc00::/7)",
			uris: []string{"http://[fd00::1]/"},
			want: true,
		},
		{
			name: "mixed http-localhost + https → true",
			uris: []string{"http://localhost:33418/", "https://app.example.com/cb"},
			want: true,
		},
		{
			name: "public-http (does NOT flip DevMode on)",
			uris: []string{"http://app.example.com/cb"},
			want: false,
		},
		{
			name: "public-http IP",
			uris: []string{"http://8.8.8.8/cb"},
			want: false,
		},
		{
			name: "scheme-case-insensitive (HTTP)",
			uris: []string{"HTTP://localhost/"},
			want: true,
		},
		{
			name: "scheme-case-insensitive HTTPS does not flip",
			uris: []string{"HTTPS://localhost/"},
			want: false,
		},
		{
			name: "malformed URI ignored",
			uris: []string{"not a url at all"},
			want: false,
		},
		{
			name: "malformed mixed with valid loopback",
			uris: []string{"::garbage::", "http://127.0.0.1/"},
			want: true,
		},
		{
			name: "https loopback does NOT flip (covered by other paths)",
			uris: []string{"https://localhost/"},
			want: false,
		},
		{
			name: "post_logout_redirect_uri-style with port and path",
			uris: []string{"http://localhost:8443/auth/callback?foo=bar"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveDevMode(tt.uris)
			if got != tt.want {
				t.Errorf("deriveDevMode(%v) = %v, want %v", tt.uris, got, tt.want)
			}
		})
	}
}
