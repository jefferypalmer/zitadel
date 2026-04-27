package dcr

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubDCRConfig satisfies [DCRConfigSubset] for clamp tests.
type stubDCRConfig struct {
	grants            []string
	responseTypes     []string
	authMethods       []string
	applicationTypes  []string
	hostPatterns      []string
	maxRedirectURIs   int
}

func (s stubDCRConfig) AllowedGrantTypes() []string              { return s.grants }
func (s stubDCRConfig) AllowedResponseTypes() []string           { return s.responseTypes }
func (s stubDCRConfig) AllowedAuthMethods() []string             { return s.authMethods }
func (s stubDCRConfig) AllowedApplicationTypes() []string        { return s.applicationTypes }
func (s stubDCRConfig) AllowedRedirectURIHostPatterns() []string { return s.hostPatterns }
func (s stubDCRConfig) MaxRedirectURIs() int                     { return s.maxRedirectURIs }

func defaultStubConfig() stubDCRConfig {
	// Mirrors cmd/defaults.yaml DCR allow-lists (T-001) so the tests
	// exercise the same vocabulary the production server will see.
	return stubDCRConfig{
		grants:           []string{"authorization_code", "refresh_token"},
		responseTypes:    []string{"code"},
		authMethods:      []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		applicationTypes: []string{"native", "web"},
		hostPatterns:     nil, // empty = no host-pattern check
		maxRedirectURIs:  10,
	}
}

func validHappyPathMetadata() *RFC7591Metadata {
	return &RFC7591Metadata{
		ClientName:              "Test Client",
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
	}
}

func TestValidateAndClampMetadata_R4_HappyPath(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	got, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	require.NoError(t, err)
	require.NotNil(t, got)
	// Returned value is a copy — input is not mutated.
	assert.NotSame(t, in, got)
	assert.Equal(t, []string{"authorization_code"}, got.GrantTypes)
	assert.Equal(t, []string{"code"}, got.ResponseTypes)
}

func TestValidateAndClampMetadata_R4_GrantTypes(t *testing.T) {
	cfg := defaultStubConfig()
	tests := []struct {
		name       string
		grants     []string
		wantCode   string
		wantField  string
	}{
		{
			name:      "empty after defaulting → invalid_client_metadata grant_types",
			grants:    []string{},
			wantCode:  ErrCodeInvalidClientMetadata,
			wantField: "grant_types",
		},
		{
			name:      "all-disallowed → invalid_client_metadata grant_types",
			grants:    []string{"client_credentials", "password"},
			wantCode:  ErrCodeInvalidClientMetadata,
			wantField: "grant_types",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validHappyPathMetadata()
			in.GrantTypes = tt.grants
			_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			ce := requireClampError(t, err)
			assert.Equal(t, tt.wantCode, ce.Code)
			assert.Contains(t, ce.Description, tt.wantField)
		})
	}
}

func TestValidateAndClampMetadata_R4_GrantTypesIntersection(t *testing.T) {
	// Mixed list — kept allowed entries, dropped disallowed.
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
	got, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, got.GrantTypes,
		"intersection must drop client_credentials but preserve order")
}

func TestValidateAndClampMetadata_R4_ResponseTypes(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.ResponseTypes = []string{"id_token"}
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "response_types")
}

func TestValidateAndClampMetadata_R4_AuthMethod_RejectsClientSecretJWT(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.TokenEndpointAuthMethod = "client_secret_jwt"
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "client_secret_jwt")
	// Description must NOT generically mention the allow-list — the
	// rejection reason is policy ("not supported"), not membership.
	assert.NotContains(t, ce.Description, "AllowedAuthMethods")
}

func TestValidateAndClampMetadata_R4_AuthMethod_OutOfAllowList(t *testing.T) {
	cfg := defaultStubConfig()
	cfg.authMethods = []string{"none"}
	in := validHappyPathMetadata()
	in.TokenEndpointAuthMethod = "client_secret_basic"
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "token_endpoint_auth_method")
}

func TestValidateAndClampMetadata_R4_ApplicationType(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.ApplicationType = "service" // not in allow-list
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "application_type")
}

func TestValidateAndClampMetadata_R4_SubjectType(t *testing.T) {
	cfg := defaultStubConfig()
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "absent → ok", value: "", wantErr: false},
		{name: "public → ok", value: "public", wantErr: false},
		{name: "pairwise → reject", value: "pairwise", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := validHappyPathMetadata()
			in.SubjectType = c.value
			_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			if !c.wantErr {
				assert.NoError(t, err)
				return
			}
			ce := requireClampError(t, err)
			assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
			assert.Contains(t, ce.Description, "subject_type")
		})
	}
}

func TestValidateAndClampMetadata_R4_IDTokenSigningAlg(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.IDTokenSignedResponseAlg = "ES512" // not advertised
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256", "ES256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "id_token_signed_response_alg")
}

func TestValidateAndClampMetadata_R4_IDTokenSigningAlg_AdvertisedAccepted(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.IDTokenSignedResponseAlg = "RS256"
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256", "ES256"}, false)
	assert.NoError(t, err)
}

func TestValidateAndClampMetadata_R4_RequestObjectKeysRejected(t *testing.T) {
	cfg := defaultStubConfig()
	tests := []struct {
		name  string
		mut   func(*RFC7591Metadata)
		field string
	}{
		{
			name:  "request_object_signing_alg",
			mut:   func(m *RFC7591Metadata) { m.RequestObjectSigningAlg = "RS256" },
			field: "request_object_signing_alg",
		},
		{
			name:  "request_object_encryption_alg",
			mut:   func(m *RFC7591Metadata) { m.RequestObjectEncryptionAlg = "RSA-OAEP" },
			field: "request_object_encryption_alg",
		},
		{
			name:  "request_object_encryption_enc",
			mut:   func(m *RFC7591Metadata) { m.RequestObjectEncryptionEnc = "A256GCM" },
			field: "request_object_encryption_enc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validHappyPathMetadata()
			tt.mut(in)
			_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			ce := requireClampError(t, err)
			assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
			assert.Contains(t, ce.Description, tt.field)
		})
	}
}

func TestValidateAndClampMetadata_R4_SoftwareStatement(t *testing.T) {
	cfg := defaultStubConfig()
	t.Run("present + feature off → unapproved_software_statement", func(t *testing.T) {
		in := validHappyPathMetadata()
		in.SoftwareStatement = "eyJhbGciOiJSUzI1NiJ9..."
		_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false /*softwareStatementEnabled*/)
		ce := requireClampError(t, err)
		assert.Equal(t, ErrCodeUnapprovedSoftwareStatement, ce.Code)
	})
	t.Run("absent + feature off → ok", func(t *testing.T) {
		_, err := ValidateAndClampMetadata(cfg, validHappyPathMetadata(), []string{"RS256"}, false)
		assert.NoError(t, err)
	})
	t.Run("whitespace-only is treated as absent", func(t *testing.T) {
		in := validHappyPathMetadata()
		in.SoftwareStatement = "   "
		_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
		assert.NoError(t, err)
	})
}

func TestValidateAndClampMetadata_R4_RedirectURIsCount(t *testing.T) {
	cfg := defaultStubConfig()
	cfg.maxRedirectURIs = 2
	in := validHappyPathMetadata()
	in.RedirectURIs = []string{
		"https://a.example.com/cb",
		"https://b.example.com/cb",
		"https://c.example.com/cb",
	}
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
	assert.Contains(t, ce.Description, "MaxRedirectURIs")
}

func TestValidateAndClampMetadata_R4_RedirectURIs_HostPatterns(t *testing.T) {
	cfg := defaultStubConfig()
	cfg.hostPatterns = []string{"*.example.com", "example.com"}

	t.Run("matching host accepted", func(t *testing.T) {
		in := validHappyPathMetadata()
		in.RedirectURIs = []string{"https://app.example.com/cb"}
		_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
		assert.NoError(t, err)
	})
	t.Run("non-matching host rejected", func(t *testing.T) {
		in := validHappyPathMetadata()
		in.RedirectURIs = []string{"https://evil.attacker.com/cb"}
		_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
		ce := requireClampError(t, err)
		assert.Equal(t, ErrCodeInvalidRedirectURI, ce.Code)
	})
}

func TestValidateAndClampMetadata_R4_NativeLoopbackHTTP(t *testing.T) {
	cfg := defaultStubConfig()
	cfg.hostPatterns = []string{"example.com"} // would otherwise reject loopback
	cases := []string{
		"http://localhost:54212/cb",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:1234/cb",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			in := validHappyPathMetadata()
			in.ApplicationType = "native"
			in.TokenEndpointAuthMethod = "none"
			in.RedirectURIs = []string{uri}
			_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			assert.NoError(t, err, "loopback HTTP must be accepted for native (RFC 8252 §7.3)")
		})
	}
}

func TestValidateAndClampMetadata_R4_NativeLoopbackHTTP_NotAllowedForWeb(t *testing.T) {
	// Loopback HTTP for a web app must NOT slip past the host-pattern
	// check (the "loopback for native" exemption is intentionally narrow).
	cfg := defaultStubConfig()
	cfg.hostPatterns = []string{"example.com"}
	in := validHappyPathMetadata()
	in.RedirectURIs = []string{"http://localhost:1234/cb"}
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	require.Error(t, err)
	ce := requireClampError(t, err)
	assert.Equal(t, ErrCodeInvalidRedirectURI, ce.Code)
}

// TestValidateAndClampMetadata_R4_DoesNotMutateInput pins the
// non-mutation contract — the caller's request body must be safe to
// inspect after a clamp call (the original is what gets logged /
// audited).
func TestValidateAndClampMetadata_R4_DoesNotMutateInput(t *testing.T) {
	cfg := defaultStubConfig()
	in := validHappyPathMetadata()
	in.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
	want := append([]string{}, in.GrantTypes...)
	_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
	require.NoError(t, err)
	assert.Equal(t, want, in.GrantTypes, "input GrantTypes must not be mutated")
}

func TestIsLoopbackHTTP(t *testing.T) {
	yes := []string{
		"http://localhost/cb",
		"http://localhost:8080/cb",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:80/cb",
		"http://[::1]/cb",
		"http://[::1]:1234/cb",
	}
	no := []string{
		"https://localhost/cb",     // https not loopback-special-cased
		"http://example.com/cb",    // not loopback host
		"http://10.0.0.1/cb",       // RFC 1918 private but not loopback
		"http://2130706433/cb",     // numeric form not whitelisted
		"file:///etc/passwd",
	}
	for _, u := range yes {
		assert.True(t, isLoopbackHTTP(u), "expected loopback: %s", u)
	}
	for _, u := range no {
		assert.False(t, isLoopbackHTTP(u), "expected not loopback: %s", u)
	}
}

func TestHostMatches(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "*.example.com", false}, // single-label wildcard does not match apex
		{"app.example.com", "*.example.com", true},
		{"deep.app.example.com", "*.example.com", false}, // single-label only
		{"app.example.com", "example.com", false},
		{"example.com", "", false},
	}
	for _, tt := range tests {
		got := hostMatches(tt.host, tt.pattern)
		assert.Equal(t, tt.want, got, "hostMatches(%q, %q)", tt.host, tt.pattern)
	}
}

func TestIsClampError(t *testing.T) {
	ce := newClampError(ErrCodeInvalidClientMetadata, "f", "r", "DCR-Test1")
	got, ok := IsClampError(ce)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidClientMetadata, got.Code)

	got2, ok := IsClampError(errors.New("boom"))
	assert.False(t, ok)
	assert.Nil(t, got2)
}

func requireClampError(t *testing.T, err error) *ClampError {
	t.Helper()
	require.Error(t, err)
	ce, ok := IsClampError(err)
	require.True(t, ok, "expected *ClampError, got %T: %v", err, err)
	// Description always names the offending field.
	assert.True(t, strings.Contains(ce.Description, ":"),
		"description should be 'field: reason', got: %q", ce.Description)
	return ce
}

// TestValidateAndClampMetadata_R4_UserinfoBypassRejected pins
// cavekit-register-handler.md R4 amendment 2026-04-27 / F-100 —
// authorization-code exfiltration via URL userinfo.
//
// Before the fix, extractHost cut the URL on `://` then `/?#` then
// split port on `:`, never stripping the RFC 3986 `userinfo` segment.
// `https://app.example.com:8080@evil.com/cb` parsed to host=
// `app.example.com` and matched `*.example.com`, while the actual
// host the browser would resolve is `evil.com`. An attacker
// registering a client with attacker-controlled DNS could thereby
// defeat the host allow-list and steal authorization codes via the
// malicious redirect.
//
// The fix uses net/url.Parse + u.Hostname() and rejects any URL
// where u.User != nil (defence-in-depth).
func TestValidateAndClampMetadata_R4_UserinfoBypassRejected(t *testing.T) {
	cfg := defaultStubConfig()
	cfg.hostPatterns = []string{"*.example.com"}

	// All four shapes named in the kit AC. Each presents as a host
	// matching the allow-list when parsed by a hand-rolled split, but
	// the real authority is `evil.com`.
	bypasses := []string{
		"https://victim.example.com@evil.com/cb",
		"https://victim.example.com:443@evil.com/cb",
		"https://user:pass@evil.com/cb",
		"https://[2001:db8::1]@evil.com/cb",
	}
	for _, uri := range bypasses {
		t.Run(uri, func(t *testing.T) {
			in := validHappyPathMetadata()
			in.RedirectURIs = []string{uri}
			_, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			ce := requireClampError(t, err)
			assert.Equal(t, ErrCodeInvalidRedirectURI, ce.Code,
				"userinfo-carrying redirect URI MUST be rejected as invalid_redirect_uri")
			// The error_description should name the field. Don't pin
			// the literal text — just that the field name appears.
			assert.Contains(t, ce.Description, "redirect_uris")
		})
	}
}

// TestValidateAndClampMetadata_R4_F103_ResponseTypeSetSemantics pins
// cavekit-register-handler.md R4 amendment 2026-04-27 / F-103. RFC 6749
// §3.1.1 defines response_type values as space-separated SETS of tokens
// — `"token id_token"` MUST be treated as equivalent to `"id_token
// token"`. Pre-fix the clamp used exact-string slices.Contains, so a
// spec-compliant client sending the non-canonical spelling got 400.
//
// The fix canonicalizes each value (Fields + sort + join) on both the
// requested side and the allow-list side before comparison. The
// canonical form mirrors zitadel/oidc/v3.ResponseTypeIDToken =
// "id_token token" so the rest of the Zitadel OIDC stack (which
// switches on that exact upstream literal) sees consistent values.
func TestValidateAndClampMetadata_R4_F103_ResponseTypeSetSemantics(t *testing.T) {
	cases := []struct {
		name       string
		allowList  []string
		requested  []string
		wantOutput []string // empty → expect rejection
		wantOK     bool
	}{
		{
			name:       "non-canonical spelling matches canonical allow-list",
			allowList:  []string{"id_token token"},
			requested:  []string{"token id_token"}, // attacker / spec-compliant client
			wantOutput: []string{"id_token token"}, // echo allow-list spelling
			wantOK:     true,
		},
		{
			name:       "canonical spelling matches non-canonical allow-list",
			allowList:  []string{"token id_token"}, // operator misordered
			requested:  []string{"id_token token"},
			wantOutput: []string{"token id_token"}, // echo allow-list spelling
			wantOK:     true,
		},
		{
			name:       "extra whitespace canonicalises",
			allowList:  []string{"id_token token"},
			requested:  []string{"  token   id_token  "},
			wantOutput: []string{"id_token token"},
			wantOK:     true,
		},
		{
			name:       "code single-token unchanged",
			allowList:  []string{"code"},
			requested:  []string{"code"},
			wantOutput: []string{"code"},
			wantOK:     true,
		},
		{
			name:      "disallowed token rejected even with whitespace permutation",
			allowList: []string{"code"},
			requested: []string{"id_token token"}, // not in allow-list
			wantOK:    false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := defaultStubConfig()
			cfg.responseTypes = c.allowList
			in := validHappyPathMetadata()
			in.ResponseTypes = c.requested
			got, err := ValidateAndClampMetadata(cfg, in, []string{"RS256"}, false)
			if !c.wantOK {
				ce := requireClampError(t, err)
				assert.Equal(t, ErrCodeInvalidClientMetadata, ce.Code)
				assert.Contains(t, ce.Description, "response_types")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.wantOutput, got.ResponseTypes,
				"clamped response_types must echo the allow-list canonical spelling, not the client's spelling")
		})
	}
}
