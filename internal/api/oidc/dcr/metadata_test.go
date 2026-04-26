package dcr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/domain"
)

func intPtr(v int) *int   { return &v }
func boolPtr(v bool) *bool { return &v }

func TestRFC7591Metadata_ToOIDCApp_R6_HappyPath(t *testing.T) {
	m := &RFC7591Metadata{
		ClientName:              "App",
		RedirectURIs:            []string{"https://x.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ApplicationType:         "web",
		PostLogoutRedirectURIs:  []string{"https://x.example.com/post-logout"},
		BackChannelLogoutURI:    "https://x.example.com/bcl",
	}
	app := m.ToOIDCApp()
	require.NotNil(t, app)
	assert.Equal(t, "App", app.AppName)
	assert.Equal(t, []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode, domain.OIDCGrantTypeRefreshToken}, app.GrantTypes)
	assert.Equal(t, []domain.OIDCResponseType{domain.OIDCResponseTypeCode}, app.ResponseTypes)
	require.NotNil(t, app.AuthMethodType)
	assert.Equal(t, domain.OIDCAuthMethodTypeBasic, *app.AuthMethodType)
	require.NotNil(t, app.ApplicationType)
	assert.Equal(t, domain.OIDCApplicationTypeWeb, *app.ApplicationType)
	require.NotNil(t, app.BackChannelLogoutURI)
	assert.Equal(t, "https://x.example.com/bcl", *app.BackChannelLogoutURI)
}

func TestRFC7591Metadata_ToOIDCApp_NilSafe(t *testing.T) {
	var m *RFC7591Metadata
	assert.Nil(t, m.ToOIDCApp())
}

func TestRFC7591Metadata_BuildDCRMeta_R6_AllPassthroughFields(t *testing.T) {
	m := &RFC7591Metadata{
		Contacts:         []string{"a@example.com", "b@example.com"},
		LogoURI:          "https://x.example.com/logo.png",
		ClientURI:        "https://x.example.com",
		PolicyURI:        "https://x.example.com/policy",
		TosURI:           "https://x.example.com/tos",
		SoftwareID:       "sw-id-1",
		SoftwareVersion:  "1.2.3",
		DefaultMaxAge:    intPtr(3600),
		RequireAuthTime:  boolPtr(true),
		DefaultACRValues: []string{"urn:mace:incommon:iap:silver"},
		InitiateLoginURI: "https://x.example.com/login",
		Scope:            "openid profile email",
	}
	got := m.BuildDCRMeta()
	require.NotNil(t, got)
	assert.Equal(t, []string{"a@example.com", "b@example.com"}, got["contacts"])
	assert.Equal(t, "https://x.example.com/logo.png", got["logo_uri"])
	assert.Equal(t, "https://x.example.com", got["client_uri"])
	assert.Equal(t, "https://x.example.com/policy", got["policy_uri"])
	assert.Equal(t, "https://x.example.com/tos", got["tos_uri"])
	assert.Equal(t, "sw-id-1", got["software_id"])
	assert.Equal(t, "1.2.3", got["software_version"])
	assert.Equal(t, 3600, got["default_max_age"])
	assert.Equal(t, true, got["require_auth_time"])
	assert.Equal(t, []string{"urn:mace:incommon:iap:silver"}, got["default_acr_values"])
	assert.Equal(t, "https://x.example.com/login", got["initiate_login_uri"])
	assert.Equal(t, "openid profile email", got["scope"])
}

func TestRFC7591Metadata_BuildDCRMeta_R6_OmitsZeroValues(t *testing.T) {
	// All-zero metadata → nil dcr_meta (no row in JSONB column).
	m := &RFC7591Metadata{}
	assert.Nil(t, m.BuildDCRMeta())
}

func TestRFC7591Metadata_BuildDCRMeta_R6_PartialFields(t *testing.T) {
	m := &RFC7591Metadata{
		LogoURI:   "https://x.example.com/logo.png",
		SoftwareID: "sw-id-2",
	}
	got := m.BuildDCRMeta()
	require.NotNil(t, got)
	assert.Equal(t, 2, len(got), "only populated fields should appear, got: %v", got)
	assert.Equal(t, "https://x.example.com/logo.png", got["logo_uri"])
	assert.Equal(t, "sw-id-2", got["software_id"])
}

func TestRFC7591Metadata_BuildDCRMeta_NilSafe(t *testing.T) {
	var m *RFC7591Metadata
	assert.Nil(t, m.BuildDCRMeta())
}
