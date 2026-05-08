package start

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/zitadel/internal/api/oidc"
	"github.com/zitadel/zitadel/internal/domain"
)

func TestApplyDevModeFromRedirects_AllHttps(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"https://app.example.com/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode != nil {
		t.Errorf("all-https → DevMode must remain nil, got %v", *app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_LocalhostFlipsTrue(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"http://localhost:33418/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode == nil || !*app.DevMode {
		t.Errorf("http://localhost → DevMode=true, got %v", app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_LoopbackIPFlipsTrue(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"http://127.0.0.1:5050/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode == nil || !*app.DevMode {
		t.Errorf("http://127.0.0.1 → DevMode=true, got %v", app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_MixedFlipsTrue(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"https://app.example.com/cb", "http://localhost/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode == nil || !*app.DevMode {
		t.Errorf("mixed http-localhost + https → DevMode=true, got %v", app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_PrivateIPFlipsTrue(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"http://10.0.0.5/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode == nil || !*app.DevMode {
		t.Errorf("private-IP http → DevMode=true, got %v", app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_PublicHTTPDoesNotFlip(t *testing.T) {
	app := &domain.OIDCApp{RedirectUris: []string{"http://app.example.com/cb"}}
	applyDevModeFromRedirects(context.Background(), app)
	if app.DevMode != nil {
		t.Errorf("public-http (non-loopback) must NOT auto-flip DevMode, got %v", *app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_RequestExplicitWins(t *testing.T) {
	explicit := false
	app := &domain.OIDCApp{
		RedirectUris: []string{"http://localhost/cb"},
		DevMode:      &explicit,
	}
	applyDevModeFromRedirects(context.Background(), app)
	if *app.DevMode != false {
		t.Errorf("request-explicit DevMode=false must be preserved, got %v", *app.DevMode)
	}
}

func TestApplyDevModeFromRedirects_NilSafe(t *testing.T) {
	applyDevModeFromRedirects(context.Background(), nil)
}

func TestApplyMCPProfileToOIDCApp_FillsOmittedFields(t *testing.T) {
	app := &domain.OIDCApp{}
	profile := &oidc.DCRMCPProfileConfig{
		AccessTokenType:          "JWT",
		IDTokenRoleAssertion:     true,
		IDTokenUserinfoAssertion: true,
		ClockSkew:                2 * time.Second,
	}
	applyMCPProfileToOIDCApp(app, profile)

	if app.AccessTokenType == nil || *app.AccessTokenType != domain.OIDCTokenTypeJWT {
		t.Errorf("AccessTokenType = %v, want JWT", app.AccessTokenType)
	}
	if app.IDTokenRoleAssertion == nil || *app.IDTokenRoleAssertion != true {
		t.Errorf("IDTokenRoleAssertion = %v, want true", app.IDTokenRoleAssertion)
	}
	if app.IDTokenUserinfoAssertion == nil || *app.IDTokenUserinfoAssertion != true {
		t.Errorf("IDTokenUserinfoAssertion = %v, want true", app.IDTokenUserinfoAssertion)
	}
	if app.ClockSkew == nil || *app.ClockSkew != 2*time.Second {
		t.Errorf("ClockSkew = %v, want 2s", app.ClockSkew)
	}
}

func TestApplyMCPProfileToOIDCApp_ExplicitValuesWin(t *testing.T) {
	bearer := domain.OIDCTokenTypeBearer
	roleFalse := false
	app := &domain.OIDCApp{
		AccessTokenType:      &bearer,
		IDTokenRoleAssertion: &roleFalse,
	}
	profile := &oidc.DCRMCPProfileConfig{
		AccessTokenType:          "JWT",
		IDTokenRoleAssertion:     true,
		IDTokenUserinfoAssertion: true,
		ClockSkew:                2 * time.Second,
	}
	applyMCPProfileToOIDCApp(app, profile)

	if *app.AccessTokenType != domain.OIDCTokenTypeBearer {
		t.Errorf("explicit Bearer must not be overwritten")
	}
	if *app.IDTokenRoleAssertion != false {
		t.Errorf("explicit false must not be overwritten")
	}
	// Untouched fields get the profile default.
	if app.IDTokenUserinfoAssertion == nil || *app.IDTokenUserinfoAssertion != true {
		t.Errorf("untouched IDTokenUserinfoAssertion should default to true")
	}
}

func TestApplyMCPProfileToOIDCApp_BearerConfig(t *testing.T) {
	app := &domain.OIDCApp{}
	applyMCPProfileToOIDCApp(app, &oidc.DCRMCPProfileConfig{AccessTokenType: "Bearer"})
	if app.AccessTokenType == nil || *app.AccessTokenType != domain.OIDCTokenTypeBearer {
		t.Errorf("expected Bearer, got %v", app.AccessTokenType)
	}
}

func TestApplyMCPProfileToOIDCApp_UnknownConfigFallsBackToJWT(t *testing.T) {
	app := &domain.OIDCApp{}
	applyMCPProfileToOIDCApp(app, &oidc.DCRMCPProfileConfig{AccessTokenType: "garbage"})
	if app.AccessTokenType == nil || *app.AccessTokenType != domain.OIDCTokenTypeJWT {
		t.Errorf("unknown config typo should fall back to JWT, got %v", app.AccessTokenType)
	}
}

func TestApplyMCPProfileToOIDCApp_ZeroClockSkewLeavesNil(t *testing.T) {
	app := &domain.OIDCApp{}
	applyMCPProfileToOIDCApp(app, &oidc.DCRMCPProfileConfig{ClockSkew: 0})
	if app.ClockSkew != nil {
		t.Errorf("zero ClockSkew config should leave OIDCApp.ClockSkew nil, got %v", *app.ClockSkew)
	}
}

func TestApplyMCPProfileToOIDCApp_NilSafe(t *testing.T) {
	applyMCPProfileToOIDCApp(nil, &oidc.DCRMCPProfileConfig{}) // must not panic
	applyMCPProfileToOIDCApp(&domain.OIDCApp{}, nil)           // must not panic
}
