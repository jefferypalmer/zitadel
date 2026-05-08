package start

import (
	"testing"
	"time"

	"github.com/zitadel/zitadel/internal/api/oidc"
	"github.com/zitadel/zitadel/internal/domain"
)

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
