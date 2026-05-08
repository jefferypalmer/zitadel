package start

import (
	"strings"

	"github.com/zitadel/zitadel/internal/api/oidc"
	"github.com/zitadel/zitadel/internal/domain"
)

// applyMCPProfileToOIDCApp fills the four OIDCApp-side MCP profile
// fields when the request body did not specify them. Mirrors
// cavekit-dcr-bootstrap-validation.md R9. Operates on
// pointer-typed fields — a non-nil pointer means the request supplied
// an explicit value and is preserved.
//
// Lives in cmd/start (not internal/api/oidc/dcr) because the dcr
// package operates on RFC7591Metadata, not on the synthesized
// domain.OIDCApp; the synthesis happens in the Register closure
// inside start.go where the OIDCApp + the DCRConfig are both in
// scope.
func applyMCPProfileToOIDCApp(app *domain.OIDCApp, profile *oidc.DCRMCPProfileConfig) {
	if app == nil || profile == nil {
		return
	}
	if app.AccessTokenType == nil {
		v := mapAccessTokenType(profile.AccessTokenType)
		app.AccessTokenType = &v
	}
	if app.IDTokenRoleAssertion == nil {
		b := profile.IDTokenRoleAssertion
		app.IDTokenRoleAssertion = &b
	}
	if app.IDTokenUserinfoAssertion == nil {
		b := profile.IDTokenUserinfoAssertion
		app.IDTokenUserinfoAssertion = &b
	}
	if app.ClockSkew == nil && profile.ClockSkew > 0 {
		c := profile.ClockSkew
		app.ClockSkew = &c
	}
}

// mapAccessTokenType translates the operator-config string ("JWT" /
// "Bearer", case-insensitive) to the typed enum. Unknown values fall
// back to JWT (the MCP-profile default) — the kit explicitly favors
// MCP-friendly behavior for unrecognized config typos rather than
// failing-closed.
func mapAccessTokenType(s string) domain.OIDCTokenType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bearer":
		return domain.OIDCTokenTypeBearer
	case "jwt", "":
		return domain.OIDCTokenTypeJWT
	default:
		return domain.OIDCTokenTypeJWT
	}
}
