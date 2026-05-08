package start

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/zitadel/logging"

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

// applyDevModeFromRedirects auto-enables OIDCApp.DevMode when ANY
// redirect URI is http loopback / private-IP — the local-dev shape
// MCP clients (VS Code, Claude Code MCP, etc.) register with. Without
// DevMode the redirect-host clamps reject http URIs as insecure, which
// defeats the zero-config DCR promise for local-dev clients.
// cavekit-dcr-bootstrap-validation.md R10.
//
// Logs the determination at INFO with the redirect URIs and the reason
// so operators can see WHY DevMode is on for a given app.
//
// Operates on the OIDCApp.DevMode pointer field: a non-nil pointer
// (request explicitly set DevMode true or false) is preserved.
func applyDevModeFromRedirects(ctx context.Context, app *domain.OIDCApp) {
	if app == nil || app.DevMode != nil {
		return
	}
	dev := false
	for _, raw := range app.RedirectUris {
		if isLocalDevHTTPRedirect(raw) {
			dev = true
			break
		}
	}
	if !dev {
		return
	}
	app.DevMode = &dev
	logging.WithFields(
		"redirect_uris", app.RedirectUris,
		"reason", "http_loopback_or_private_ip_redirect",
	).Info("dcr: DevMode auto-enabled (cavekit-dcr-bootstrap-validation R10)")
}

// isLocalDevHTTPRedirect mirrors the dcr-package isLocalDevRedirectURI
// helper. Duplicated here (rather than imported) because cmd/start
// already accumulates a small set of dcr-internal heuristics and a
// circular import via dcr → start is undesirable. Behavioral parity is
// pinned by the tests in dcr_mcp_profile_test.go and the dcr package's
// dcr_defaults_test.go.
func isLocalDevHTTPRedirect(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
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
