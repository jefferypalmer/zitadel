package dcr

import (
	"net"
	"net/url"
	"strings"
)

// applyMCPProfileDefaults supplies the MCP-friendly RFC 7591 metadata
// defaults for fields a minimal Claude-Code-style client typically
// omits. cavekit-dcr-bootstrap-validation.md R9.
//
// Precedence: explicit request values WIN. Defaults only fill empty /
// zero-value request fields, so an operator who needs a different
// shape can override per-request without breaking the profile path.
//
// Operator allow-list precedence: the helper runs BEFORE
// ValidateAndClampMetadata's intersect step, so any default that lands
// outside `OIDC.DCR.AllowedAuthMethods` / `AllowedGrantTypes` /
// `AllowedResponseTypes` / `AllowedApplicationTypes` is rejected with
// the same RFC 7591 envelope the user-supplied path returns. That
// keeps operator policy authoritative.
//
// Defaults:
//
//   - grant_types        → ["authorization_code", "refresh_token"]
//   - response_types     → ["code"]
//   - token_endpoint_auth_method → "none" (PKCE-only public client)
//   - application_type   → derived from redirect URIs:
//       - any http loopback / private-IP redirect → "native"
//       - else                                    → "web"
//
// The remaining four R9 fields (access_token_type=JWT,
// id_token_role_assertion=true, id_token_userinfo_assertion=true,
// clock_skew=2s) live on the synthesized OIDCApp shape, not on
// RFC7591Metadata. They are applied in the Register closure
// (cmd/start/start.go) where the OIDCApp is built.
func applyMCPProfileDefaults(meta *RFC7591Metadata) {
	if meta == nil {
		return
	}
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(meta.ResponseTypes) == 0 {
		meta.ResponseTypes = []string{"code"}
	}
	if strings.TrimSpace(meta.TokenEndpointAuthMethod) == "" {
		meta.TokenEndpointAuthMethod = "none"
	}
	if strings.TrimSpace(meta.ApplicationType) == "" {
		meta.ApplicationType = deriveApplicationType(meta.RedirectURIs)
	}
}

// deriveApplicationType picks "native" when any redirect URI is an
// http loopback / private-IP entry (Claude Code MCP / VS Code style),
// "web" otherwise. RFC 7591 §3.2.1 + RFC 8252 §7.3 — native clients
// register loopback redirect URIs because system browsers can't open
// custom-scheme URLs without user assist.
func deriveApplicationType(redirectURIs []string) string {
	for _, raw := range redirectURIs {
		if isLocalDevRedirectURI(raw) {
			return "native"
		}
	}
	return "web"
}

// deriveDevMode decides whether DevMode should be auto-enabled for a
// dynamically-registered OIDC client based on its redirect URIs.
//
// Rule (cavekit-dcr-bootstrap-validation.md R10):
//
//	DevMode = true  when ANY redirect URI has scheme "http" AND its host
//	                is a loopback address (localhost, 127.0.0.1, ::1)
//	                OR a private-range IP (RFC 1918 / RFC 4193).
//	DevMode = false when all redirect URIs use https — or use http with
//	                public-routable hosts (the public-http case is also
//	                rejected upstream by other validators; deriveDevMode
//	                does not flip DevMode on for it because public-http
//	                redirect URIs should be a hard fail, not a "let it
//	                through with DevMode" pattern).
//
// Native MCP clients (VS Code, Claude Code MCP, etc.) register with
// redirect URIs like http://127.0.0.1:33418/. Without DevMode the
// downstream redirect-host clamps reject these as insecure — which
// defeats the zero-config promise of DCR for local-dev clients. This
// helper derives the bit from the request rather than requiring the
// operator to flip it manually after registration.
//
// The helper is pure: no I/O, no logging, no error path. Malformed URIs
// are simply ignored (a malformed URI cannot itself justify DevMode;
// it will be rejected by the URL validator earlier in the pipeline).
//
// Wired into [applyMCPProfileDefaults] in T-109/T-110.
func deriveDevMode(redirectURIs []string) bool {
	for _, raw := range redirectURIs {
		if isLocalDevRedirectURI(raw) {
			return true
		}
	}
	return false
}

// isLocalDevRedirectURI returns true if `raw` is an http URI with a
// loopback or private-range host. Exposed at package level (lowercase)
// only so the unit tests can exercise individual entries — callers
// should use [deriveDevMode].
func isLocalDevRedirectURI(raw string) bool {
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
	// Hostname literals that are loopback by name.
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Non-IP host that isn't `localhost` — treat as public.
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return false
}
