package dcr

import (
	"net"
	"net/url"
	"strings"
)

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
