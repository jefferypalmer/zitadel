// Package dcr implements the OIDC Dynamic Client Registration HTTP
// surface (RFC 7591 / RFC 7592). T-008 lands the routing skeleton +
// dual-gate semantics; the handler bodies are filled in by T-031
// (POST register), T-050 (RFC 7592 GET/PUT/DELETE), and friends.
package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// errorEnvelope is the RFC 7591 §3.2.2 client-registration error body.
// All DCR handler error responses MUST use this shape so consumers
// (including Claude Code MCP) can parse uniformly.
type errorEnvelope struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Handler returns an http.Handler that serves the DCR routes under
// `/oidc/v1/register{/*}`. It is mounted ONLY when
// OIDC.DCR.Enabled=true at startup (cavekit-config.md R3 yaml gate);
// when not mounted, requests fall through to the surrounding mux and
// produce a 404 — that's the "yaml off → 404" half of the dual-gate.
//
// The handler then enforces the runtime half:
//
//   - Runtime feature flag OFF for the current instance →
//     HTTP 403 with `{"error":"feature_disabled","error_description":...}`
//     and `Content-Type: application/json;charset=UTF-8`.
//   - Runtime feature flag ON →
//     HTTP 200 stub response. T-031 (cavekit-register-handler.md)
//     replaces this with the real RFC 7591 POST handler; T-050
//     (cavekit-manage-handler.md) adds GET/PUT/DELETE on
//     `/oidc/v1/register/{client_id}`.
//
// The handler does NOT authenticate. The Initial-Access-Token mode
// (cavekit-register-handler.md R3) and the RFC 7592 RAT mode
// (cavekit-manage-handler.md R2) ride on top of this handler in
// later tasks; today every reachable response is "feature gate ok".
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authz.GetFeatures(r.Context()).DynamicClientRegistration {
			writeError(w, http.StatusForbidden, "feature_disabled",
				"Dynamic Client Registration is not enabled for this instance.")
			return
		}

		// Stub. T-031 / T-050 will replace this branch with method-aware
		// (POST/GET/PUT/DELETE) routing and the real RFC 7591/7592 logic.
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "dcr_handler_stub",
			"message": "DCR is gated ON; the real handler arrives with T-031 / T-050.",
		})
	})
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{
		Error:            code,
		ErrorDescription: description,
	})
}
