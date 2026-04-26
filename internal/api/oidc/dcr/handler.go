// Package dcr implements the OIDC Dynamic Client Registration HTTP
// surface (RFC 7591 / RFC 7592). T-008 landed the dual-gate semantics
// behind a single HandlerFunc; T-031 promotes that to a gorilla
// `*mux.Router` multiplexing POST/GET/PUT/DELETE on
// `/oidc/v1/register{/*}`. The handler bodies are still stubs — they
// land in T-033 (POST register), T-053 (GET), T-054 (PUT), and T-056
// (DELETE).
package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// HandlerPrefix is the URL path prefix the DCR handler is mounted at.
// Exported so OIDC discovery (cavekit-discovery-and-as-metadata.md R1 /
// T-029) and the RFC 8414 AS metadata handler (R2 / T-030) can advertise
// the same registration_endpoint URL the start.go mount uses — keeps
// the two from diverging.
const HandlerPrefix = "/oidc/v1/register"

// errorEnvelope is the RFC 7591 §3.2.2 client-registration error body.
// All DCR handler error responses MUST use this shape so consumers
// (including Claude Code MCP) can parse uniformly.
type errorEnvelope struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Handler returns the DCR HTTP surface mounted under
// `/oidc/v1/register{/*}`. The yaml gate (cavekit-config.md R3) is
// enforced at the start.go mount site — when off, the prefix is
// unmounted and the request gets the surrounding mux's 404. The
// runtime feature-flag half is enforced here as middleware: when the
// per-instance flag is off, every request returns 403 with the RFC
// 7591 `feature_disabled` envelope (and no method-routing happens).
//
// Method routing (cavekit-register-handler.md R1 + cavekit-manage-handler.md R1):
//
//   - POST /                 → register a new client (RFC 7591). Real
//                              body lands in T-033.
//   - GET  /{client_id}      → read existing client metadata (RFC 7592).
//                              Real body lands in T-053.
//   - PUT  /{client_id}      → update client (RFC 7592). Real body
//                              lands in T-054.
//   - DELETE /{client_id}    → delete client + revoke tokens (RFC 7592).
//                              Real body lands in T-056.
//
// Any other (path, method) combination falls through to a 404.
//
// Mounted via `apis.RegisterHandlerOnPrefix(HandlerPrefix, ...)` which
// strips the prefix before passing the request in, so the mux below
// sees paths like "/" or "/<client_id>".
//
// The handler does NOT authenticate. The Initial-Access-Token mode
// (cavekit-register-handler.md R3) and the RFC 7592 RAT mode
// (cavekit-manage-handler.md R2) ride on top of the routes here in
// later tasks.
func Handler() http.Handler {
	r := mux.NewRouter()
	// StrictSlash so requests for "" and "/" both route to POST /.
	r.StrictSlash(true)

	r.HandleFunc("/", postRegisterStub).Methods(http.MethodPost)
	r.HandleFunc("/{client_id}", getClientStub).Methods(http.MethodGet)
	r.HandleFunc("/{client_id}", putClientStub).Methods(http.MethodPut)
	r.HandleFunc("/{client_id}", deleteClientStub).Methods(http.MethodDelete)

	// Method-mismatch on a known path → 405 instead of 404 (gorilla mux
	// supports this via NotFound + MethodNotAllowed handlers; default is
	// 405 for known paths). Override 405 to match RFC 7591 idiom (return
	// the RFC envelope).
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request",
			"this DCR endpoint does not support the requested HTTP method.")
	})
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Cache-friendly 404 for unknown sub-paths under /oidc/v1/register.
		http.NotFound(w, req)
	})

	return featureGateMiddleware(r)
}

// featureGateMiddleware enforces the runtime half of the dual-gate.
// Wraps every method route so the gate runs BEFORE any RFC 7591/7592
// parsing — important so the 403 cannot be confused with a metadata
// validation error.
func featureGateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authz.GetFeatures(r.Context()).DynamicClientRegistration {
			writeError(w, http.StatusForbidden, "feature_disabled",
				"Dynamic Client Registration is not enabled for this instance.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// postRegisterStub is the placeholder for cavekit-register-handler.md
// R2..R8 (T-033..T-043). Returns the same 200 marker the T-008 single-
// HandlerFunc emitted so existing integration probes keep working.
func postRegisterStub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "dcr_handler_stub",
		"message": "DCR is gated ON; the real POST /register handler arrives with T-033.",
	})
}

// getClientStub / putClientStub / deleteClientStub are the placeholders
// for cavekit-manage-handler.md R4/R5/R6 (T-053..T-056). They return
// 501 so an integration probe can distinguish "method routed correctly
// but not yet implemented" from "wrong path".
func getClientStub(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"GET /oidc/v1/register/{client_id} arrives with T-053 (RFC 7592 read).")
}

func putClientStub(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"PUT /oidc/v1/register/{client_id} arrives with T-054 (RFC 7592 update).")
}

func deleteClientStub(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"DELETE /oidc/v1/register/{client_id} arrives with T-056 (RFC 7592 delete).")
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
