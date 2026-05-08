package dcr

import (
	"encoding/json"
	"net/http"
)

// RFC 7591 §3.2.2 client-registration error codes. Used as the `error`
// field of every 4xx response body emitted by the DCR HTTP surface
// (POST /register, GET/PUT/DELETE /register/{client_id}). Kept as
// exported string constants so handler bodies (T-033, T-053, T-054,
// T-056) and tests reference the same canonical value.
const (
	ErrCodeInvalidRedirectURI          = "invalid_redirect_uri"
	ErrCodeInvalidClientMetadata       = "invalid_client_metadata"
	ErrCodeInvalidSoftwareStatement    = "invalid_software_statement"
	ErrCodeUnapprovedSoftwareStatement = "unapproved_software_statement"

	// Not in RFC 7591 §3.2.2 but used uniformly across DCR for the
	// non-metadata failures: `feature_disabled` for the runtime-flag-off
	// gate (cavekit-config.md R3 / cavekit-register-handler.md R1),
	// `invalid_token` for IAT/RAT auth failures (cavekit-register-handler.md
	// R3 / cavekit-manage-handler.md R2/R3), `invalid_request` for
	// method-mismatch and other request-shape errors, `not_implemented`
	// for stubs awaiting later tasks.
	ErrCodeFeatureDisabled = "feature_disabled"
	ErrCodeInvalidToken    = "invalid_token"
	ErrCodeInvalidRequest  = "invalid_request"
	ErrCodeNotImplemented  = "not_implemented"

	// HTTP-status-mapped envelope codes used by the request decoder
	// (T-033 / R2). RFC 7591 §3.2.2 only enumerates the first four
	// codes above as 400 errors; 413 + 415 are documented HTTP
	// extensions per R8.
	ErrCodeUnsupportedMediaType = "unsupported_media_type"
	ErrCodePayloadTooLarge      = "payload_too_large"

	// MissingOrInvalidAccessTokenDescription is the canonical
	// `error_description` string for every 401 invalid_token response
	// (cavekit-register-handler.md R3 amendment 2026-04-27 / N-5).
	// RFC 6750 §3 vocabulary; the fixed string keeps log-aggregator
	// pattern matching stable across the four 401 paths (auth-first
	// short-circuit, IAT verify, IAT consume, RAT verify).
	MissingOrInvalidAccessTokenDescription = "missing or invalid access token"

	// ErrCodeServerError is the envelope `error` code for 500
	// responses (cavekit-register-handler.md R8 amendment / F-202).
	// Mirrors RFC 6749 §5.2's `server_error` family; intentionally
	// distinct from the RFC 7591 §3.2.2 metadata codes so consumers
	// can distinguish an internal fault from a client-input fault.
	ErrCodeServerError = "server_error"

	// ErrCodeDefaultProjectNotFound is the envelope `error` code
	// returned when anonymous-mode DCR cannot resolve the configured
	// DefaultProjectID / DefaultOrgID at request time — the projection
	// row was deleted or never existed. The dispatcher maps this to
	// HTTP 503 (server_error) so callers retry rather than treating it
	// as a permanent client-input fault. cavekit-dcr-bootstrap-validation
	// R5. The body still uses the RFC 7591 envelope `error: server_error`
	// per RFC 6749 §5.2 because RFC 7591 §3.2.2 doesn't enumerate a
	// per-deployment-state code; downstream tooling can disambiguate via
	// the description string.
	ErrCodeDefaultProjectNotFound = "default_project_not_found"
)

// ErrorEnvelope is the RFC 7591 §3.2.2 client-registration error body.
// All DCR handler error responses (POST + GET + PUT + DELETE) MUST use
// this exact shape so consumers — including Claude Code MCP — can parse
// uniformly across the four routes.
type ErrorEnvelope struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// WriteError sanitizes the description (F-202) before writing.
// WriteError is the single error-response writer for the DCR package.
// Sets the RFC 7591 Content-Type plus the no-store / no-cache pair that
// every DCR response (success or failure) carries — caching a DCR
// response would either replay a one-time RAT or mask a feature-flag
// flip. Callers in T-033/T-053/T-054/T-056 should use this rather than
// hand-rolling the envelope.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{
		Error:            code,
		ErrorDescription: SanitiseErrorDescription(description),
	})
}

// zerrors-ID convention: any zerrors raised inside this package use the
// `DCR-<5 alphanumeric>` prefix (e.g., `DCR-Wx2Y9`) so log scans can
// disambiguate DCR failures from sibling OIDC code paths. Tasks
// T-033/T-034/T-036/T-040/T-054 will introduce concrete IDs.

// MaxErrorDescriptionBytes caps user-input echoed in the
// `error_description` envelope field per cavekit-register-handler.md
// R8 amendment 2026-04-27 / F-202. Prevents log-injection (control
// chars) and oversized reflected-input flow into log aggregators.
const MaxErrorDescriptionBytes = 256

// SanitiseErrorDescription strips ASCII control characters (< 0x20
// except \t) and caps the length per F-202. Safe to call on
// any string; nil-safe on empty input.
func SanitiseErrorDescription(s string) string {
	if s == "" {
		return s
	}
	var b []byte
	for i := 0; i < len(s) && len(b) < MaxErrorDescriptionBytes; i++ {
		c := s[i]
		if c < 0x20 && c != '\t' {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
