package dcr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// DecodeOptions parametrise the request decoder. Values come from
// `OIDC.DCR.MaxRequestBodyBytes` (cavekit-config.md R1) and the
// allow-list config the clamp uses afterwards.
type DecodeOptions struct {
	// MaxBodyBytes caps the request body (R2 AC: 413 when exceeded).
	// Zero means "use the package default" (DefaultMaxBodyBytes).
	MaxBodyBytes int64
}

// DefaultMaxBodyBytes is the fallback cap used when DecodeOptions
// leaves MaxBodyBytes unset. Mirrors the cmd/defaults.yaml value
// (65536) so unconfigured callers behave the same as a default deploy.
const DefaultMaxBodyBytes int64 = 65536

// Synthesised client_name format per cavekit-register-handler.md R2:
// `Dynamically Registered Client <clientID[:8]>`. The handler computes
// the suffix AFTER mint-id (T-040 RegisterClient.in.App.AppName is
// the audit-side ClientNameUnclamped — the synthesised value goes
// onto the clamped/persisted side once the client_id is known).
//
// SynthesiseClientName is exported so the handler dispatcher (T-033 +
// T-040 wiring) can produce it once the snowflake clientID is allocated.
// Per AC: "Empty / missing client_name is replaced with the synthesized
// string"; the handler decides when to call this based on the post-decode
// metadata (after Decode has applied defaults but BEFORE clamp).
func SynthesiseClientName(clientID string) string {
	const prefix = "Dynamically Registered Client "
	id := clientID
	if len(id) > 8 {
		id = id[:8]
	}
	return prefix + id
}

// Decode reads + parses the RFC 7591 registration request body from r.
// Returns the decoded metadata (with R2 defaults applied) on success.
// On any R2 error condition returns a *ClampError carrying the right
// HTTP status code so the dispatcher can `WriteError` with one branch.
//
// Status mapping per R2 ACs (RFC 7591 §3.2.2 envelope):
//   - Content-Type not application/json → 415 + `unsupported_media_type`
//   - body > MaxBodyBytes → 413 + `payload_too_large`
//   - malformed JSON → 400 + `invalid_client_metadata`
//
// `error: "unsupported_media_type"` and `error: "payload_too_large"`
// are NOT defined by RFC 7591 §3.2.2's 4-code allow-list — the kit R2
// AC names them explicitly because they map to the HTTP status code,
// not the RFC envelope codes. Decode emits them as the envelope `error`
// field for consistency; the spec's R8 status-code matrix accepts
// 413/415 as "permitted HTTP extensions."
//
// Unknown JSON fields are silently dropped per R2 last AC (default
// json.Decoder behaviour without DisallowUnknownFields).
func Decode(r *http.Request, opts DecodeOptions) (*RFC7591Metadata, error) {
	if r == nil || r.Body == nil {
		return nil, &ClampError{
			Status:      http.StatusBadRequest,
			Code:        ErrCodeInvalidClientMetadata,
			Description: "request body is required",
		}
	}

	// 415 — Content-Type. mime.ParseMediaType strips parameters
	// ("application/json; charset=utf-8" → "application/json") so the
	// charset hint clients send doesn't break the gate. RFC 7591 §3.1
	// requires application/json — but case-insensitively per RFC 7231
	// §3.1.1.1.
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil, &ClampError{
			Status:      http.StatusUnsupportedMediaType,
			Code:        ErrCodeUnsupportedMediaType,
			Description: "Content-Type header is required and must be application/json",
		}
	}
	mt, _, mtErr := mime.ParseMediaType(ct)
	if mtErr != nil || !strings.EqualFold(mt, "application/json") {
		return nil, &ClampError{
			Status:      http.StatusUnsupportedMediaType,
			Code:        ErrCodeUnsupportedMediaType,
			Description: fmt.Sprintf("Content-Type %q not supported; use application/json", ct),
		}
	}

	// 413 — body cap. http.MaxBytesReader returns *MaxBytesError on
	// overflow during io.ReadAll; we map that to the 413 envelope.
	max := opts.MaxBodyBytes
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	body, readErr := io.ReadAll(http.MaxBytesReader(nil, r.Body, max))
	if readErr != nil {
		var mbe *http.MaxBytesError
		if errors.As(readErr, &mbe) {
			return nil, &ClampError{
				Status:      http.StatusRequestEntityTooLarge,
				Code:        ErrCodePayloadTooLarge,
				Description: fmt.Sprintf("request body exceeds MaxRequestBodyBytes (%d)", max),
			}
		}
		return nil, &ClampError{
			Status:      http.StatusBadRequest,
			Code:        ErrCodeInvalidClientMetadata,
			Description: "failed to read request body",
		}
	}
	if len(body) == 0 {
		return nil, &ClampError{
			Status:      http.StatusBadRequest,
			Code:        ErrCodeInvalidClientMetadata,
			Description: "request body is empty",
		}
	}

	// 400 — malformed JSON. Default decoder allows unknown fields
	// (R2 AC: silently dropped). UseNumber() not needed — the metadata
	// struct uses concrete types.
	var meta RFC7591Metadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, &ClampError{
			Status:      http.StatusBadRequest,
			Code:        ErrCodeInvalidClientMetadata,
			Description: fmt.Sprintf("malformed JSON: %s", err.Error()),
		}
	}

	// Drop client_name#<lang> — these are unknown JSON fields by Go's
	// struct-tag mapping (no `client_name#<lang>` field on
	// RFC7591Metadata) so they're already silently dropped by Unmarshal
	// per R4 AC `client_name#<lang> localized variants are silently
	// dropped`.

	ApplyDefaults(&meta)
	return &meta, nil
}

// ApplyDefaults fills the R2 default values onto an in-place
// RFC7591Metadata struct. Called by Decode after JSON unmarshal but
// usable standalone for tests / the PUT handler (T-054) that re-clamps
// pre-existing metadata.
//
// Defaults per R2 ACs:
//   - grant_types missing/empty → ["authorization_code"]
//   - response_types missing/empty → ["code"]
//   - token_endpoint_auth_method missing → "client_secret_basic"
//   - application_type missing → "web" (OIDC Reg 1.0 §2 — NOT RFC 7591)
//
// client_name is intentionally NOT defaulted here; the synthesised
// "Dynamically Registered Client <id[:8]>" needs the post-mint client_id
// the handler dispatcher allocates, so the handler calls
// SynthesiseClientName once the ID exists. ApplyDefaults leaves an
// empty ClientName as-is.
func ApplyDefaults(m *RFC7591Metadata) {
	if m == nil {
		return
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{"authorization_code"}
	}
	if len(m.ResponseTypes) == 0 {
		m.ResponseTypes = []string{"code"}
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if m.ApplicationType == "" {
		m.ApplicationType = "web"
	}
}
