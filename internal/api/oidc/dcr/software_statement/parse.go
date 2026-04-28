// Package software_statement implements RFC 7591 §2.3 / §3.1.1
// `software_statement` JWT verification for the DCR register handler.
// This file (T-005 / cavekit-software-statement.md R2) covers the
// structural parse: 3-segment split, base64url decode, JSON decode,
// header-`alg` requirement, body-`iss` requirement, and 64 KiB body
// size cap. Signature + claim verification (R5) lands in verify.go;
// trusted-issuer lookup (R3) in lookup.go; JWKS fetch (R4) in
// jwks_cache.go.
//
// Every error returned here is a *ParseError with code
// `invalid_software_statement` (RFC 7591 §3.2.2) and an i18n key under
// `Errors.DCR.SoftwareStatement.InvalidStructure` so the register
// handler can surface a uniform 400 envelope.
package software_statement

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxSoftwareStatementBytes caps the raw JWT before we even try to
// split it. cavekit-software-statement.md R2 specifies 64 KiB. The
// outer DCR `MaxRequestBodyBytes` already bounds the whole register
// request body; this is defense-in-depth so a single maliciously
// large JWT cannot push the register body cap (typically 64 KiB) to
// its full extent on `software_statement` alone.
const MaxSoftwareStatementBytes = 64 * 1024

// InvalidStructureKey is the i18n key returned for every R2
// structural failure. Trusted-issuer mismatch (R3), expiry / replay
// (R5), and required-claim absence (R7) use sibling keys.
const InvalidStructureKey = "Errors.DCR.SoftwareStatement.InvalidStructure"

// ParseError signals a structural failure. Code is always
// `invalid_software_statement` per RFC 7591 §3.2.2; the surfaced
// `error_description` is the package-level description (no operator
// secrets, no offending input echoed). I18nKey lets the register
// handler key the localization, mirroring Phase 1 ClampError.
type ParseError struct {
	Code        string
	Description string
	I18nKey     string
	Wrapped     error
}

func (e *ParseError) Error() string {
	if e == nil {
		return ""
	}
	if e.Wrapped != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Description, e.Wrapped)
	}
	return e.Code + ": " + e.Description
}

func (e *ParseError) Unwrap() error { return e.Wrapped }

func newStructureError(reason string) *ParseError {
	return &ParseError{
		Code:        "invalid_software_statement",
		Description: "software_statement: " + reason,
		I18nKey:     InvalidStructureKey,
	}
}

// Parsed is the structurally-decoded JWT. RawJWT preserves the full
// 3-segment string so signature verification (R5) can recompute the
// signing input. Header / Body are already JSON-decoded — callers
// that need the raw bytes should split them themselves rather than
// expand this type.
type Parsed struct {
	RawJWT  string
	RawHeader []byte
	RawBody   []byte
	Header  Header
	Body    Body
	// Issuer is Body.Iss verbatim (operator-controlled — safe to
	// reflect in audit logs but NOT in error_description per R3).
	Issuer string
}

// Header is the RFC 7515 §4.1 JOSE header subset we care about
// structurally. Signature verification (R5) reads `Alg` and `Kid`.
// Other JWS fields are accepted on the wire but ignored here.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Body is the RFC 7519 §4 claims subset visible at parse time. The
// shape MUST be a superset of what verify.go (R5) and override
// mapping (R6) read. Unknown claims are kept in Extra so override
// mapping can pull RFC 7591 §2.3-listed metadata claims back out.
type Body struct {
	Iss string `json:"iss"`
	Aud any    `json:"aud,omitempty"`
	Exp *int64 `json:"exp,omitempty"`
	Nbf *int64 `json:"nbf,omitempty"`
	Iat *int64 `json:"iat,omitempty"`
	Jti string `json:"jti,omitempty"`
	Sub string `json:"sub,omitempty"`
	// Extra holds every JSON field not enumerated above. Override
	// mapping (cavekit-software-statement.md R6 / T-028) reads from
	// Extra to pull RFC 7591 §2.3 claims (`redirect_uris`, etc.).
	Extra map[string]json.RawMessage `json:"-"`
}

// Parse runs cavekit-software-statement.md R2 on a `software_statement`
// JWT. Returns nil + nil for an empty input (caller decides whether the
// claim was required). On any structural failure returns nil + a
// *ParseError keyed Errors.DCR.SoftwareStatement.InvalidStructure.
//
// Parse is signature-agnostic — it MUST NOT trust any field. R5
// (verify.go) is the gate that enforces signature + claim semantics.
func Parse(raw string) (*Parsed, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxSoftwareStatementBytes {
		return nil, newStructureError(fmt.Sprintf(
			"size exceeds %d-byte cap", MaxSoftwareStatementBytes))
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, newStructureError("must be a 3-segment JWT")
	}
	for i, segment := range parts[:2] {
		if segment == "" {
			return nil, newStructureError(fmt.Sprintf("segment %d is empty", i))
		}
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: header is not valid base64url",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}
	rawBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: body is not valid base64url",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}

	var header Header
	if err := strictDecode(rawHeader, &header); err != nil {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: header is not valid JSON",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}
	if strings.TrimSpace(header.Alg) == "" {
		return nil, newStructureError("header `alg` is required")
	}

	// Decode body twice: once into a typed Body, once into a generic
	// map so we can preserve unknown claims for R6 override mapping
	// without re-parsing.
	var body Body
	if err := strictDecode(rawBody, &body); err != nil {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: body is not valid JSON",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}
	if strings.TrimSpace(body.Iss) == "" {
		return nil, newStructureError("body claim `iss` is required")
	}
	body.Extra = map[string]json.RawMessage{}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &generic); err != nil {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: body is not a JSON object",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}
	for k, v := range generic {
		switch k {
		case "iss", "aud", "exp", "nbf", "iat", "jti", "sub":
			// Fields enumerated on Body — skip.
		default:
			body.Extra[k] = v
		}
	}

	return &Parsed{
		RawJWT:    raw,
		RawHeader: rawHeader,
		RawBody:   rawBody,
		Header:    header,
		Body:      body,
		Issuer:    body.Iss,
	}, nil
}

// strictDecode runs json.Decoder with DisallowUnknownFields=false
// (we want unknown claims to land in Body.Extra) but UseNumber so a
// stray float64 parse can't drop precision on `exp` / `iat` / `nbf`.
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}
