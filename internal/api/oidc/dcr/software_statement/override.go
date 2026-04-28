package software_statement

// override.go implements cavekit-software-statement.md R6 — claim-to-
// metadata override mapping per RFC 7591 §2.3 — and R7 — required-
// claim enforcement.
//
// R6: when a verified software_statement carries any of the mapped
// claims below, the JWT value supersedes the caller's request body for
// that field. Envelope claims (iss, iat, exp, jti, nbf, plus any
// trusted-issuer-specific custom claim used purely for vetting) are
// NEVER mapped — the operator's grant of "trust this JWT" doesn't
// extend to letting the JWT issue arbitrary claims back into the
// metadata stream.
//
// The single mapped-claims comment below MUST stay in sync with
// `mappedClaims`; the unit test asserts both lists agree
// alphabetically. If you add a claim, update both.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// mappedClaims enumerates the RFC 7591 §2.3 metadata claims a
// software_statement may override. Comment ↔ table ↔ test must agree.
//
// Mapped (JWT supersedes body):
//   - redirect_uris
//   - grant_types
//   - response_types
//   - scope
//   - client_name
//   - client_uri
//   - logo_uri
//   - tos_uri
//   - policy_uri
//   - software_id
//   - software_version
var mappedClaims = []string{
	"client_name",
	"client_uri",
	"grant_types",
	"logo_uri",
	"policy_uri",
	"redirect_uris",
	"response_types",
	"scope",
	"software_id",
	"software_version",
	"tos_uri",
}

// MissingRequiredClaimKey is the i18n key for R7 rejections.
const MissingRequiredClaimKey = "Errors.DCR.SoftwareStatement.MissingRequiredClaim"

// MergedMetadata applies the R6 override pass to a body-decoded RFC
// 7591 metadata payload using a verified software_statement. Returns a
// new map keyed by RFC 7591 §2 field names where the JWT-supplied
// values override the body-supplied ones for any claim in
// `mappedClaims`. Body-only / unmapped fields pass through.
//
// The caller is the register handler (T-031) which:
//   1. Decodes the request body into RFC7591Metadata.
//   2. Parses + verifies the software_statement (T-005, T-013, T-027).
//   3. Calls MergedMetadata to produce the override-applied map.
//   4. Re-decodes the map into RFC7591Metadata for the existing R4
//      clamp pipeline (Phase 1 R4) — kit R6 explicit: "merged result
//      still flows through Phase 1 R4 clamps (cannot bypass
//      scheme allow-list)".
//
// `bodyMap` carries the caller-supplied JSON body decoded as
// map[string]json.RawMessage so unknown fields (or fields missing on
// RFC7591Metadata) survive the round-trip. The handler is responsible
// for the body-decode; this function is pure.
func MergedMetadata(bodyMap map[string]json.RawMessage, parsed *Parsed) map[string]json.RawMessage {
	if parsed == nil {
		// No software_statement → no override pass. Return the body
		// unchanged so the caller's existing decode flow continues.
		return bodyMap
	}
	out := make(map[string]json.RawMessage, len(bodyMap)+len(mappedClaims))
	for k, v := range bodyMap {
		out[k] = v
	}
	for _, claim := range mappedClaims {
		if v, ok := parsed.Body.Extra[claim]; ok && len(v) > 0 {
			out[claim] = v
		}
	}
	return out
}

// MappedClaims returns a defensive copy of the override-eligible claim
// list. Exposed for tests so the comment ↔ table parity assertion
// doesn't reach into private state.
func MappedClaims() []string {
	out := make([]string, len(mappedClaims))
	copy(out, mappedClaims)
	return out
}

// VerifyRequiredClaims runs cavekit-software-statement.md R7 against a
// parsed software_statement. The trusted-issuer descriptor's
// RequiredClaims list (zero or more claim names) MUST each be present
// AND non-empty in the body. Empty RequiredClaims passes by definition
// (R5's standard JWT claims have already been enforced by Verify).
//
// Empty-value semantics: null, "", [], {} are treated as absent.
// Any other value (string with content, non-empty array, object with
// fields, number, bool) passes.
//
// Failure returns *ParseError keyed MissingRequiredClaimKey with the
// claim name in error_description (operator-supplied, safe to reflect
// per kit R7).
func VerifyRequiredClaims(parsed *Parsed, requiredClaims []string) *ParseError {
	if len(requiredClaims) == 0 || parsed == nil {
		return nil
	}
	for _, claim := range requiredClaims {
		raw, present := parsed.Body.Extra[claim]
		if !present || isAbsentValue(raw) {
			return &ParseError{
				Code:        "invalid_software_statement",
				Description: fmt.Sprintf("software_statement: required claim %q is missing or empty", claim),
				I18nKey:     MissingRequiredClaimKey,
			}
		}
	}
	return nil
}

// isAbsentValue reports whether a JSON value is null, empty string,
// empty array, or empty object — the four R7 "treated as absent"
// forms. Anything else returns false (claim is present and non-empty).
func isAbsentValue(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	switch trimmed {
	case "", "null", "\"\"", "[]", "{}":
		return true
	}
	return false
}
