package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

// RFC 8707 §2 resource-indicator validation.
//
// Validation runs once at request entry (in the AuthorizeResourceSidecar
// for /authorize, and per-handler for /token grants once T-045 lands).
// Failure produces the OAuth `invalid_target` error envelope per
// cavekit-rfc8707-resource.md R6 (T-028) — JSON 400, Content-Type
// application/json;charset=UTF-8.

// errInvalidTarget is the typed error returned by ValidateResources so
// callers can emit an `invalid_target` envelope without sniffing strings.
// It is exported via [InvalidTargetError] (the helper below) for the
// downstream token handlers in T-045.
type errInvalidTarget struct {
	description string
}

func (e *errInvalidTarget) Error() string {
	if e.description == "" {
		return "invalid_target"
	}
	return e.description
}

// IsInvalidTargetError reports whether err was produced by
// ValidateResources and therefore should map to an `invalid_target`
// 400 envelope.
func IsInvalidTargetError(err error) bool {
	var ite *errInvalidTarget
	return errors.As(err, &ite)
}

// ValidateResources enforces RFC 8707 §2 resource-indicator semantics
// against the configured AllowedAudiences allow-list.
//
// Behavior:
//   - len(resources) == 0 → nil (no resource specified is always OK).
//   - empty allow-list → any syntactically valid resource is accepted.
//   - non-empty allow-list → each resource must appear in the allow-list.
//   - first invalid value short-circuits with errInvalidTarget; the
//     description names the offending value but never echoes the
//     allow-list (don't leak the audience policy to unauthenticated
//     callers).
//
// Syntax rules (RFC 8707 §2 + RFC 3986 §4.3):
//   - parseable as URI
//   - absolute (has scheme)
//   - MUST NOT include a fragment component
func ValidateResources(resources, allowed []string) error {
	for _, r := range resources {
		if err := validateResourceSyntax(r); err != nil {
			return err
		}
		if len(allowed) == 0 {
			continue
		}
		if !slices.Contains(allowed, r) {
			return &errInvalidTarget{description: fmt.Sprintf("resource %q is not in the configured allow-list", r)}
		}
	}
	return nil
}

func validateResourceSyntax(raw string) error {
	if raw == "" {
		return &errInvalidTarget{description: "resource value is empty"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return &errInvalidTarget{description: fmt.Sprintf("resource %q is not a valid URI", raw)}
	}
	if !u.IsAbs() {
		return &errInvalidTarget{description: fmt.Sprintf("resource %q must be an absolute URI per RFC 8707 §2", raw)}
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return &errInvalidTarget{description: fmt.Sprintf("resource %q must not include a fragment per RFC 8707 §2", raw)}
	}
	return nil
}

// writeInvalidTargetError emits the OAuth `invalid_target` 400 envelope
// per cavekit-rfc8707-resource.md R6 (T-028). It is the canonical writer
// for both /authorize (called from the sidecar middleware) and /token
// (T-045 wires this into each token grant handler).
//
// Cache headers: discovery and AS-metadata responses set Cache-Control;
// error responses must not be cached, hence Cache-Control: no-store +
// Pragma: no-cache (matches the rest of the OIDC error pipeline).
func writeInvalidTargetError(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	if description == "" {
		description = "the requested resource is not valid"
	}
	// Hand-encoded to keep the byte sequence stable and avoid pulling
	// json marshalling for a two-field object.
	body := `{"error":"invalid_target","error_description":` + jsonString(description) + `}`
	_, _ = w.Write([]byte(body))
}

// jsonString hand-encodes a string for the invalid_target envelope.
// Avoids encoding/json just so the error path stays allocation-cheap and
// the wire bytes are stable across Go versions.
func jsonString(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				out = append(out, []byte(fmt.Sprintf(`\u%04x`, r))...)
				continue
			}
			out = append(out, []byte(string(r))...)
		}
	}
	out = append(out, '"')
	return string(out)
}
