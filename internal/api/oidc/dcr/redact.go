package dcr

import (
	"regexp"
)

// redact.go provides defensive log-redaction utilities per
// cavekit-security-hardening.md R3 (T-061). Per the M0 audit (T-006)
// the HTTP + gRPC middleware do NOT log request/response bodies and
// `internal/logstore/` already redacts the Authorization header (T-063
// audit). These utilities are the "defensive wrapper" R3 AC3 calls
// for: any future log-line that constructs a string from caller input
// MUST pass it through `RedactSecrets` before slog'ing.
//
// Patterns matched:
//   - `zdiat_<id>.<random>`            — IAT plaintext (cavekit-iat.md R5)
//   - `zdrat_<base64url>`              — RAT plaintext (cavekit-manage-handler.md R5 / T-040)
//   - `"client_secret":"<value>"`      — JSON-shaped client_secret echo
//   - `"software_statement":"<value>"` — JSON-shaped JWT echo (Phase 2 surface)
//   - `"registration_access_token":"<value>"` — JSON-shaped RAT echo
//   - `Authorization: Bearer <token>`  — header-shaped (defense-in-depth alongside logstore)
//
// Each match is replaced with a fixed sentinel that preserves the
// JSON / header structure so log readability is unaffected and
// downstream parsers don't break.
//
// Half-redaction is unsafe (cavekit-security-hardening.md R3
// amendment 2026-04-26 / cavekit-iat.md R5): masking only the random
// portion of `zdiat_<id>.<random>` lets an attacker reconstruct the
// credential by combining a log-leaked ID with a separately-leaked
// random. The IAT regex MUST be greedy through the `.` separator.

const (
	redactedSentinel    = "<REDACTED>"
	redactedSecretJSON  = `"client_secret":"<REDACTED>"`
	redactedSWStmtJSON  = `"software_statement":"<REDACTED>"`
	redactedRATJSON     = `"registration_access_token":"<REDACTED>"`
	redactedBearer      = "Authorization: Bearer <REDACTED>"
	redactedBearerLower = "authorization: bearer <REDACTED>"
)

// secretPatterns is ordered: JSON-keyed forms first (more specific),
// then bare-token forms (greedy). The IAT regex `zdiat_[^\s"',]+`
// matches through the `.` separator per the kit AC.
var secretPatterns = []struct {
	rx          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`"client_secret"\s*:\s*"[^"]*"`), redactedSecretJSON},
	{regexp.MustCompile(`"software_statement"\s*:\s*"[^"]*"`), redactedSWStmtJSON},
	{regexp.MustCompile(`"registration_access_token"\s*:\s*"[^"]*"`), redactedRATJSON},
	// Authorization headers — case-insensitive matcher (HTTP/2 lowercases).
	{regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+[^\s\r\n,;"]+`), redactedBearer},
	// Bare zdiat_/zdrat_ — match outside JSON-string contexts, e.g. when
	// a log message echoes a token directly. Greedy through `.` and
	// other non-delimiters per kit AC.
	{regexp.MustCompile(`zdiat_[^\s"',]+`), redactedSentinel},
	{regexp.MustCompile(`zdrat_[^\s"',]+`), redactedSentinel},
}

// RedactSecrets returns s with every recognised secret pattern
// replaced by a sentinel. Safe for arbitrary log strings — applies
// patterns in order, no panic on malformed input.
//
// Performance note: the function compiles regexes ONCE at package
// init (the `regexp.MustCompile` calls in `secretPatterns`). Per-call
// cost is O(L · k) where L is len(s) and k is the pattern count (5
// here). Acceptable for log-emission paths.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	for _, p := range secretPatterns {
		s = p.rx.ReplaceAllString(s, p.replacement)
	}
	return s
}
