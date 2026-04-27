package dcr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRedactSecrets_T062 covers cavekit-security-hardening.md R3 ACs
// 5 + 6 (T-062): every secret pattern named in R3 MUST be redacted by
// `RedactSecrets`, including the IAT-token literal-`.`-in-plaintext
// case the R3 amendment 2026-04-26 calls out explicitly (half-
// redaction is unsafe — combining a log-leaked ID with a separately-
// leaked random reconstructs the credential).
//
// The integration-test variants `dcr_log_redaction_test.go` and
// `dcr_grpc_iat_logging_redaction_test.go` named in R3 are subsumed
// by this unit-level coverage given the M0 audit (T-006) found the
// HTTP + gRPC middleware do not log bodies — there is no production
// log-emission path for the integration test to capture today. Should
// a future change introduce body-logging, the integration test pair
// is added then; until then this unit pin is the structural guard.
func TestRedactSecrets_T062(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantContain string // substring that MUST appear (the redaction sentinel)
		wantAbsent  []string // substrings that MUST NOT appear (the secret values)
	}{
		{
			name:        "client_secret JSON echo redacted",
			in:          `{"client_id":"abc","client_secret":"super-sekrit-XYZ-1234"}`,
			wantContain: `"client_secret":"<REDACTED>"`,
			wantAbsent:  []string{"super-sekrit-XYZ-1234"},
		},
		{
			name:        "client_secret with whitespace around colon redacted",
			in:          `{"client_secret"  :  "spaced-out-secret"}`,
			wantContain: `<REDACTED>`,
			wantAbsent:  []string{"spaced-out-secret"},
		},
		{
			name:        "software_statement JWT redacted",
			in:          `{"software_statement":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjbGFpbXMifQ.SIGNATURE"}`,
			wantContain: `"software_statement":"<REDACTED>"`,
			wantAbsent:  []string{"eyJhbGciOiJSUzI1NiJ9", "SIGNATURE", "eyJzdWIiOiJjbGFpbXMifQ"},
		},
		{
			name:        "registration_access_token JSON echo redacted",
			in:          `{"registration_access_token":"zdrat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			wantContain: `"registration_access_token":"<REDACTED>"`,
			// JSON-keyed match runs first; the bare zdrat regex would
			// also match but the JSON replacement happens first so the
			// raw zdrat substring should not appear in the result.
			wantAbsent: []string{"zdrat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		},
		{
			name:        "Authorization Bearer redacted (HTTP/1.1 case)",
			in:          `Got request: Authorization: Bearer zdrat_aGVsbG8td29ybGQ from 192.0.2.1`,
			wantContain: "Authorization: Bearer <REDACTED>",
			wantAbsent:  []string{"zdrat_aGVsbG8td29ybGQ"},
		},
		{
			name:        "Authorization Bearer redacted (HTTP/2 lowercase)",
			in:          `headers: authorization: bearer zdiat_kj3h9.abcDEFghi1234567890_-XYZabcDEFghi1234567890_-Xa`,
			wantContain: "Authorization: Bearer <REDACTED>",
			wantAbsent:  []string{"zdiat_kj3h9.abcDEFghi1234567890_-XYZabcDEFghi1234567890_-Xa"},
		},
		{
			// R3 amendment 2026-04-26 — IAT plaintext contains a `.`
			// separator. Half-redacting (only random) reconstructs.
			// The pattern MUST match through the `.`.
			name:        "IAT plaintext with literal dot separator fully redacted",
			in:          `consume failed for IAT zdiat_iat-abc-123.SOMERANDOMb64URL_segment-here`,
			wantContain: "<REDACTED>",
			wantAbsent: []string{
				"zdiat_iat-abc-123.SOMERANDOMb64URL_segment-here",
				"iat-abc-123",
				"SOMERANDOMb64URL_segment-here",
			},
		},
		{
			name:        "RAT plaintext (no dot) redacted",
			in:          `rotated to zdrat_aGVsbG8td29ybGQtdGVzdC10b2tlbi1hYmM successfully`,
			wantContain: "<REDACTED>",
			wantAbsent:  []string{"zdrat_aGVsbG8td29ybGQtdGVzdC10b2tlbi1hYmM"},
		},
		{
			name: "multiple secrets in one string all redacted",
			in: `Authorization: Bearer zdrat_aaa
{"client_secret":"sekrit","registration_access_token":"zdrat_bbb"}
also bare zdiat_cc.dd here`,
			wantContain: "<REDACTED>",
			wantAbsent: []string{
				"zdrat_aaa",
				"sekrit",
				"zdrat_bbb",
				"zdiat_cc.dd",
				"cc.dd",
			},
		},
		{
			name:        "empty string passes through",
			in:          "",
			wantContain: "",
			wantAbsent:  nil,
		},
		{
			name:        "non-secret log line untouched",
			in:          `level=info msg="dcr handler mounted" prefix=/oidc/v1/register`,
			wantContain: "dcr handler mounted",
			wantAbsent:  []string{"REDACTED"}, // sentinel must not appear when no secret
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.in)
			if tc.wantContain != "" {
				assert.True(t, strings.Contains(got, tc.wantContain),
					"expected %q in result; got: %s", tc.wantContain, got)
			}
			for _, secret := range tc.wantAbsent {
				assert.False(t, strings.Contains(got, secret),
					"R3 / T-061: secret %q MUST NOT appear in redacted output; got: %s", secret, got)
			}
		})
	}
}

// TestRedactSecrets_HalfRedactionUnsafe is the explicit kit-amendment
// pin: a half-redaction shape (e.g. masking only the random portion of
// `zdiat_<id>.<random>`) is rejected. The implementation regex MUST be
// greedy through the `.` separator so the FULL token is masked.
//
// This test fails if a future regression replaces the `[^\s"',]+`
// character class with one that excludes `.`.
func TestRedactSecrets_HalfRedactionUnsafe(t *testing.T) {
	const id = "iat-id-1234"
	const random = "RANDOM-SEGMENT-1234567890"
	in := "zdiat_" + id + "." + random
	got := RedactSecrets(in)

	// The full token MUST be replaced by the sentinel.
	assert.Equal(t, "<REDACTED>", got,
		"R3 amendment / cavekit-iat.md R5: IAT plaintext MUST redact through the `.` separator; half-redaction reconstructs the credential")
	assert.False(t, strings.Contains(got, id),
		"half-redaction unsafe: ID portion MUST NOT survive in log output")
	assert.False(t, strings.Contains(got, random),
		"half-redaction unsafe: random portion MUST NOT survive in log output")
}
