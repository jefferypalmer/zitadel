package command

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIATPlaintext_R5_EmbedsIDFormat is the DE-001 regression test
// (cavekit-iat.md R5 amendment 2026-04-26). The plaintext MUST be of
// the form `zdiat_<id>.<random>` so the registration handler can look
// up the row by ID without needing a deterministic hash. Pre-amendment
// `GenerateIATPlaintext` returned `zdiat_<random>` with no ID — this
// test fails against the pre-amendment implementation and passes after
// the format change lands.
func TestIATPlaintext_R5_EmbedsIDFormat(t *testing.T) {
	// CreateInitialAccessToken is the sole external consumer of the
	// generator. We test the property at the format level rather than
	// calling the full command (which needs an eventstore harness)
	// because the kit AC is a property of the plaintext shape itself.
	plaintext, err := GenerateIATPlaintextForID("test-id-abc")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(plaintext, IATPlaintextPrefix),
		"plaintext must keep the zdiat_ prefix; got %q", plaintext)

	// Strip prefix. Remaining must be `<id>.<random>`.
	body := strings.TrimPrefix(plaintext, IATPlaintextPrefix)
	idPart, randomPart, ok := strings.Cut(body, ".")
	require.True(t, ok, "plaintext must contain a literal `.` separator; got %q", plaintext)
	assert.Equal(t, "test-id-abc", idPart, "ID portion must be the row PK we passed in")
	assert.NotEmpty(t, randomPart, "random portion must be non-empty")
	assert.True(t, len(randomPart) >= 60, "random portion must encode at least 48 bytes; got %d chars in %q", len(randomPart), randomPart)
}

// TestParseIATPlaintext_R5_FirstDotSplit pins the parser contract:
// `strings.Cut` first-dot split. An attacker who smuggles dots into
// the random portion must NOT be able to confuse the parser.
func TestParseIATPlaintext_R5_FirstDotSplit(t *testing.T) {
	// Build a plaintext where the random portion contains a `.`.
	// (Real bytes from base64url have no `.` — but the parser must
	// still split on the FIRST dot only, not greedy.)
	in := IATPlaintextPrefix + "id-1.random.with.extra.dots"
	id, random, ok := ParseIATPlaintext(in)
	require.True(t, ok)
	assert.Equal(t, "id-1", id, "first-dot split: ID is everything between prefix and first dot")
	assert.Equal(t, "random.with.extra.dots", random, "remainder (including subsequent dots) is the random portion")
}

// TestParseIATPlaintext_R5_RejectsMalformed pins the negative cases.
func TestParseIATPlaintext_R5_RejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"zdiat_",                // no separator, no random
		"zdiat_no-separator",    // missing dot
		"zdiat_.empty-id-random", // empty ID
		"zdiat_id.",             // empty random
		"not-a-zdiat-token.x.y", // wrong prefix
		"ZDIAT_id.random",       // case-sensitive prefix per kit (lowercase only)
		"zdiat_id with space.r", // ID alphabet violation
		"zdiat_id+plus.random",  // ID alphabet violation (+ outside [A-Za-z0-9_-])
	}
	for _, s := range bad {
		_, _, ok := ParseIATPlaintext(s)
		assert.False(t, ok, "ParseIATPlaintext(%q) must reject", s)
	}
}

// TestParseIATPlaintext_R5_AcceptsValid pins the positive cases.
func TestParseIATPlaintext_R5_AcceptsValid(t *testing.T) {
	good := []struct {
		in            string
		wantID        string
		wantRandom    string
	}{
		{"zdiat_a.bcd", "a", "bcd"},
		{"zdiat_ABC123_-z.QWERTY", "ABC123_-z", "QWERTY"},
		{"zdiat_id.random.with.dots", "id", "random.with.dots"},
	}
	for _, c := range good {
		id, random, ok := ParseIATPlaintext(c.in)
		assert.True(t, ok, "ParseIATPlaintext(%q) must accept", c.in)
		assert.Equal(t, c.wantID, id)
		assert.Equal(t, c.wantRandom, random)
	}
}
