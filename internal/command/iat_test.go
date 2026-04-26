package command

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateIATPlaintext pins cavekit-iat.md R5 acceptance:
//   - plaintext begins with literal `zdiat_`
//   - decoded random portion is exactly 48 bytes
//   - base64url (no padding) encoding produces a fixed length string
//   - successive calls produce distinct values (cryptographic randomness)
func TestGenerateIATPlaintext(t *testing.T) {
	const expectedRandomBytes = 48
	// 48 bytes → ceil(48 * 4 / 3) chars without padding = 64.
	const expectedEncodedLen = 64

	tok, err := GenerateIATPlaintext()
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(tok, IATPlaintextPrefix), "must start with %q, got %q", IATPlaintextPrefix, tok)
	suffix := strings.TrimPrefix(tok, IATPlaintextPrefix)
	assert.Len(t, suffix, expectedEncodedLen, "encoded random portion length")

	decoded, err := base64.RawURLEncoding.DecodeString(suffix)
	require.NoError(t, err, "suffix must be valid base64url (no padding)")
	assert.Len(t, decoded, expectedRandomBytes, "decoded random byte count")

	// Distinctness across two calls — collision probability with 384
	// bits of entropy is astronomically low; if this ever flakes the
	// CSPRNG itself is broken.
	other, err := GenerateIATPlaintext()
	require.NoError(t, err)
	assert.NotEqual(t, tok, other, "two consecutive generations must produce distinct plaintext")
}

// TestIsIATPlaintext_PrefixDiscriminator covers the cheap structural
// check used by the registration handler before calling Passwap.Verify.
func TestIsIATPlaintext_PrefixDiscriminator(t *testing.T) {
	gen, err := GenerateIATPlaintext()
	require.NoError(t, err)

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty string", "", false},
		{"freshly-generated token", gen, true},
		{"only the prefix", IATPlaintextPrefix, true},
		{"access-token prefix is not IAT", "at_abcdef", false},
		{"refresh-token prefix is not IAT", "rt_abcdef", false},
		{"session-token prefix is not IAT", "sess_abcdef", false},
		{"random bearer", "Bearer abc.def.ghi", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsIATPlaintext(tt.in))
		})
	}
}

// TestIATPrefix_NoCollisionWithKnownPrefixes is a guard test that
// fails loudly if a future refactor changes IATPlaintextPrefix to
// something that overlaps with another Zitadel token namespace
// (M1 prefix-collision check from cavekit-iat.md R5).
func TestIATPrefix_NoCollisionWithKnownPrefixes(t *testing.T) {
	// Tokens we positively control elsewhere in the repo (verified via
	// grep against `*Prefix = "..."` declarations at T-021 implementation):
	//   internal/command/oidc_session.go AccessTokenPrefix      = "at_"
	//   internal/command/oidc_session.go RefreshTokenPrefix     = "rt_"
	//   internal/api/authz/session_token.go SessionTokenPrefix  = "sess_"
	knownPrefixes := []string{"at_", "rt_", "sess_"}
	for _, p := range knownPrefixes {
		assert.False(t, strings.HasPrefix(IATPlaintextPrefix, p),
			"IAT prefix %q must not start with the known prefix %q", IATPlaintextPrefix, p)
		assert.False(t, strings.HasPrefix(p, IATPlaintextPrefix),
			"known prefix %q must not start with the IAT prefix %q", p, IATPlaintextPrefix)
	}
	assert.NotEmpty(t, IATPlaintextPrefix, "IAT prefix must not be empty")
	assert.True(t, strings.HasSuffix(IATPlaintextPrefix, "_"),
		"IAT prefix follows the trailing-underscore convention used by the rest of the repo")
}
