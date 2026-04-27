package dcr

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// stubMismatchedHasher is the F-101 reproduction artifact: a hasher
// whose Hash returns an `$argon2id$`-encoded string but whose
// underlying Swapper has NO argon2id verifier registered. Verifies
// against the produced hash with ANY plaintext return ErrNoVerifier
// — exactly the production cmd/defaults.yaml shape (Algorithm: bcrypt
// + empty Verifiers list) that turned the anti-enum guard into an
// inverted timing oracle.
type stubMismatchedHasher struct {
	// realArgonHasher is used to produce the encoded hash on Hash().
	// realBcryptOnlySwapper is what Verify() goes through — it has
	// no argon2id verifier so it returns ErrNoVerifier.
	realArgonHasher       *argon2.Hasher
	realBcryptOnlySwapper *passwap.Swapper
}

func newStubMismatchedHasher(t *testing.T) *stubMismatchedHasher {
	t.Helper()
	argon := argon2.NewArgon2id(argon2.RecommendedIDParams)
	bcryptOnly := passwap.NewSwapper(bcrypt.New(bcrypt.MinCost))
	return &stubMismatchedHasher{
		realArgonHasher:       argon,
		realBcryptOnlySwapper: bcryptOnly,
	}
}

func (h *stubMismatchedHasher) Hash(plaintext string) (string, error) {
	return h.realArgonHasher.Hash(plaintext)
}

func (h *stubMismatchedHasher) Verify(encoded, plaintext string) (string, error) {
	return h.realBcryptOnlySwapper.Verify(encoded, plaintext)
}

// TestBuildAntiEnumDummyHash_F101_PanicsOnErrNoVerifier pins the
// startup probe per cavekit-iat.md R4 amendment 2026-04-27 / F-101.
// When the configured swapper cannot Verify its own Hash output (an
// algorithm-mismatch shape — exactly the F-101 vulnerability), the
// wiring helper MUST panic at startup so the deployment fails fast
// rather than serving traffic with a silently-inverted timing oracle.
func TestBuildAntiEnumDummyHash_F101_PanicsOnErrNoVerifier(t *testing.T) {
	hasher := newStubMismatchedHasher(t)
	require.Panics(t, func() {
		_, _ = BuildAntiEnumDummyHash(hasher)
	}, "wiring helper MUST panic when Verify on its own Hash output returns ErrNoVerifier")
}

// TestBuildAntiEnumDummyHash_F101_HappyPath confirms the helper
// returns a usable hash when the hasher and verifier match.
func TestBuildAntiEnumDummyHash_F101_HappyPath(t *testing.T) {
	hasher := newRealBcryptHasher(t)
	got, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	// Wrong plaintext must return a non-nil non-ErrNoVerifier error.
	_, verifyErr := hasher.Verify(got, "wrong-plaintext")
	require.Error(t, verifyErr)
	assert.False(t, errors.Is(verifyErr, passwap.ErrNoVerifier),
		"matched-algorithm verify must NOT return ErrNoVerifier (this is the whole point of the fix)")
}

// realBcryptHasherAdapter wraps a real bcrypt-only passwap.Swapper to
// satisfy [IATHasher] for tests. Mirrors the production
// internal/crypto/passwap.go::Hasher shape: same algorithm for both
// Hash and Verify, no shape-mismatch.
type realBcryptHasherAdapter struct {
	swapper *passwap.Swapper
}

func newRealBcryptHasher(t *testing.T) *realBcryptHasherAdapter {
	t.Helper()
	return &realBcryptHasherAdapter{
		swapper: passwap.NewSwapper(bcrypt.New(bcrypt.MinCost)),
	}
}

func (a *realBcryptHasherAdapter) Hash(plaintext string) (string, error) {
	return a.swapper.Hash(plaintext)
}

func (a *realBcryptHasherAdapter) Verify(encoded, plaintext string) (string, error) {
	return a.swapper.Verify(encoded, plaintext)
}

// realPasswapVerifier wraps a real passwap-backed hasher to satisfy
// the dcr [IATVerifier] interface — i.e. the registration-handler
// VerifyIATPlaintext seam. CRITICAL: this is what F-101 demanded —
// the timing test MUST go through real Passwap, not a string-equality
// stub.
type realPasswapVerifier struct {
	hasher IATHasher
}

func (v *realPasswapVerifier) VerifyIATPlaintext(presented, encoded string) error {
	if presented == "" || encoded == "" {
		return errors.New("empty input")
	}
	if _, err := v.hasher.Verify(encoded, presented); err != nil {
		return err
	}
	return nil
}

// TestResolveIAT_F101_RealPasswapTimingEquivalence is the F-101
// regression test per cavekit-iat.md R4 amendment 2026-04-27 AC3.
// Goes through a REAL passwap.Swapper (NOT a string-equality stub —
// that's how F-101 slipped past T-038). Asserts mean-not-found /
// mean-wrong-random ratio falls in [0.5, 2.0]. Pre-fix the dummy is
// a $argon2id$ literal vs a bcrypt swapper → not-found returns
// instantly via ErrNoVerifier → ratio ≪ 1 → FAIL. Post-fix both
// paths run real bcrypt-cost-4 verify → ratio ≈ 1 → PASS.
func TestResolveIAT_F101_RealPasswapTimingEquivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test takes ~200ms; skipped under -short")
	}
	const N = 50
	hasher := newRealBcryptHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)

	// Real-hashed row hash for the wrong-random branch.
	rowHash, err := hasher.Hash("the-real-token-random")
	require.NoError(t, err)

	verifier := &realPasswapVerifier{hasher: hasher}
	parser := func(presented string) (string, string, bool) {
		// Anything starting with `zdiat_id.` parses as id="id" with
		// random=remainder. Returns ok=false for the malformed-input
		// scenario we don't exercise here.
		if !strings.HasPrefix(presented, "zdiat_") {
			return "", "", false
		}
		body := strings.TrimPrefix(presented, "zdiat_")
		idPart, randomPart, ok := strings.Cut(body, ".")
		if !ok || idPart == "" || randomPart == "" {
			return "", "", false
		}
		return idPart, randomPart, true
	}

	ctx := authz.WithInstanceID(context.Background(), "inst-1")

	// Warmup: prime any one-shot caches in the bcrypt verifier.
	_, _ = ResolveIAT(ctx, stubIATQueries{err: errors.New("nf")}, verifier, parser, "zdiat_warm.up", dummy)

	measure := func(queries IATLookupQueries, presented string) time.Duration {
		start := time.Now()
		_, _ = ResolveIAT(ctx, queries, verifier, parser, presented, dummy)
		return time.Since(start)
	}

	notFoundQueries := stubIATQueries{err: errors.New("nf")}
	wrongRandomQueries := stubIATQueries{row: &QueryIATRow{
		ID:            "iat-1",
		InstanceID:    "inst-1",
		ResourceOwner: "org-1",
		ProjectID:     "proj-1",
		TokenHash:     rowHash,
	}}

	var notFoundTotal, wrongRandomTotal time.Duration
	for i := 0; i < N; i++ {
		notFoundTotal += measure(notFoundQueries, "zdiat_some-id.somerandom")
		wrongRandomTotal += measure(wrongRandomQueries, "zdiat_iat-1.wrongrandom")
	}
	notFoundMean := notFoundTotal / N
	wrongRandomMean := wrongRandomTotal / N
	ratio := float64(notFoundMean) / float64(wrongRandomMean)

	t.Logf("F-101 timing: not-found mean=%v, wrong-random mean=%v, ratio=%.3f",
		notFoundMean, wrongRandomMean, ratio)

	assert.GreaterOrEqual(t, ratio, 0.5,
		"not-found path must NOT be more than 2x faster than wrong-random — F-101 inverted-oracle regression")
	assert.LessOrEqual(t, ratio, 2.0,
		"not-found path must NOT be more than 2x slower than wrong-random — defensive upper bound")
}
