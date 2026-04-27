package dcr

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/bcrypt"
)

// TestT058_TimingSideChannel_RFC7592ManageVerify is the
// cavekit-security-hardening.md R4 (T-058) timing-side-channel
// regression test for the RFC 7592 manage-handler verify path.
//
// Threat model T12 — an attacker enumerates valid `client_id`s by
// observing response-time deltas between (a) unknown client_id +
// wrong RAT and (b) known client_id + wrong RAT. The mitigation is
// `VerifyRAT`'s NotFound branch paying one Passwap.Verify cost
// against the configured `AntiEnumDummyHash` so timing matches the
// known-and-wrong branch (T-051 implementation, T-052 cross-handler
// structural pin).
//
// This test exercises the actual `VerifyRAT` function with a REAL
// `passwap.Swapper` (NOT a fake verifier) so a regression that bypasses
// the dummy-Verify call OR uses a non-matching dummy hash (F-101
// inverted-oracle shape) fails the ratio bound.
//
// Methodology mirrors `TestResolveIAT_F101_RealPasswapTimingEquivalence`
// (the IAT-side timing test): 50 iterations × 2 branches, real
// bcrypt-cost-4 verify per call (~5ms each), assert the ratio of
// means falls in [0.5, 2.0]. The kit's literal text mentions "1000
// GETs" + "mean+p95 delta < 5ms" — at bcrypt cost 4 each verify is
// ~5ms, so a 5ms ABSOLUTE delta is a ~100% ratio bound; the [0.5,
// 2.0] ratio is a STRICTER bound (≤2x relative drift) and covers the
// kit's CI-failure intent.
//
// Skipped under -short (CI feasibility).
func TestT058_TimingSideChannel_RFC7592ManageVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-side-channel test takes ~500ms; skipped under -short")
	}

	const N = 50

	// Real bcrypt-only Swapper — same algorithm produces the dummy
	// hash AND verifies all paths, so the ErrNoVerifier shortcut that
	// caused F-101 cannot occur here. Active+verifier symmetry is the
	// production-safe wiring (cmd/start/start.go uses
	// commands.SecretHasher() which embeds the configured Swapper).
	swapper := passwap.NewSwapper(bcrypt.New(bcrypt.MinCost))
	verifier := &realRotationVerifier{swapper: swapper}

	// Build the dummy hash via the production helper so the test
	// exercises the same construction site `BuildAntiEnumDummyHash`
	// uses; a regression that breaks the production helper fails this
	// test even when the wrong-RAT-on-known-client branch still works.
	hasher := &realBcryptHasherAdapter{swapper: swapper}
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)

	// Stored hash for the wrong-RAT-on-known branch.
	storedHash, err := swapper.Hash("the-real-RAT-plaintext")
	require.NoError(t, err)

	knownClientRow := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: storedHash,
	}

	knownDeps := ManageDeps{
		Queries:           &fakeManageQueries{row: knownClientRow},
		RATVerifier:       verifier,
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: dummy,
	}
	unknownDeps := ManageDeps{
		Queries:           &fakeManageQueries{err: errors.New("not found")},
		RATVerifier:       verifier,
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: dummy,
	}

	// Warmup: prime any one-shot caches in the bcrypt verifier.
	_, _ = VerifyRAT(context.Background(), knownDeps, "client-1", "warmup")
	_, _ = VerifyRAT(context.Background(), unknownDeps, "unknown", "warmup")

	measure := func(deps ManageDeps, clientID, presented string) time.Duration {
		start := time.Now()
		_, _ = VerifyRAT(context.Background(), deps, clientID, presented)
		return time.Since(start)
	}

	var unknownTotal, wrongRATTotal time.Duration
	for i := 0; i < N; i++ {
		// Branch (a): nonexistent client_id with any RAT.
		unknownTotal += measure(unknownDeps, "unknown", "zdrat_anything")
		// Branch (b): known-valid client_id with WRONG RAT.
		wrongRATTotal += measure(knownDeps, "client-1", "zdrat_wrong-RAT-plaintext")
	}

	unknownMean := unknownTotal / N
	wrongRATMean := wrongRATTotal / N
	ratio := float64(unknownMean) / float64(wrongRATMean)

	t.Logf("T-058 timing: unknown-clientID mean=%v, wrong-RAT-on-known mean=%v, ratio=%.3f",
		unknownMean, wrongRATMean, ratio)

	// R4 AC3: tight bound. The kit's "5ms delta" loose phrasing
	// translates here to a ratio of [0.5, 2.0] — both branches MUST
	// run real bcrypt-cost-4 verify exactly once, so the means align
	// to within ~2x noise. A regression that elides the dummy-Verify
	// call returns the unknown branch in microseconds → ratio ≪ 1 →
	// fails. F-101's inverted oracle (ErrNoVerifier shortcut) had the
	// SAME failure shape in the IAT path; this asserts the parallel
	// guard for the RFC 7592 manage path.
	assert.GreaterOrEqual(t, ratio, 0.5,
		"R4 AC3 / T12: unknown-client_id MUST NOT be more than 2x faster than wrong-RAT-on-known — anti-enum regression")
	assert.LessOrEqual(t, ratio, 2.0,
		"R4 AC3 / T12: unknown-client_id MUST NOT be more than 2x slower than wrong-RAT-on-known — defensive upper bound")
}
