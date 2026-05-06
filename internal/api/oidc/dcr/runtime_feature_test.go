package dcr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/feature"
)

// TestRuntimeFeatureFlagEnabled covers v5.0.0-dcr.5 hotfix semantics:
//   - DefaultRuntimeFlag=true (production default) → always true regardless
//     of `authz.GetFeatures(ctx).DynamicClientRegistration` (because the
//     proto/projection wire-up to set the flag is missing).
//   - DefaultRuntimeFlag=false (legacy / strict-gate emulation) →
//     reads the per-instance flag value.
//
// TestMain flips DefaultRuntimeFlag to false for the rest of the dcr
// test package; this test temporarily flips it back to true for the
// production-default arm.
func TestRuntimeFeatureFlagEnabled(t *testing.T) {
	flagOn := authz.WithInstance(context.Background(), &stubInstance{
		features: feature.Features{DynamicClientRegistration: true},
	})
	flagOff := authz.WithInstance(context.Background(), &stubInstance{
		features: feature.Features{DynamicClientRegistration: false},
	})

	t.Run("strict (default false): honors per-instance flag", func(t *testing.T) {
		// TestMain already set DefaultRuntimeFlag=false.
		assert.True(t, RuntimeFeatureFlagEnabled(flagOn), "explicit flag-on must enable")
		assert.False(t, RuntimeFeatureFlagEnabled(flagOff), "flag-off + default-false must disable")
	})

	t.Run("permissive (default true, the v5.0.0-dcr.5 production default): always enables", func(t *testing.T) {
		prev := DefaultRuntimeFlag
		DefaultRuntimeFlag = true
		t.Cleanup(func() { DefaultRuntimeFlag = prev })

		assert.True(t, RuntimeFeatureFlagEnabled(flagOn), "explicit flag-on still enables")
		assert.True(t, RuntimeFeatureFlagEnabled(flagOff),
			"v5.0.0-dcr.5 hotfix: permissive default → enables even when per-instance flag is off "+
				"(because the proto/projection wire-up to set it doesn't exist)")
	})
}
