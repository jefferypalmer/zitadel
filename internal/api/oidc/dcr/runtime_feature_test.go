package dcr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/feature"
)

// TestRuntimeFeatureFlagEnabled covers the gate-effective-value rules:
//   - production default (DefaultRuntimeFlag=false): the per-instance
//     `authz.GetFeatures(ctx).DynamicClientRegistration` flag is
//     authoritative. cavekit-feature-flag-dcr-runtime.md wired this
//     flag end-to-end; the SetInstanceFeatures gRPC + console toggle
//     are how operators flip it.
//   - permissive override (DefaultRuntimeFlag=true): test-only seam
//     emulating the v5.0.0-dcr.5 hotfix shape so future regressions
//     of the wire-up still have a safe override path.
func TestRuntimeFeatureFlagEnabled(t *testing.T) {
	flagOn := authz.WithInstance(context.Background(), &stubInstance{
		features: feature.Features{DynamicClientRegistration: true},
	})
	flagOff := authz.WithInstance(context.Background(), &stubInstance{
		features: feature.Features{DynamicClientRegistration: false},
	})

	t.Run("strict (production default false): per-instance flag authoritative", func(t *testing.T) {
		// Production default is already false; assert the strict semantics.
		assert.True(t, RuntimeFeatureFlagEnabled(flagOn), "explicit flag-on must enable")
		assert.False(t, RuntimeFeatureFlagEnabled(flagOff), "flag-off + default-false must disable")
	})

	t.Run("permissive override (DefaultRuntimeFlag=true): always enables", func(t *testing.T) {
		prev := DefaultRuntimeFlag
		DefaultRuntimeFlag = true
		t.Cleanup(func() { DefaultRuntimeFlag = prev })

		assert.True(t, RuntimeFeatureFlagEnabled(flagOn), "explicit flag-on still enables")
		assert.True(t, RuntimeFeatureFlagEnabled(flagOff),
			"permissive-default override → enables even when per-instance flag is off")
	})
}
