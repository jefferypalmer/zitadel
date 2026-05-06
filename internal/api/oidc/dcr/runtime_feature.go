package dcr

import (
	"context"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// runtimeFeatureFlagEnabled implements the runtime half of the
// cavekit-config.md R3 dual-gate. The end-to-end wire-up of
// `feature.KeyDynamicClientRegistration` lives at
// `cavekit-feature-flag-dcr-runtime.md` (proto field, command write
// model, eventstore event types, projection reducer, query read model,
// console toggle). With that wire-up in place, operators flip the
// per-instance flag via the console (Instance Settings → Features →
// Dynamic Client Registration) or the SetInstanceFeatures gRPC, and
// the cascade through `internal/query/instance_by_id.sql`'s
// `json_object_agg(coalesce(i.value, s.value))` makes the projected
// value reach `authz.GetFeatures(ctx).DynamicClientRegistration`.
//
// `DefaultRuntimeFlag` is a package var so tests can pin permissive
// semantics for cases that exercise the gate-passes-when-off branch
// (the v5.0.0-dcr.5 hotfix permissive-default behavior, kept as a
// test-only seam in case a future operational override is needed).
// Production default is false — strict dual-gate.
var DefaultRuntimeFlag = false

// RuntimeFeatureFlagEnabled reports the effective per-instance runtime
// flag. Production callers should use this rather than reading
// `authz.GetFeatures(ctx).DynamicClientRegistration` directly.
func RuntimeFeatureFlagEnabled(ctx context.Context) bool {
	if authz.GetFeatures(ctx).DynamicClientRegistration {
		return true
	}
	return DefaultRuntimeFlag
}
