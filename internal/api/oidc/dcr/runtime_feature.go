package dcr

import (
	"context"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// runtimeFeatureFlagEnabled implements the runtime half of the
// cavekit-config.md R3 dual-gate. Phase 1/2 added
// `feature.KeyDynamicClientRegistration` (`internal/feature/feature.go`
// line 28) plus the read sites here, in `oidc/server.go::dcrAdvertised`,
// and in `grpc/admin/iat.go::iatDualGate` — but the proto field on
// `Set{Instance,System}FeaturesRequest`, the command-layer
// `InstanceFeaturesWriteModel.DynamicClientRegistration` field, the
// projection mapping, and the console UI toggle were never added. With
// no write path, `authz.GetFeatures(ctx).DynamicClientRegistration`
// always reads the zero-value (false), making the runtime gate
// permanently closed regardless of operator intent.
//
// v5.0.0-dcr.5 hotfix: when the explicit runtime flag is true (i.e. a
// future wire-up has set it via the eventstore), honor that. When it's
// false, fall back to the runtime default — which v5.0.0-dcr.5 sets to
// true so the yaml gate (`OIDC.DCR.Enabled` / `s.dcrYAMLEnabled` /
// `s.dcrEnabled`) becomes the authoritative on/off. Multi-tenant
// per-instance disable returns once the proto + command + projection
// are wired (tracked as a follow-up).
//
// `DefaultRuntimeFlag` is a package-var so tests that assert the
// gate-fires-when-runtime-off contract can override it to false and
// verify the legacy code path still behaves correctly.
var DefaultRuntimeFlag = true

// RuntimeFeatureFlagEnabled reports the effective per-instance runtime
// flag. Production callers should use this rather than reading
// `authz.GetFeatures(ctx).DynamicClientRegistration` directly.
func RuntimeFeatureFlagEnabled(ctx context.Context) bool {
	if authz.GetFeatures(ctx).DynamicClientRegistration {
		return true
	}
	return DefaultRuntimeFlag
}
