package setup

import (
	"context"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/feature"
	"github.com/zitadel/zitadel/internal/repository/feature/feature_v2"
)

// SeedDCRRuntimeFeatureFlag emits one
// `feature.v2.system.dynamic_client_registration.set` event with
// value=true at the system aggregate level on first boot of v5.0.0-dcr.6
// (or any later release that ships this step). Idempotent — the
// migration framework guarantees String() runs at most once.
//
// Background: Phase 1/2 added the DynamicClientRegistration feature key
// to internal/feature/feature.go but never the proto/projection wire-up
// to set it. Operators upgrading through dcr.5 (which used a permissive
// default) had DCR running on the yaml gate alone. cavekit-feature-flag-
// dcr-runtime.md R9 flips the runtime gate back to strict (the per-
// instance flag is authoritative again), which would silently disable
// DCR for everyone who's relied on the dcr.5 permissive default. R10
// path (a) auto-seed addresses that: every existing instance inherits
// system-level dynamic_client_registration=true via the
// json_object_agg(coalesce(i.value, s.value)) cascade in
// internal/query/instance_by_id.sql, so DCR keeps working without any
// operator intervention. Instances that explicitly want DCR off can
// override per-instance via the new console toggle (R8).
type SeedDCRRuntimeFeatureFlag struct {
	eventstore *eventstore.Eventstore
}

func (mig *SeedDCRRuntimeFeatureFlag) Execute(ctx context.Context, _ eventstore.Event) error {
	aggregate := feature_v2.NewAggregate("SYSTEM", "SYSTEM")
	enabled := true
	event := feature_v2.NewSetEvent[bool](
		ctx,
		aggregate,
		feature_v2.SystemDynamicClientRegistration,
		enabled,
	)
	_ = feature.KeyDynamicClientRegistration // import-pin to surface a build break if the key is renamed
	_, err := mig.eventstore.Push(ctx, event)
	return err
}

func (mig *SeedDCRRuntimeFeatureFlag) String() string {
	return "72_seed_dcr_runtime_feature_flag"
}
