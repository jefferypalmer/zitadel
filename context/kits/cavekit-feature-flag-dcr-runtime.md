---
created: "2026-05-06T00:00:00Z"
last_edited: "2026-05-06T00:00:00Z"
---

# Cavekit — DCR Runtime Feature Flag End-to-End Wire-Up

## Description

Phase 1/2 added `feature.KeyDynamicClientRegistration` (Key=17 in `internal/feature/feature.go`) and three runtime read sites that gate DCR behind a per-instance feature flag — `internal/api/oidc/dcr/handler.go::featureGateMiddleware` (HTTP `/oidc/v1/register`), `internal/api/oidc/server.go::dcrAdvertised` (discovery + RFC 8414 AS metadata advertisement), and `internal/api/grpc/admin/iat.go::iatDualGate` (admin IAT RPCs). The kit's intent (`cavekit-config.md` R3) was a defense-in-depth dual-gate: yaml `OIDC.DCR.Enabled` PLUS per-instance runtime flag, both must be on.

But the wiring chain that lets an operator FLIP the per-instance flag was never built. The proto field is missing on `Set{Instance,System}FeaturesRequest` and `Get{Instance,System}FeaturesResponse`. The proto→command converter doesn't carry it. `InstanceFeaturesWriteModel` / `SystemFeaturesWriteModel` have no field for it. There is no event type registered in `feature_v2/feature.go`, no reducer in `internal/query/projection/instance_features.go`, no read-model field in `internal/query/instance_features_model.go`, and no toggle row in `console/src/app/components/features/features.component.{ts,html}`.

The result: `authz.GetFeatures(ctx).DynamicClientRegistration` always reads the zero-value `false`. The runtime gate is permanently closed regardless of operator intent. v5.0.0-dcr.5 shipped a hotfix (`internal/api/oidc/dcr/runtime_feature.go::DefaultRuntimeFlag = true`) that makes the runtime gate permissive-by-default so the yaml gate alone gatekeeps DCR. The dual-gate semantics are vestigial until this kit lands.

This kit completes the wire-up using `enableRelationalTables` as the model (it is the most recently-added end-to-end-wired feature flag, so its file footprint defines the canonical pattern). Once the wire-up lands, the dcr.5 hotfix is reverted: `DefaultRuntimeFlag` flips back to `false` and the dual-gate's strict semantics are restored.

## Requirements

### R1: Proto field on Set/Get Instance + System Features

**Description:** Add `dynamic_client_registration` to the four feature-service proto messages so clients can set and read the flag per-instance and per-system. Mirror the shape of `enable_relational_tables` byte-for-byte (`optional bool` on the request, `FeatureFlag` on the response, with the standard `(google.api.field_behavior) = OPTIONAL` + `(buf.validate.field).cel` annotations).

**Acceptance Criteria:**
- [ ] `proto/zitadel/feature/v2/instance.proto`: `SetInstanceFeaturesRequest` gains `optional bool dynamic_client_registration = <next-free-field-number>` with the same `(google.api.field_behavior)` and description annotations as `enable_relational_tables`.
- [ ] `proto/zitadel/feature/v2/instance.proto`: `GetInstanceFeaturesResponse` gains `FeatureFlag dynamic_client_registration = <next-free-field-number>` with the same annotation shape.
- [ ] `proto/zitadel/feature/v2/system.proto`: `SetSystemFeaturesRequest` and `GetSystemFeaturesResponse` gain the symmetric pair.
- [ ] Field numbers do NOT collide with any existing field — pick the next free integer in each message (look at `enable_relational_tables` field-number neighborhood as the precedent).
- [ ] Descriptions in the proto comments cite `cavekit-config.md` R3 dual-gate semantics + reference `cavekit-feature-flag-dcr-runtime.md`.
- [ ] `buf lint proto/zitadel/feature/v2/...` passes.

**Dependencies:** none (foundational).

### R2: Regenerated proto stubs

**Description:** Run the codegen so the new field surfaces in `pkg/grpc/feature/v2/...` and the connect-go stubs.

**Acceptance Criteria:**
- [ ] `pnpm exec buf generate ../proto --include-imports --include-wkt` (the existing `nx run @zitadel/api:generate-stubs` target) regenerates `pkg/grpc/feature/v2/instance.pb.go` and `system.pb.go` with the new `DynamicClientRegistration` field on both request and response types.
- [ ] `@zitadel/proto/zitadel/feature/v2/instance_pb` (consumed by the console) regenerates with the matching field on `SetInstanceFeaturesRequestSchema` and `GetInstanceFeaturesResponse`.
- [ ] `git diff` post-codegen contains only generated-file changes; hand-written code remains untouched.
- [ ] `go build ./...` clean (the new field is unused at this point but the stubs must compile).

**Dependencies:** R1.

### R3: Proto ↔ command-model converter

**Description:** Extend `internal/api/grpc/feature/v2/converter.go` so the new proto field flows into the command-layer write model on `Set*Features` and back out on `Get*Features`. Mirror the `EnableRelationalTables` pattern verbatim — same line shape, same nil-handling.

**Acceptance Criteria:**
- [ ] `instanceFeaturesToCommand` (currently `internal/api/grpc/feature/v2/converter.go:27`) gains `DynamicClientRegistration: req.DynamicClientRegistration` immediately after the `EnableRelationalTables` line.
- [ ] `instanceFeaturesToPb` (line 48) gains `DynamicClientRegistration: featureSourceToFlagPb(&f.DynamicClientRegistration)`.
- [ ] `systemFeaturesToCommand` (line 66) and `systemFeaturesToPb` (line 89) gain the symmetric pair.
- [ ] `internal/api/grpc/feature/v2/converter_test.go` extends the existing `TestInstanceFeaturesToCommand` / `TestSystemFeaturesToCommand` table-driven tests to cover the new field — every case the EnableRelationalTables row covers, the new field covers too.

**Dependencies:** R2.

### R4: Command-layer write model

**Description:** Add the `*bool` field to `InstanceFeaturesWriteModel` and `SystemFeaturesWriteModel`, extend the `IsZero` check, the event-type filter list, the `Reduce` switch, and the command-emit-on-change list. Mirror EnableRelationalTables.

**Acceptance Criteria:**
- [ ] `internal/command/instance_features.go` `InstanceFeatures` struct gains `DynamicClientRegistration *bool` after `EnableRelationalTables`.
- [ ] `internal/command/instance_features.go` `IsZero` (line 28) extends the chained-AND to include `m.DynamicClientRegistration == nil`.
- [ ] `internal/command/instance_features_model.go` event-filter list (line ~77) gains `feature_v2.InstanceDynamicClientRegistration` after `feature_v2.InstanceEnableRelationalTables`.
- [ ] `internal/command/instance_features_model.go` `Reduce` switch (line ~113) gains `case feature.KeyDynamicClientRegistration:` that decodes the bool payload and assigns to `features.DynamicClientRegistration`.
- [ ] `internal/command/instance_features_model.go` `commands` builder (line ~130) gains `cmds = appendFeatureUpdate(...wm.DynamicClientRegistration, f.DynamicClientRegistration, feature_v2.InstanceDynamicClientRegistration)` immediately after the EnableRelationalTables append.
- [ ] Symmetric edits to `internal/command/system_features.go` (struct + IsZero) and `internal/command/system_features_model.go` (filter list + reduce + commands).
- [ ] Existing unit tests in those files run cleanly.

**Dependencies:** R3.

### R5: Eventstore event types

**Description:** Register the two new event types — `feature.v2.system.dynamic_client_registration.set` and `feature.v2.instance.dynamic_client_registration.set` — by following the `EnableRelationalTables` pattern in `internal/repository/feature/feature_v2/feature.go` and `eventstore.go`.

**Acceptance Criteria:**
- [ ] `internal/repository/feature/feature_v2/feature.go` gains `SystemDynamicClientRegistration = setEventTypeFromFeature(feature.LevelSystem, feature.KeyDynamicClientRegistration)` after `SystemEnableRelationalTables` (currently line 21).
- [ ] Same file gains `InstanceDynamicClientRegistration = setEventTypeFromFeature(feature.LevelInstance, feature.KeyDynamicClientRegistration)` after `InstanceEnableRelationalTables` (currently line 32).
- [ ] `internal/repository/feature/feature_v2/eventstore.go` registers both via `eventstore.RegisterFilterEventMapper(AggregateType, ..., eventstore.GenericEventMapper[SetEvent[bool]])` — one in the system block (after line 16) and one in the instance block (after line 27).

**Dependencies:** R4 (the command write model references the event types).

### R6: Projection reducer

**Description:** Subscribe the instance-features projection to the new event so the in-memory feature struct reflects writes.

**Acceptance Criteria:**
- [ ] `internal/query/projection/instance_features.go` `Reducers()` (line ~53 — the function that lists every event the projection cares about) gains an entry `{Event: feature_v2.InstanceDynamicClientRegistration, Reduce: reduceInstanceSetFeature[bool]}` immediately after the `InstanceEnableRelationalTables` entry (line 100). System-level mirror lives in `internal/query/projection/system_features.go` if there's a separate system projection — otherwise the symmetric site.
- [ ] No new column needed — the JSONB feature-blob already accepts arbitrary key/value via the existing `reduceInstanceSetFeature` generic reducer.

**Dependencies:** R5.

### R7: Query read model

**Description:** Add the field to the `InstanceFeatures` / `SystemFeatures` query-side structs so callers (including `authz.GetFeatures(ctx).DynamicClientRegistration`) see the projected value.

**Acceptance Criteria:**
- [ ] `internal/query/instance_features.go` `InstanceFeatures` struct (line ~20) gains `DynamicClientRegistration FeatureSource[bool]` after `EnableRelationalTables`.
- [ ] `internal/query/system_features.go` `SystemFeatures` struct (line ~29) gains the symmetric field.
- [ ] `internal/query/instance_features_model.go` reset block (line ~79) gains `m.instance.DynamicClientRegistration = FeatureSource[bool]{}` after the EnableRelationalTables reset.
- [ ] `internal/query/instance_features_model.go` event filter (line ~73) and `Reduce` switch (line ~123) gain entries mirroring EnableRelationalTables.
- [ ] `internal/query/system_features_model.go` symmetric edits.
- [ ] `internal/feature/feature.go` `Features` struct already has `DynamicClientRegistration bool` (line 55) — no change needed; this R wires the path that populates it.

**Dependencies:** R6.

### R8: Console toggle + i18n

**Description:** Surface the toggle in the console's Instance Settings → Features page so an admin can flip it without writing a curl. Add i18n labels for all 22 locales (or at minimum en + de — the rest can be filled by a follow-up `pnpm translate-i18n` run since R5 of `cavekit-i18n-pipeline.md` requires it).

**Acceptance Criteria:**
- [ ] `console/src/app/components/features/features.component.ts` `FEATURE_KEYS` array (line ~30) gains `'dynamicClientRegistration'` — must match the proto field's camelCase name exactly so the auto-generated `Set{Instance,System}FeaturesRequestSchema` field is reachable.
- [ ] `console/src/assets/i18n/en.json` gains under `SETTING.FEATURES`:
  - `DYNAMICCLIENTREGISTRATION: "Dynamic Client Registration"`
  - `DYNAMICCLIENTREGISTRATION_DESCRIPTION: "Allow OAuth/OIDC clients to register themselves at runtime via /oidc/v1/register (RFC 7591). The yaml gate (OIDC.DCR.Enabled) must also be on."`
- [ ] `console/src/assets/i18n/de.json` gains the German translations.
- [ ] The other 20 locales gain the keys (either via `pnpm translate-i18n` if API key is available, or via `console/scripts/_archive/dcr-i18n-fill-extended.mjs`-style hand-fill).
- [ ] Manual smoke: load Instance Settings → Features in the console; the new toggle appears in the list, flipping it round-trips through the gRPC call without errors, and `authz.GetFeatures` reads the new value on the next request.

**Dependencies:** R7 (the toggle's gRPC payload has to reach a code path that actually persists it).

### R9: Revert the v5.0.0-dcr.5 permissive default

**Description:** Once the wire-up is complete, the dcr.5 hotfix becomes harmful — it would mask a legitimate operator decision to leave the per-instance flag off. Flip `DefaultRuntimeFlag` back to `false` so the strict dual-gate semantics return.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/dcr/runtime_feature.go` `DefaultRuntimeFlag` flips from `true` to `false`. The package-var indirection STAYS for test-seam reasons; only the default value changes.
- [ ] The godoc on `DefaultRuntimeFlag` is rewritten to drop the "v5.0.0-dcr.5 hotfix" framing and instead document the strict semantics: "Default false; the per-instance feature flag is authoritative once the wire-up at `cavekit-feature-flag-dcr-runtime.md` is in place."
- [ ] `internal/api/oidc/dcr/runtime_feature_testmain_test.go` is deleted — TestMain forcing `DefaultRuntimeFlag = false` is redundant when production already defaults to false.
- [ ] `internal/api/oidc/dcr/runtime_feature_test.go` `TestRuntimeFeatureFlagEnabled` is rewritten so the "strict" arm uses the production default and the "permissive" arm explicitly flips the var on. The case matrix flips, but the test still pins both arms.
- [ ] The `prevDefault := dcr.DefaultRuntimeFlag; dcr.DefaultRuntimeFlag = false; t.Cleanup(...)` overrides in the five tests that flipped the var (`TestServer_registrationEndpointURL`, `TestDiscoveryConfig_RegistrationEndpoint_NeverNullInJSON`, `TestDiscoveryAndAsMetadata_R3_BothOmitRegistrationWhenDisabled`, `TestDcrAdvertised_DualGateMatrix`, `TestIAT_RuntimeFeatureGate`) are removed — those tests now match production behavior without local override.
- [ ] An integration test exists that flips the per-instance flag via `SetInstanceFeatures` and asserts a subsequent `POST /oidc/v1/register` is gated correctly (off → 403, on → 201). This is the load-bearing assertion that the wire-up actually closed the loop.

**Dependencies:** R1..R8 — flipping the default before the wire-up exists would re-break DCR for every operator.

### R10: Migration + backwards-compat

**Description:** Existing instances upgrading from a dcr.5-deployed version must not silently get DCR turned off when dcr.6 lands. Two paths: (a) seed a system-level event setting `dynamic_client_registration = true` on existing instances during the dcr.6 migration, OR (b) document the upgrade procedure explicitly so operators flip the per-instance flag during the dcr.6 rollout window. Path (a) is preferred because it's invisible to operators; path (b) is acceptable when the operator universe is small.

**Acceptance Criteria:**
- [ ] Decision recorded in this kit's Changelog: chose (a) auto-seed OR (b) document — with rationale.
- [ ] If (a): a new numbered setup step (`cmd/setup/72.go` or next free) emits a `feature.v2.system.dynamic_client_registration.set` event with `value=true` on first boot of dcr.6, idempotent (skips if any prior set/reset event exists for the key). The seed targets the system level so it cascades to every instance unless an instance has its own override.
- [ ] If (b): release notes for v5.0.0-dcr.6 include a numbered upgrade-step list ("Before pulling dcr.6: SetSystemFeatures with `dynamic_client_registration: true`. After pulling dcr.6, anonymous DCR continues to work; operators who want per-instance disable can now flip the toggle in the console.").
- [ ] Documentation lives at `context/impl/impl-feature-flag-dcr-runtime.md` with the decision rationale + concrete steps.

**Dependencies:** R9 (the migration only matters if the strict default is restored).

## Out of Scope

- **Bulk migration of every Phase-1/2 feature flag's wire-up.** Only `DynamicClientRegistration` is in scope; if other Phase-1/2 keys turn out to have the same gap (e.g., another `Key` was added without proto/projection wire-up), each gets its own kit.
- **Adding new feature semantics.** This kit reuses the existing dual-gate; no new "dcr.audit-only mode" / "dcr.read-only mode" / etc.
- **Org-level scoping.** The runtime flag is system-or-instance, mirroring every other entry in `FEATURE_KEYS`. Per-org DCR enable/disable is `cavekit-org-dcr-policy.md` territory.
- **Multi-region projection consistency.** When the toggle flips, the projected value reaches all replicas via the existing eventstore replication path — no new infrastructure needed.
- **CLI tool to flip the flag.** `zitadel ctl features set dynamic_client_registration=true`-style — out of scope; the gRPC RPC + console toggle are the supported interfaces.

## Cross-References

- `cavekit-config.md` R3 — the original dual-gate design statement that this kit makes load-bearing for the first time.
- `cavekit-feature-flags.md` (if it exists; otherwise `internal/feature/feature.go` doc) — the canonical "how to add a feature flag" doctrine. This kit IS that doctrine applied to `DynamicClientRegistration`.
- `cavekit-i18n-pipeline.md` R5 — every EN-defined subtree must be filled in all 22 locales; the new `SETTING.FEATURES.DYNAMICCLIENTREGISTRATION*` keys are R5's responsibility once they land in en.json.
- `cavekit-software-statement.md` R14 — the production-wiring kit for the verifier pipeline; same shape of "Phase-1/2 declared the surface but never wired it" gap.
- `cavekit-manage-handler.md` R9 — the dcr-shape recover middleware; this kit doesn't touch it but the runtime gate's panic-on-misconfig path lives behind that wrapper.

## Source Traceability (brownfield)

The exact callsites the implementation will touch, captured at `cd21bc6ed..1439a4842` (v5.0.0-base..v5.0.0-dcr.5).

**Backend reads (gate sites — already routed through `RuntimeFeatureFlagEnabled` after dcr.5):**
- `internal/api/oidc/dcr/handler.go:120` — HTTP register gate.
- `internal/api/oidc/server.go:194` — discovery + AS-metadata advertisement gate.
- `internal/api/grpc/admin/iat.go:53` — admin IAT RPC gate.

**Backend feature-key declaration:**
- `internal/feature/feature.go:28` — `KeyDynamicClientRegistration Key = 17`.
- `internal/feature/feature.go:55` — `DynamicClientRegistration bool` on the in-memory `Features` struct.
- `internal/feature/key_enumer.go:64,67,90,91` — auto-generated; will need `go generate` if the enumer source changes.

**Backend wire-up scaffolding (mirror `EnableRelationalTables` line-for-line):**
- `internal/api/grpc/feature/v2/converter.go:27,48,66,89` — proto↔model converters.
- `internal/command/instance_features.go:24,37` — write model struct + IsZero.
- `internal/command/instance_features_model.go:77,113,115,130` — event filter + reduce + command emit.
- `internal/command/system_features.go:19,30` + `system_features_model.go` — symmetric system-level.
- `internal/repository/feature/feature_v2/feature.go:21,32` — event-type constants.
- `internal/repository/feature/feature_v2/eventstore.go:16,27` — event-mapper registration.
- `internal/query/projection/instance_features.go:100` — projection reducer.
- `internal/query/instance_features.go:20` — read model field.
- `internal/query/instance_features_model.go:73,79,123,124` — event filter + reset + reduce.
- Symmetric `internal/query/system_features.go` + `system_features_model.go`.

**Frontend wire-up scaffolding:**
- `console/src/app/components/features/features.component.ts:30` — `FEATURE_KEYS` array.
- `console/src/app/components/features/features.component.html:24-30` — toggle template (no edit; the `@for` loop handles new keys automatically once the array entry lands).
- `console/src/assets/i18n/en.json` — `SETTING.FEATURES.ENABLERELATIONALTABLES` is the precedent at `'SETTING.FEATURES.DYNAMICCLIENTREGISTRATION*'`'s nesting.
- `console/src/assets/i18n/{ar,bg,...}.json` × 22 — i18n fan-out via `cavekit-i18n-pipeline.md`.

**Hotfix to remove (R9):**
- `internal/api/oidc/dcr/runtime_feature.go` — flip `DefaultRuntimeFlag` to `false`, rewrite godoc.
- `internal/api/oidc/dcr/runtime_feature_testmain_test.go` — delete.
- `internal/api/oidc/dcr/runtime_feature_test.go` — rewrite assertions to match new default.
- 5 tests with local `DefaultRuntimeFlag = false` overrides in `internal/api/oidc/dcr_discovery_test.go` and `internal/api/grpc/admin/iat_test.go` — delete the override blocks.

## Changelog

- 2026-05-06: Created — v5.0.0-dcr.5 hotfix exposed the gap (`internal/api/oidc/dcr/runtime_feature.go` `DefaultRuntimeFlag = true` is a band-aid). Initial draft adds R1..R10 covering proto, codegen, converter, command, eventstore, projection, query, console, and the hotfix-revert. R10 leaves the migration choice (auto-seed vs operator-documented) open pending operator-universe size.
