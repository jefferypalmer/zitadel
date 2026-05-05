---
created: "2026-05-05T00:00:00Z"
last_edited: "2026-05-05T18:00:00Z"
complexity: medium
---

# Cavekit: Eventstore Framework Guard (NewHandler degenerate-construction refusal)

## Scope
Defines a construction-time guard in `internal/eventstore/handler/v2/handler.go::NewHandler` that refuses to construct a `*Handler` when the supplied `Projection` would produce a degenerate prefill loop: empty `eventTypes` map (derived from `projection.Reducers()` returning nil or empty slice), no `TriggerWithoutEvents` callback configured, and the projection does NOT implement `GlobalProjection`. In any other combination — non-empty Reducers OR `TriggerWithoutEvents != nil` OR projection implements `GlobalProjection` — construction proceeds unchanged. Out of scope: any other framework-defensive guards (rate limits, advisory-lock contention reporting, projection-ordering checks, etc.). Each future framework guard gets its own R or its own kit.

## Source
- Audit finding (BLOCKER): `internal/query/projection/dcr_software_statement_jtis.go` (now deleted by Phase 3 Step 1) registered as a projection with `Reducers() returns nil`. Framework's `eventQuery` (handler.go:746-773) built a SearchQuery with empty `aggregateTypes`/`eventTypes` arrays. SQL-builder (`internal/eventstore/repository/search_query.go:281-289`) and in-memory matcher (`internal/eventstore/search_query.go:382`) both treat empty filter as "match every event." Result: `processEvents` scanned the entire eventstore for the instance, generating one `NewNoOpStatement` per event (`statement.go:69-82`), batched 1000 at a time per `bulkLimit`, advancing state but never reducing — a process killed mid-loop leaves a stuck `system.migration.started` event with no matching `done`, infinite-retry-loop on next start.
- FieldHandler precedent: `internal/eventstore/handler/v2/field_handler.go:43-58` constructs `Handler{}` inline (NOT via `NewHandler`) with empty Reducers and explicit `eventTypes` map passed in. The guard at `NewHandler` does not affect FieldHandler.
- Proper-pattern cross-reference: `cavekit-software-statement.md` R12 forbids this pattern in domain code (the rule that the GUARD enforces structurally).

## Requirements

### R1: Guard at `NewHandler` rejects degenerate constructions
**Description:** `NewHandler(ctx, config, projection)` (handler.go:158) MUST refuse to construct a `*Handler` when ALL THREE of the following are true after evaluating the supplied `Projection` and `Config`: (1) `len(aggregates) == 0` — i.e., `projection.Reducers()` returned nil or empty slice, so the framework has no event-type filter to apply. (2) `config.TriggerWithoutEvents == nil` — i.e., no scheduled-wakeup callback is provided as an alternative trigger source. (3) `projection` does NOT implement the `GlobalProjection` marker interface (which sets `queryGlobal = true` later at line 201-203 and explicitly opts the projection into a no-filter query). In that combination the handler would, on every Trigger / scheduled requeue / migration prefill, scan the entire eventstore (filtered by instance only) and produce one no-op statement per event. The guard fails loudly at construction time so the wrong-shape projection never reaches `migration.Migrate` or `Handler.Start`. The guard panics with an actionable message, NOT returns an error: `NewHandler` is currently a non-error-returning constructor (changing its signature would touch every projection registration site). A panic at construction surfaces as an immediate boot-time stack trace pointing at the misnamed projection — the existing setup pipeline would see the panic (no recover handler at boot) and exit with non-zero, which is the desired "refuse to start with a broken projection" behavior.

**Acceptance Criteria:**
- [ ] `internal/eventstore/handler/v2/handler.go::NewHandler` evaluates the three conditions above immediately after `aggregates` is built (around line 174, before any side-effecting setup) and `panic`s with a message of the form: `eventstore/handler/v2: projection %q has empty Reducers, no TriggerWithoutEvents, and does not implement GlobalProjection — refusing to construct because the prefill loop would scan the entire eventstore as no-op statements. Use a numbered setup step (cmd/setup/NN.go) for application-managed tables, a TriggerWithoutEvents callback for scheduled-wakeup projections, or a FieldHandler for field projections.` (substitute `%q` with `projection.Name()`).
- [ ] The guard runs BEFORE `metrics := NewProjectionMetrics(ctx)` and BEFORE the `handler := &Handler{…}` literal — failure mode is "panic before any side effect."
- [ ] `FieldHandler` (`field_handler.go:43-58`) is unaffected: it constructs `Handler{}` directly via struct literal, not via `NewHandler`. The guard cannot trip on the FieldHandler path. Verifiable by reading field_handler.go and confirming the constructor does not call `NewHandler`.
- [ ] Projections that implement `GlobalProjection` (e.g. system-features, instance-features per the existing codebase) pass the guard regardless of Reducers content because the third condition is false.
- [ ] Projections with `Reducers()` returning a non-empty slice pass because the first condition is false.
- [ ] Projections with empty Reducers but with `Config.TriggerWithoutEvents != nil` (a legitimate scheduled-wakeup pattern; presently unused in production but a documented framework knob) pass because the second condition is false.

**Dependencies:** None internal — this is a self-contained framework-layer change.

### R2: Test coverage for all four arms of the guard's truth table
**Description:** A unit test file `internal/eventstore/handler/v2/nil_reducers_guard_test.go` (or extension to existing `handler_test.go`) covers the four cases the guard distinguishes: one panicking case, three passing cases.

**Acceptance Criteria:**
- [ ] Case 1 (panic): `NewHandler` invoked with a stub `Projection` whose `Reducers()` returns `nil`, a `Config` with `TriggerWithoutEvents == nil`, and the projection does NOT implement `GlobalProjection` → test asserts a panic with the message substring `refusing to construct`.
- [ ] Case 2 (pass — non-empty Reducers): same projection but `Reducers()` returns a one-element `[]AggregateReducer` slice → no panic; constructed handler has non-empty `eventTypes`.
- [ ] Case 3 (pass — TriggerWithoutEvents set): empty Reducers but `Config.TriggerWithoutEvents` set to a non-nil `Reduce` function → no panic; constructed handler stores the callback.
- [ ] Case 4 (pass — GlobalProjection): empty Reducers, no `TriggerWithoutEvents`, but the projection implements `GlobalProjection` → no panic; constructed handler has `queryGlobal == true`.
- [ ] All four tests run as part of the existing `go test ./internal/eventstore/handler/v2/...` suite and pass.

**Dependencies:** R1.

### R3: Framework guard does not affect existing projections in the codebase
**Description:** After Step 1 of `cavekit-software-statement.md` R9/R12 deletes the only offending projection (`dcr_software_statement_jtis.go`), every projection currently registered in `internal/query/projection/projection.go::newProjectionsList()` (and equivalent registrations under `internal/admin/repository/eventsourcing/handler/`, `internal/auth/repository/eventsourcing/handler/`, `internal/notification/handlers/`) MUST satisfy at least one of the three pass conditions in R1. The guard is a back-stop, not a scope expander — it should never trip during normal startup of the v5.0.0-dcr.3 binary.

**Acceptance Criteria:**
- [ ] `cmd/setup` integration tests (or equivalent boot-smoke) start a fresh Zitadel instance against an empty Postgres and complete `setup` + `start` without the guard panicking.
- [ ] The same against an existing-data Postgres (upgrade simulation): boot completes without panic, and no log line containing `refusing to construct` is emitted.
- [ ] grep-scan (acceptance test): `grep -rn 'func.*Reducers().*\[\]handler.AggregateReducer' internal/admin/repository/eventsourcing/handler/ internal/auth/repository/eventsourcing/handler/ internal/notification/handlers/ internal/query/projection/ | xargs grep -l 'return nil$\|return \[\]handler.AggregateReducer{}$'` returns empty after Step 1 is applied. Any non-empty result is a regression — either an undeleted offender or a new projection that misuses the pattern.

**Dependencies:** `cavekit-software-statement.md` R9/R12 (deletes the only current offender — Phase 3 Step 1). R3's grep-scan is the cross-validation that Step 1 actually completed.

### R1.1: Guard fires on zero TOTAL event types, not zero aggregates (post-loop revision F-007)
**Description:** R1 currently fires when `len(aggregates) == 0`. A degenerate projection that returns `[]AggregateReducer{{Aggregate: "x", EventReducers: nil}}` produces `len(aggregates) == 1` with an empty inner `eventTypes` slice — the prefill loop is still effectively a no-op scan. The guard's invariant should be "no Reducer in the result has any EventReducers", a strict superset of "len(aggregates) == 0".

**Acceptance Criteria:**
- [ ] `NewHandler` computes `totalEventTypes := sum(len(reducer.EventReducers))` over `projection.Reducers()` and panics when `totalEventTypes == 0 && config.TriggerWithoutEvents == nil && !isGlobalProjection`. The existing `len(aggregates) == 0` check is replaced by this stricter invariant.
- [ ] Truth-table test (R2) gains a 5th case: `[]AggregateReducer{{Aggregate: "x", EventReducers: nil}}` + nil `TriggerWithoutEvents` + non-Global → asserts the same panic message containing `"refusing to construct"`.
- [ ] AST-walk tests (`internal/query/projection/no_empty_reducers_test.go` and `cmd/start/no_panic_smoke_test.go`) extend to recognize the degenerate-non-empty-Reducers shape — currently they only catch literal `return nil` and `return []handler.AggregateReducer{}` bodies.

**Dependencies:** R1 (the invariant being strengthened); R2 (the test that needs the 5th case).

## Out of Scope
- Any other framework-defensive guards (rate limits, lock-contention metrics, projection-ordering invariants, requeue-storm protection). Each gets its own R or its own kit.
- Re-architecting `NewHandler` to return an error instead of panic. Discussed in audit, rejected: would touch every projection registration site for a programmer-error case where the only recovery is "fix the code."
- Adding a parallel guard at `Handler.Start()` for the periodic-schedule path. Not needed because the guard at `NewHandler` runs at construction (before either `Migrate` or `Start` can invoke any path that would trigger the eventstore scan), and any reachable Handler will have passed the guard.
- Static-analysis lint rule (e.g. via `go vet` or a custom linter) that flags `Reducers() returns nil` at compile time. Considered, deferred — runtime guard is sufficient and tests catch the case in CI.

## Cross-References
- See `cavekit-software-statement.md` R9 + R12: the BLOCKER that motivated this kit; R12 enforces the same rule at the kit level for domain code.
- See `cavekit-iat.md` R8: the contrasting positive-pattern note (eventstore-derivable identities use UniqueConstraints, not separate dedup tables; if you need a dedup table see `cavekit-software-statement.md` R9 pattern).
- See `cavekit-overview.md`: this kit is added to the Domain Index and Cross-Reference Map (framework-defensive layer).

## Source Traceability (brownfield)
- `internal/eventstore/handler/v2/handler.go:158-205` — `NewHandler` constructor, current implementation builds `aggregates` from `Reducers()` without checking for the degenerate case. R1 inserts the guard immediately after line 174.
- `internal/eventstore/handler/v2/handler.go:646-651` — `generateStatements` `triggerWithoutEvents` short-circuit; documents the legitimate path-3 case the guard preserves.
- `internal/eventstore/handler/v2/handler.go:760-762` — `eventQuery` `queryGlobal` branch; documents the legitimate path-4 case the guard preserves.
- `internal/eventstore/handler/v2/field_handler.go:43-58` — FieldHandler constructs `Handler{}` directly; not affected by the NewHandler guard.
- `internal/eventstore/search_query.go:382` — empty filter == match-all in matches(); the SQL behavior the guard prevents from being silently exploited.
- `internal/eventstore/repository/search_query.go:281-289` — same behavior in SQL-side `aggregateTypeFilter` / `eventTypeFilter`.

## Changelog
- 2026-05-05: Created — v3 audit cleanup. Initial draft adds three Rs: R1 NewHandler guard, R2 truth-table tests, R3 framework-stays-clean back-stop.
- 2026-05-05 (post-loop revision): Added R1.1 strengthening the guard invariant from `len(aggregates) == 0` to `totalEventTypes == 0` so degenerate non-empty Reducers shapes are caught (F-007).
