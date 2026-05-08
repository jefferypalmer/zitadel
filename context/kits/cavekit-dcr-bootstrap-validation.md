---
created: "2026-05-08T00:00:00Z"
last_edited: "2026-05-08T00:00:00Z"
---

# Cavekit — DCR Bootstrap Validation + Discovered Hotfix Patterns

## Description

Captures the patterns + remaining gaps surfaced by the v5.0.0-dcr.4..dcr.8
hotfix sequence that fixed real-deployment bugs after the Phase 3 build
loop closed. Each requirement has either:

- **DONE** — already shipped as a hotfix; this kit codifies the
  invariant so a future regression triggers a kit-level audit instead of
  silently re-introducing the bug.
- **PENDING** — the build loop hasn't addressed it yet; the next
  `/ck:make` cycle should pick these up.

The driving incident: Alexander upgraded from `v5.0.0-base` through
`dcr.3..dcr.8`, hit five distinct bugs that each blocked the next step
of his integration. Every one had a kit-level cause that the original
build's acceptance criteria didn't catch.

## Requirements

### R1: Phase-1/2 column additions ship a numbered ALTER-TABLE setup step

**Status:** DONE — `cmd/setup/71.{go,sql}` (v5.0.0-dcr.4 hotfix).

**Description:** Phase 1/2 added four columns to `apps7_oidc_configs`
(`registration_access_token_hash`, `registration_access_token_expires_at`,
`dcr_meta`, `jwks_inline`) via the projection's `Init()` declaration in
`internal/query/projection/app.go`. Init only fires for FRESH databases —
upgrading databases never get the columns. Symptom: `/oauth/v2/authorize`
on an upgraded instance returns
`ERROR: column c.jwks_inline does not exist (SQLSTATE 42703)`.

**Doctrine for future kits:** any column added to a projection's `Init()`
on a v-suffixed table that already exists in production MUST also ship as
a numbered `cmd/setup/NN.sql` migration with `ALTER TABLE … ADD COLUMN
IF NOT EXISTS …`. Idempotent re-apply on fresh DBs (where `Init()` already
created the column) is required. Without the migration, the upgrade-path
test passes (column present from `Init()`) but the actual
upgrade-from-existing-data path fails.

**Acceptance Criteria:**
- [x] `cmd/setup/71.sql` runs four `ALTER TABLE IF EXISTS …
      ADD COLUMN IF NOT EXISTS …` statements covering all four DCR
      columns. Idempotent via `IF NOT EXISTS`.
- [x] Step registered in `cmd/setup/setup.go`'s migration slice +
      `cmd/setup/config.go`'s Steps struct.
- [x] Embedded-Postgres smoke test verifies the migration applies
      cleanly to a v5.0.0-base-shape DB and is a no-op on second apply.
- [ ] **Future kits:** when adding columns to existing projection tables,
      every PR MUST include both the projection-side `Init()` change AND
      a numbered setup step. CI gate: a static check that flags new
      columns in `Init()` table-suffix declarations without a matching
      ALTER step in the same commit range.

### R2: DCR router's empty-path-after-StripPrefix problem

**Status:** DONE — `internal/api/oidc/dcr/wire.go` path-normalization
wrapper (v5.0.0-dcr.8 hotfix).

**Description:** `apis.RegisterHandlerOnPrefix("/oidc/v1/register", h)`
calls `http.StripPrefix(...)`, which produces an empty path string when
the request URL had no trailing slash. Gorilla mux treats
`r.HandleFunc("", …)` and `r.HandleFunc("/", …)` as the same canonical
pattern and matches NEITHER an actually-empty path. The parent mux falls
through to the catch-all login handler at `/`, which 301-redirects to
`/`. POST bodies are corrupted by the redirect in HTTP clients without
`-L` (and most downgrade to GET on 301 from POST per RFC 9110). MCP
clients that POST without trailing slashes silently fail.

**Doctrine for future kits:** any HTTP handler mounted via
`apis.RegisterHandlerOnPrefix` whose internal router uses gorilla mux
and registers routes on `/` MUST wrap the handler with a path-
normalization shim that rewrites `req.URL.Path = "/"` when it sees the
empty string. The dcr.6 attempt to register both `""` and `/` was a
no-op because gorilla normalizes them to the same pattern internally.

**Acceptance Criteria:**
- [x] `dcr.NewHandler` wraps the inner gorilla router in a HandlerFunc
      that rewrites `req.URL.Path = "/"` when it's empty, before
      `r.ServeHTTP`.
- [x] `internal/api/oidc/dcr/no_slash_register_test.go::TestStripPrefixEmptyPath_NormalizationFix`
      pins the invariant by rebuilding the StripPrefix + normalize +
      gorilla pipeline minimally and asserting both slash forms reach
      the inner handler.
- [ ] **Future kits:** any new mount-via-`RegisterHandlerOnPrefix`
      handler with internal gorilla routing MUST include a similar
      no-slash regression test, OR mount via a different registration
      pattern that doesn't strip the prefix (e.g. exact `Path` match in
      the parent router).

### R3: AS metadata mounts independently of OIDC server middleware chain

**Status:** DONE — `internal/api/oidc/server.go::AsMetadata` +
`registrationEndpointURL` source issuer from
`http_utils.DomainContext(ctx).Origin()` instead of
`op.IssuerFromContext(ctx)` (v5.0.0-dcr.7 hotfix).

**Description:** `op.IssuerFromContext(ctx)` reads a context value
populated only by `op.NewIssuerInterceptor`, which runs inside the
OIDC server's middleware chain. The OIDC discovery doc at
`/.well-known/openid-configuration` is mounted via
`apis.RegisterHandlerPrefixes(oidcServer, oidcPrefixes...)` and goes
through that chain. The RFC 8414 AS metadata handler at
`/.well-known/oauth-authorization-server` mounts independently via
`apis.RegisterHandlerOnPrefix(as_metadata.HandlerPath, asMetaWrapped)`
— no `op.NewIssuerInterceptor` wrap. Result: AS metadata's
`op.IssuerFromContext(ctx)` returns "", every endpoint URL becomes a
relative path (`/oauth/v2/authorize`), and `registration_endpoint`
never appears. MCP clients that probe AS metadata fail.

**Doctrine for future kits:** when multiple endpoints share an
issuer-derived URL builder (discovery, AS metadata, DCR
registration_endpoint, etc.) the issuer source MUST be
middleware-chain-independent. `http_utils.DomainContext(ctx).Origin()`
is populated by zitadel's global `WithOrigin` middleware (mounted on the
root router at `cmd/start/start.go:458-462`) and is the correct shared
source. `op.IssuerFromContext(ctx)` is OIDC-server-mux-specific and
MUST NOT be relied on outside that chain.

**Acceptance Criteria:**
- [x] `Server.AsMetadata` and `Server.registrationEndpointURL` source
      issuer from `ContextToIssuer(ctx)` (which reads
      `http_utils.DomainContext(ctx).Origin()`).
- [x] Falls back to `op.IssuerFromContext(ctx)` when DomainContext is
      empty so test fixtures using `op.ContextWithIssuer` still work.
- [x] `TestDiscoveryAndAsMetadata_R3_SharedFieldsByteIdentical` passes
      with both ctx-population paths.
- [ ] **Future kits:** any new well-known endpoint or issuer-derived URL
      builder MUST source the issuer from `ContextToIssuer` first; the
      `op.IssuerFromContext` fallback is a test-only seam.

### R4: Anonymous DCR validates DefaultProjectID + DefaultOrgID exist at boot

**Status:** PENDING — design only; no commit yet.

**Description:** `RegistrationDeps.Validate()` checks that
`DefaultProjectID` is non-empty when `RequireInitialAccessToken=false`,
but does NOT check that the project actually exists in
`projections.projects4`. An operator who sets a stale or typo'd
`ZITADEL_OIDC_DCR_DEFAULTPROJECTID` gets:

1. The DCR registration succeeds — command emits
   `ApplicationAddedEvent` with the dangling `project_id`.
2. The projection writes the row to `apps7` with the dangling FK.
3. The registration response includes a `client_id`.
4. The next request to `/oauth/v2/authorize?client_id=…` JOINs through
   `apps7 → apps7_oidc_configs → projects4 → orgs1` and the projects4
   join drops the row → `400 invalid_request: Errors.App.NotFound`.
5. The console's "Owned Projects" view also doesn't show the project
   (it doesn't exist), so the user can't navigate to it to debug.

Same risk for `DefaultOrgID` (the `orgs1` join would drop the row).

Alexander hit this exact failure mode on v5.0.0-dcr.7 — registrations
returned 201 for hours before the `/authorize` request finally
exposed the dangling FK.

**Acceptance Criteria:**
- [ ] `cmd/start/start.go` (or `RegistrationDeps.Validate` if it's given
      a Queries handle) queries `projections.projects4` for
      `DefaultProjectID` at boot when
      `RequireInitialAccessToken=false`. Refuses to start with a clear
      error message when the row is absent: e.g.
      `dcr: OIDC.DCR.DefaultProjectID="316834300718743550" does not
      exist in projections.projects4 — anonymous DCR mode requires a
      real project ID. Create the project first or set a different ID.`
- [ ] Same check for `DefaultOrgID` against `projections.orgs1`.
- [ ] Boot validation also confirms `project.resource_owner ==
      DefaultOrgID` so the anonymous-mode app→project→org chain is
      consistent. Mismatch is a fatal config error.
- [ ] Boot validation also confirms project state and org state are
      both ACTIVE (1). A deactivated project/org passed as default is
      a fatal config error.
- [ ] Integration test: start zitadel with a phantom DefaultProjectID;
      assert startup fails with the expected error class. Start with a
      real project; assert startup succeeds.

**Dependencies:** none (foundational — should be the first thing checked
at boot when DCR is enabled and anonymous mode is on).

### R5: DCR registration command rejects requests when the projected default project/org is missing

**Status:** PENDING — design only; defense-in-depth on top of R4.

**Description:** Even with R4's boot-time check, race conditions are
possible: an operator deletes the default project mid-run (before R4
re-checks). The DCR registration command's
`commands.RegisterClient` should re-validate the resolved
project/org existence as part of its preconditions, returning
`ClampError{Status: 503, Code: "default_project_not_found"}` instead of
silently emitting an `ApplicationAddedEvent` with a dangling FK.

**Acceptance Criteria:**
- [ ] `commands.RegisterClient` queries the project + org at the start
      of the command (same query the R4 boot check uses, factored into a
      shared helper). On miss, emits NO events and returns the new
      ClampError code.
- [ ] Dispatcher maps the new code to a 503 Service Unavailable with the
      RFC 7591 error envelope `{"error":"server_error",
      "error_description":"default project not configured"}`.
- [ ] Unit test pins the no-events-emitted invariant via the events-
      slice capture pattern used in `dcr_audit_payload_test.go`.

**Dependencies:** R4 (the boot check is the primary line of defense;
this is the in-request fallback).

### R6: dcr_meta JSONB column populated only on non-empty pass-through metadata

**Status:** DONE (informational — not a bug, kit-level
documentation only).

**Description:** `reduceApplicationDynamicallyRegistered` in
`internal/query/projection/app.go:840` writes the `dcr_meta` JSONB
column only when `e.DCRMeta` is non-empty. Minimal smoke
registrations that send only the required fields (`client_name`,
`redirect_uris`, `token_endpoint_auth_method`, `grant_types`,
`response_types`, `application_type`) leave `dcr_meta` NULL.
`IsDynamicallyRegistered` is computed from
`registration_access_token_hash IS NOT NULL`, NOT from
`dcr_meta IS NOT NULL` — so a registration with empty `dcr_meta` still
shows up as DCR-registered in the management gRPC + console.

**Doctrine for future kits:** when debugging "DCR app not showing as
dynamically-registered", `dcr_meta` is a red herring — check
`registration_access_token_hash` instead.

**Acceptance Criteria:**
- [x] Doc-only — captures the projection's split-write semantics so
      future debugging sessions don't chase the wrong column.

### R7: Operator deletion paths for DCR-registered apps

**Status:** DONE (informational — covered by existing kits).

**Description:** Three supported paths to delete a DCR-registered app:

1. **RFC 7592 DELETE** — `DELETE /oidc/v1/register/{client_id}` with the
   `registration_access_token` Bearer. Cleanest. Requires saved RAT.
   Covered by `cavekit-manage-handler.md` R6.
2. **Management gRPC `DeleteApp`** — `DELETE /management/v1/projects/
   {project_id}/apps/{app_id}` with admin Bearer. No RAT needed.
   Covered by existing `application.proto`.
3. **Console UI** — Project → Apps → app row → Delete button.

A fourth dirty path exists for dev (direct SQL `DELETE FROM
projections.apps7` + `apps7_oidc_configs`) but bypasses event sourcing
and re-emerges on projection rebuild. NOT a supported path.

**Acceptance Criteria:**
- [x] Doc-only — captures the supported deletion paths.

## Out of Scope

- **Reactive cleanup of dangling apps when a default project is
  deleted.** The R4/R5 boot + per-request validation prevents new
  dangling rows; cleaning up legacy orphans is a separate
  data-migration concern.
- **Per-org anonymous DCR defaults.** Currently single-instance via
  `OIDC.DCR.DefaultProjectID`. Per-org defaults are a `cavekit-org-dcr-
  policy.md` extension.
- **Software-statement-driven project/org resolution.** When
  `software_statement.aud` carries an explicit project/org, that path
  could short-circuit the DefaultProjectID lookup. Future enhancement.

## Cross-References

- `cavekit-config.md` R3 — dual-gate (yaml + runtime feature flag) that
  R4 sits BEFORE in the boot sequence.
- `cavekit-feature-flag-dcr-runtime.md` — the proto/projection wire-up
  for the runtime gate; R4 here complements it by adding default-data
  validation.
- `cavekit-register-handler.md` R3, R6 — anonymous-mode resolution +
  RegisterClient command path; R5 here adds defense-in-depth on top.
- `cavekit-software-statement.md` R14 — production-wiring kit;
  same shape ("Phase-1/2 declared the surface, never wired the bootstrap
  validation") gap.
- `cavekit-discovery-and-as-metadata.md` R2/R3 — well-known endpoints
  that R3 here pins the issuer-resolution invariant for.

## Source Traceability (brownfield)

The exact callsites referenced by each requirement, anchored at the
v5.0.0-dcr.8 release (commit `4e3ae2289`).

**R1 — DCR column migrations:**
- `cmd/setup/70.{go,sql}` — dcr_software_statement_jtis1 table (Phase 3).
- `cmd/setup/71.{go,sql}` — DCR column backfill (post-Phase-3 hotfix).
- `cmd/setup/72.go` — DCR runtime feature flag system seed (dcr.6).
- `internal/query/projection/app.go:140-154` — `Init()` declaration of
  the four DCR columns (Phase 1/2).

**R2 — DCR slash bug:**
- `internal/api/oidc/dcr/wire.go:382-407` — `NewHandler` with the
  path-normalization wrapper.
- `internal/api/oidc/dcr/no_slash_register_test.go` — regression test.
- `internal/api/api.go:249-253` — `RegisterHandlerOnPrefix`'s
  `http.StripPrefix` interaction.

**R3 — AS metadata issuer resolution:**
- `internal/api/oidc/server.go:202-220` —
  `registrationEndpointURL` reads ContextToIssuer first, falls back to
  `op.IssuerFromContext`.
- `internal/api/oidc/server.go:230-265` — `AsMetadata` same pattern.
- `internal/api/oidc/op.go:336-338` — `ContextToIssuer` returns
  `http_utils.DomainContext(ctx).Origin()`.
- `cmd/start/start.go:458-462` — global `WithOrigin` middleware that
  populates the DomainContext on every request.

**R4 — DefaultProjectID boot validation (PENDING):**
- `cmd/start/start.go:721-870` — `dcrDeps := dcr.RegistrationDeps{...}`
  construction; the boot validation hook lands BEFORE the
  `dcrDeps.Validate()` call at line 882.
- `internal/api/oidc/dcr/wire.go:321-355` —
  `RegistrationDeps.Validate()` currently checks non-empty only;
  extend to existence query.
- `internal/query/project.go` — `Queries.ProjectByID`-style helper for
  the existence check (or factor a new `ProjectExistsByID(ctx, id) bool`
  helper to avoid loading the full row).
- `internal/query/org.go` — same for the org existence check.

**R5 — RegisterClient command-side validation (PENDING):**
- `internal/command/dynamic_client_registration.go:165-235` —
  `RegisterClient` command body. Insert the project/org existence
  re-validation before the event push at line 187.
- `internal/api/oidc/dcr/errors.go:46-51` — add
  `ErrCodeDefaultProjectNotFound` constant alongside
  `ErrCodeServerError`.

**R6 — dcr_meta projection write split:**
- `internal/query/projection/app.go:840-863` —
  `reduceApplicationDynamicallyRegistered` (writes dcr_meta only when
  non-empty).
- `internal/query/projection/app.go:874-895` —
  `reduceApplicationRegistrationAccessTokenSet` (writes
  registration_access_token_hash always).
- `internal/query/app.go:1231` — `IsDynamicallyRegistered:
  c.registrationAccessTokenHash.Valid` — the canonical "is this app
  DCR-registered" check.

**R7 — App deletion paths:**
- `cavekit-manage-handler.md` R6 — RFC 7592 DELETE.
- `proto/zitadel/management.proto::DeleteApp` — gRPC.
- `console/src/app/pages/projects/owned-projects/owned-project-detail/...`
  — UI.

## Changelog

- 2026-05-08: Created. Captures the post-Phase-3 hotfix sequence
  (dcr.4..dcr.8) as kit-level invariants. R1, R2, R3 mark patterns
  shipped as hotfixes so future regressions trigger a kit-level audit
  rather than silently re-introducing the bug. R4 + R5 are the next
  cycle's work — DefaultProjectID/OrgID existence validation at boot +
  in-request defense-in-depth — surfaced by Alexander hitting the
  dangling-FK failure mode on dcr.7. R6 + R7 are doctrine-only,
  capturing semantics that previously cost debugging time.
