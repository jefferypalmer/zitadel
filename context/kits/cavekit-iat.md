---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
complexity: complex
---

# Cavekit: Initial Access Token (IAT) Domain

## Scope
Defines the Initial Access Token domain — events scoped to the `project` aggregate, commands (Add / Consume / Revoke), the race-safe `max_uses` enforcement via per-use-slot eventstore `UniqueConstraint` with bounded 3-retry, the `initial_access_tokens` projection table, the query helpers, and the admin gRPC surface (`CreateInitialAccessToken` / `ListInitialAccessTokens` / `RevokeInitialAccessToken`). IATs gate the secondary "IAT-required" registration mode.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §2.5 (IAT events), §4.5 (gRPC), §5 (race-safe consume), §7.2 (projection table), §15.8 (3-retry decision), §17.5 (proto layout)
- Spec references: RFC 7591 §3 (IAT introduction); RFC 7592 §3 (related)

## Requirements

### R1: IAT events on the `project` aggregate
**Description:** Three new events are added under the `project` aggregate (NOT a new top-level aggregate). Wire-string + Go-type pairs are fixed by Zitadel convention.

**Acceptance Criteria:**
- [ ] `internal/repository/project/initial_access_token.go` defines `InitialAccessTokenAddedEvent` with wire-type string `project.initial_access_token.added`.
- [ ] Same file defines `InitialAccessTokenConsumedEvent` with wire-type `project.initial_access_token.consumed`.
- [ ] Same file defines `InitialAccessTokenRevokedEvent` with wire-type `project.initial_access_token.revoked`.
- [ ] Factory functions are named `NewInitialAccessTokenAddedEvent`, `NewInitialAccessTokenConsumedEvent`, `NewInitialAccessTokenRevokedEvent` (matches `NewOIDCConfigAddedEvent` naming).
- [ ] `InitialAccessTokenAddedEvent.Payload()` carries `{id, hash, max_uses, expires_at, project_id, allowed_grant_types, allowed_redirect_uri_patterns, description}`.
- [ ] `InitialAccessTokenConsumedEvent.Payload()` carries `{use_index}` and (for finite `max_uses`) declares a `UniqueConstraints()` entry of the form `iat_uses:<iat_id>:<use_index>` with error key `Errors.DCR.IAT.SlotAlreadyConsumed`.
- [ ] For `max_uses=0` (unlimited), `InitialAccessTokenConsumedEvent.UniqueConstraints()` returns no constraint (duplicate slot collisions are benign and unbounded use is allowed).
- [ ] `InitialAccessTokenRevokedEvent` requires no unique constraint.

**Dependencies:** `cavekit-config.md` R2 (feature flag gates gRPC surface).

### R2: Race-safe `max_uses` consume with 3-retry
**Description:** Each consumption of an IAT MUST be exactly-once for finite `max_uses`. Race safety is provided by the eventstore-level `UniqueConstraint` per `(iat_id, use_index)` pair (NOT by projection-level `SELECT FOR UPDATE`). On collision a consumer re-reads the projection and retries up to 3 times before failing.

**Acceptance Criteria:**
- [ ] Consume command re-fetches the IAT projection row on every retry (not just the first attempt) so revocation/expiry committed between retries is observed.
- [ ] If the IAT is revoked or expired at any retry read, the command fails before pushing an event.
- [ ] Slot-picker selects the next unreserved `use_index` from the freshly-read projection.
- [ ] On `zerrors.ThrowAlreadyExists` from the eventstore commit, the command retries (up to 3 total attempts).
- [ ] After the 3rd consecutive `ThrowAlreadyExists`, the command returns an error that the handler translates to HTTP 401 `invalid_token` with `error_description: "initial access token exhausted"`.
- [ ] For `max_uses=0`, no `UniqueConstraint` is declared and consume always succeeds (still emits a `consumed` event for audit).
- [ ] When the projection reports all `N` slots consumed, the consume command fails pre-push with the same 401 translation.
- [ ] `dcr_iat_concurrency_test.go` exercises three scenarios: (a) `max_uses=3` with 10 concurrent → exactly 3 succeed and 7 receive 401; (b) `max_uses=4` with 4 forced collisions → all 4 succeed via retries; (c) `max_uses=5` with 5 forced collisions → 4 succeed and 1 fails 401 "exhausted".
- [ ] `go test -race -count=1000 -run=TestIATConcurrency ./internal/command/` passes with zero flakes.

**Dependencies:** R1

### R3: `initial_access_tokens` projection
**Description:** A new SQL projection table tracks IAT lifecycle data for query lookups by ID and hash.

**Acceptance Criteria:**
- [ ] `internal/query/projection/initial_access_token.go` defines a projection registered in `internal/query/projection/projection.go`.
- [ ] The projected table schema contains exactly: `id TEXT PK`, `instance_id TEXT NOT NULL`, `resource_owner TEXT NOT NULL`, `project_id TEXT NOT NULL`, `token_hash TEXT NOT NULL`, `expires_at TIMESTAMPTZ NULL`, `max_uses INT NOT NULL`, `uses_consumed INT NOT NULL DEFAULT 0`, `consumed_slots INT[] NOT NULL DEFAULT '{}'`, `allowed_grant_types TEXT[] NULL`, `allowed_redirect_uri_patterns TEXT[] NULL`, `revoked BOOL NOT NULL DEFAULT FALSE`, `created_at TIMESTAMPTZ NOT NULL`, `change_date TIMESTAMPTZ NOT NULL`, `sequence BIGINT NOT NULL`.
- [ ] Indices `(instance_id, project_id)` and `(token_hash)` are present.
- [ ] Reducer for `InitialAccessTokenAddedEvent` INSERTs a row.
- [ ] Reducer for `InitialAccessTokenConsumedEvent` increments `uses_consumed` and appends to `consumed_slots`.
- [ ] Reducer for `InitialAccessTokenRevokedEvent` sets `revoked = TRUE`.

**Dependencies:** R1

### R4: Query helpers
**Description:** A typed query helper retrieves an IAT row by ID or by token-hash for verification at registration time.

**Acceptance Criteria:**
- [ ] `internal/query/initial_access_token.go` exposes a `InitialAccessTokenByID(ctx, id)` function returning the projected row or a not-found error.
- [ ] An `InitialAccessTokenByHash` (or equivalent) lookup exists for the registration-handler verification path.
- [ ] SQL is embedded via `//go:embed initial_access_token_by_id.sql` next to the Go file (matches `internal/query/oidc_client.go:70-97` pattern).
- [ ] Cross-instance and cross-org IATs return not-found relative to the calling instance/org context.

**Dependencies:** R3

### R5: IAT plaintext format and storage
**Description:** IAT plaintext is a 48-byte random base64url string prefixed `zdiat_`. Only the Passwap-encoded hash is persisted; plaintext is returned exactly once at issue time.

**Acceptance Criteria:**
- [ ] `CreateInitialAccessToken` returns a plaintext token whose decoded random portion is 48 bytes.
- [ ] The plaintext begins with the literal prefix `zdiat_`.
- [ ] The persisted projection column `token_hash` is a Passwap-encoded string (NOT plaintext).
- [ ] Subsequent `ListInitialAccessTokens` responses do NOT include plaintext for any token (only metadata + hash-derived ID).
- [ ] M1 verifies (via grep) that `zdiat_` does not collide with any existing Zitadel token prefix; if it does, a new distinct prefix is chosen.

**Dependencies:** R6

### R6: Admin gRPC surface
**Description:** Three RPCs are added to the existing `zitadel.admin.v1.AdminService` in the single monolithic `proto/zitadel/admin.proto` file.

**Acceptance Criteria:**
- [ ] `proto/zitadel/admin.proto` `AdminService` (line 205) gains `CreateInitialAccessToken(CreateInitialAccessTokenRequest) returns (CreateInitialAccessTokenResponse)`.
- [ ] Same service gains `ListInitialAccessTokens(ListInitialAccessTokensRequest) returns (ListInitialAccessTokensResponse)` using `zitadel.v1.ListQuery` input + `zitadel.v1.ListDetails` output.
- [ ] Same service gains `RevokeInitialAccessToken(RevokeInitialAccessTokenRequest) returns (RevokeInitialAccessTokenResponse)`.
- [ ] `CreateInitialAccessTokenRequest` fields: `string project_id = 1; google.protobuf.Duration lifetime = 2; int32 max_uses = 3 (0 = unlimited); repeated string allowed_grant_types = 4; repeated string allowed_redirect_uri_patterns = 5; string description = 6`.
- [ ] All three RPCs carry `google.api.http`, `zitadel.v1.auth_option`, and `openapiv2_operation` annotations matching the `AddSMTPConfig` pattern (~line 490) with a new tag "Initial Access Tokens".
- [ ] `auth_option` permission strings (`iam.write` / `iam.read` or repository-verified equivalents) resolve to constants registered in `internal/api/authz/`.
- [ ] `buf generate` and `pnpm generate` produce a clean diff after the proto edit.
- [ ] No new proto file is created — extension is in-place on `admin.proto`.
- [ ] When `OIDC.DCR.Enabled=true` AND the runtime feature flag `KeyDynamicClientRegistration` is OFF for the calling instance's resource owner, all three RPCs return gRPC status `FAILED_PRECONDITION` with message key `Errors.DCR.FeatureDisabled` (HTTP-bridge mapping → 403). Symmetric to the HTTP handler's runtime-flag-off behavior in `cavekit-config.md` R3 / `cavekit-register-handler.md` R8.
- [ ] When `OIDC.DCR.Enabled=false` at startup, the three RPCs are not registered on `AdminService` (the proto definitions exist; the server-side registration is conditional). Calls receive gRPC `UNIMPLEMENTED`.

**Dependencies:** R5; `cavekit-config.md` R2 (runtime feature gate), R3 (dual-gate behavior contract).

### R7: Project-aggregate serialization characteristic
**Description:** Because IAT events are emitted on the `project` aggregate, concurrent consumptions of IATs that target the same project serialize through Zitadel's per-aggregate sequence lock. This characteristic must be documented in handler godoc so operators can plan throughput.

**Acceptance Criteria:**
- [ ] The IAT consume command (or its handler godoc) carries a comment that reads: "Concurrent consumption of IATs from the same project is serialized by eventstore aggregate locking; use multiple projects for parallelism."
- [ ] An integration test (`dcr_iat_projection_lag_test.go` per `cavekit-security-hardening.md` R5) verifies retry-success rate ≥ 95% under simulated worst-case projection lag.

**Dependencies:** R2

## Out of Scope
- Inline `jwks` validation through IATs.
- Per-org IAT policy.
- IAT issuance via end-user / non-admin gRPC paths.
- Token-prefix unification across PAT / IAT / RAT.
- Bulk IAT import / export.

## Cross-References
- See `cavekit-config.md` R2: feature flag gates the admin gRPC surface for R6.
- See `cavekit-register-handler.md` R3: registration handler verifies an IAT by calling consume from R2.
- See `cavekit-security-hardening.md` R3: log redaction must cover the gRPC `CreateInitialAccessToken` response body (plaintext IAT field).
- See `cavekit-security-hardening.md` R5: T18 projection-lag test cross-references R7.
- See `cavekit-console-ui-docs-and-observability.md` R2: console IAT admin UI consumes the gRPC from R6.

## Source Traceability (brownfield)
- `proto/zitadel/admin.proto:205` — `zitadel.admin.v1.AdminService` definition. [VERIFIED] single monolithic file confirmed.
- `proto/zitadel/admin.proto` ~`:490` — `AddSMTPConfig` pattern for annotations. [VERIFIED] reference style.
- `internal/repository/project/oidc_config.go:20-83` — event factory pattern reference. [VERIFIED] Go convention `NewXEvent(ctx, agg, ...)`.
- `internal/query/oidc_client.go:70-97` — `//go:embed` SQL + `database.QueryJSONObject` pattern. [VERIFIED].
- `internal/query/projection/projection.go` — projection registration site. [GAP] IAT projection not registered.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
