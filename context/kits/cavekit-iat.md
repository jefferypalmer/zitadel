---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-27T00:30:00Z"
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
- [ ] Index `(instance_id, project_id)` is present. (No `token_hash` index — the Passwap-encoded hash is non-deterministic and is therefore never a lookup key. Lookup is by `id` only; see R4 amendment 2026-04-26.)
- [ ] Reducer for `InitialAccessTokenAddedEvent` INSERTs a row.
- [ ] Reducer for `InitialAccessTokenConsumedEvent` increments `uses_consumed` and appends to `consumed_slots`.
- [ ] Reducer for `InitialAccessTokenRevokedEvent` sets `revoked = TRUE`.

**Dependencies:** R1

### R4: Query helpers
**Description:** A typed query helper retrieves an IAT row by `id` for verification at registration time. The plaintext format (R5) embeds the IAT row's PK so the registration handler can extract it directly from a presented Bearer — no hash-based lookup is possible because the persisted `token_hash` is the non-deterministic Passwap encoding.

**Acceptance Criteria:**
- [ ] `internal/query/initial_access_token.go` exposes `InitialAccessTokenByID(ctx, id, resourceOwner)` returning the projected row or a not-found error.
- [ ] No `InitialAccessTokenByHash` helper exists. Hash-based lookup is structurally impossible against a non-deterministic Passwap hash; the registration handler instead parses the Bearer plaintext (`zdiat_<id>.<random>` per R5), extracts `<id>`, calls this lookup, then runs `VerifyIATPlaintext(presented, row.TokenHash)` to verify the random portion.
- [ ] SQL is embedded via `//go:embed initial_access_token_by_id.sql` next to the Go file (matches `internal/query/oidc_client.go:70-97` pattern).
- [ ] Cross-instance and cross-org IATs return not-found relative to the calling instance/org context.
- [ ] **Anti-enumeration dummy-hash provenance (added 2026-04-27 / F-101).** When `InitialAccessTokenByID` returns `ThrowNotFound`, the registration handler MUST run a dummy `VerifyIATPlaintext` against a precomputed dummy Passwap hash before responding 401 `invalid_token`, so the response time of an unknown ID matches the response time of a known ID with a wrong random within typical Passwap variance. The dummy hash MUST be produced by calling `secretHasher.Hash(<sentinel plaintext>)` exactly once at startup and cached in the wiring layer. Hand-written hash literals (e.g. `$argon2id$v=19$m=65536,t=2,p=1$...`) are FORBIDDEN — the encoded algorithm prefix MUST match the configured `SecretHasher.Algorithm` so `passwap.Swapper.Verify` runs the same crypto path real IATs do. A static literal can return `passwap.ErrNoVerifier` instantly when the deployment configures a different algorithm (`bcrypt` is the cmd/defaults.yaml default), inverting the oracle: not-found becomes MEASURABLY FASTER than wrong-random.
- [ ] **Startup probe (added 2026-04-27 / F-101).** The wiring code that builds the dummy hash MUST call `secretHasher.Verify(dummy, <wrong-plaintext>)` exactly once and panic if the returned error wraps `passwap.ErrNoVerifier`. Any other Verify error is the expected "wrong plaintext" outcome and is acceptable. This fail-fast probe makes a misconfigured deployment crash at boot rather than silently leak timing for the lifetime of the process. Mirrors the anti-enumeration pattern in `cavekit-manage-handler.md` R3 / `cavekit-security-hardening.md` R4 for unknown `client_id`.
- [ ] **Real-Passwap timing test (added 2026-04-27 / F-101).** A unit test MUST exercise the dummy-Verify path via the live `passwap.Swapper` (configured the same way the production hasher is, with bcrypt-cost-4 acceptable for test speed) — NOT a stub that short-circuits on string equality. The test MUST run N≥50 iterations each of (a) the not-found path and (b) the wrong-random path through `ResolveIAT`, and MUST assert that `mean-not-found / mean-wrong-random` falls in `[0.5, 2.0]`. A test using a stub verifier that bypasses real Passwap work — like the one F-101 slipped past — does NOT satisfy this AC.

**Dependencies:** R3

### R5: IAT plaintext format and storage
**Description:** IAT plaintext encodes the row's primary-key ID alongside a 48-byte CSPRNG random portion so the registration handler can look up the row in O(1) without a deterministic-hash index. Format: `zdiat_<id>.<random>`. Only the Passwap-encoded hash of the full plaintext is persisted; plaintext is returned exactly once at issue time. The secret of the credential is the `<random>` portion; the `<id>` is public-equivalent (predictable, monotonic Sonyflake) and is treated as such by all log-redaction / audit code.

**Acceptance Criteria:**
- [ ] `CreateInitialAccessToken` returns a plaintext of the form `zdiat_<id>.<random>` where `<id>` is the IAT row's primary-key ID and `<random>` is `base64url(48 random bytes)` (`crypto/rand`).
- [ ] The plaintext begins with the literal prefix `zdiat_`; the literal `.` separator delimits the ID from the random portion.
- [ ] The ID alphabet is restricted to `[A-Za-z0-9_-]+` (Sonyflake's URL-safe set); generation of a plaintext with any other character in the `<id>` position is a programmer error caught at test-time.
- [ ] `ParseIATPlaintext(s string) (id, random string, ok bool)` parses a presented Bearer using `strings.Cut(s[len("zdiat_"):], ".")` — splits on the **first** `.` only, so an attacker cannot smuggle dots into either portion to confuse the parser. Returns `ok=false` for missing prefix, missing separator, empty ID, empty random, or invalid ID alphabet.
- [ ] The persisted projection column `token_hash` is a Passwap-encoded string of the full plaintext (NOT just the random portion, NOT the plaintext itself). Storing the hash of the full plaintext means an attacker who learns the ID alone cannot reduce the verification problem.
- [ ] Subsequent `ListInitialAccessTokens` responses do NOT include plaintext for any token (only metadata; the plaintext is irrecoverable from the projection by design).
- [ ] M1 verifies (via grep) that `zdiat_` does not collide with any existing Zitadel token prefix; if it does, a new distinct prefix is chosen.
- [ ] **Log redaction (cross-ref `cavekit-security-hardening.md` R3).** Redaction patterns MUST match the entire token `zdiat_[^\s"',]+` (greedy through the `.` separator). Half-redacting (e.g. masking only the random portion) is unsafe — combining a log-leaked ID with a separately-leaked random reconstructs the credential.

**Dependencies:** R6, R3 (the projection schema this amendment de-indexes), `cavekit-security-hardening.md` R3 (log-redaction wrappers must match the full-token regex above).

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

### 2026-04-27 — Revision (F-101 / `--trace`)
- **Affected:** R4
- **Summary:** The original anti-enum dummy-Verify AC (added 2026-04-26 in the DE-001 amendment) was permissive about *provenance* of the dummy hash. T-038 implementer hardcoded a `$argon2id$` literal in source; production cmd/defaults.yaml ships `Algorithm: bcrypt` with empty `Verifiers`, so `passwap.Swapper.Verify` returned `ErrNoVerifier` instantly on the dummy — the not-found path became MEASURABLY FASTER than the wrong-random path. Inverted oracle: worse than no defence. Amendment splits the single AC into three: (1) provenance — dummy MUST come from `secretHasher.Hash(sentinel)` at startup, hardcoded literals FORBIDDEN; (2) startup probe — wiring code MUST `Verify(dummy, "x")` once at boot and panic on `ErrNoVerifier`; (3) real-Passwap timing test — N≥50 iterations through the live hasher, ratio mean-not-found / mean-wrong-random ∈ [0.5, 2.0]. Stub-only tests (which is how F-101 slipped past) do NOT satisfy AC3.
- **Commits:** 9e90d30b3 (T-038 originally landed the static literal). Regression tests + fix commits to follow.
- **Pattern category:** unspecified-parser-contract (same family as F-100 — kit permissive about provenance/derivation rule, implementer filled with ineffective artifact). With this entry the category counter reaches 2; one more triggers a cross-kit amendment recommendation.

### 2026-04-26 — Revision (DE-001 / `--trace`)
- **Affected:** R3, R4, R5
- **Summary:** R3/R4/R5 originally described mutually inconsistent contracts: R5 specified a non-deterministic Passwap-encoded plaintext, R3 indexed `token_hash`, R4 declared an `InitialAccessTokenByHash` lookup. Passwap hashes are non-deterministic by design; the registration handler cannot derive the lookup key from a presented Bearer. Amendment moves to ID-embedded plaintext (`zdiat_<id>.<random>`), drops the unusable hash index from R3, drops `InitialAccessTokenByHash` from R4, and adds three security ACs: dummy-Verify-on-not-found anti-enum (R4), parser contract via `strings.Cut` first-dot split with restricted ID alphabet (R5), and full-token log-redaction regex `zdiat_[^\s"',]+` cross-ref to security R3 (R5).
- **Commits:** 52210faa4 (T-021 originally) / 78b8f520a (T-019) / c53263536 (T-020) — original drift commits being corrected. Regression test + fix commits to follow.
- **Pattern category:** kit-internal-inconsistency (cross-requirement contract mismatch).
