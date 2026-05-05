---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-05-05T18:00:00Z"
complexity: complex
---

# Cavekit: RFC 7592 Management Handler (`GET|PUT|DELETE /oidc/v1/register/{client_id}`)

## Scope
Defines the RFC 7592 client-configuration endpoint: GET / PUT / DELETE on `/oidc/v1/register/{client_id}` authenticated by Registration Access Token (RAT). Covers RAT verification with Passwap silent rehash, anti-enumeration 401 on unknown `client_id`, full re-clamp of metadata on PUT, RAT rotation on every successful PUT, and token revocation on DELETE per RFC 7592 §4. Shares mux router, validate/clamp logic, and error envelope with `cavekit-register-handler.md`.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §1.2, §2.6 (RAT behavior), §4.4 (handler flow)
- Spec references: RFC 7592 §2 (operations), §2.1 (anti-enumeration), §4 (DELETE token revocation)

## Requirements

### R1: Endpoint mounting and routing
**Description:** GET / PUT / DELETE on `/oidc/v1/register/{client_id}` must be served by the same gorilla `*mux.Router` as `cavekit-register-handler.md` R1 — shared package, shared validate/error helpers.

**Acceptance Criteria:**
- [ ] GET / PUT / DELETE on the path produce 401 when no `Authorization: Bearer` header is supplied.
- [ ] When DCR is disabled at config time the path returns 404.
- [ ] When dual-gate startup is on but runtime feature is off, returns 403 `feature_disabled` (matches `cavekit-config.md` R3).
- [ ] Routing precedence: this `{client_id}` path is registered alongside `POST /oidc/v1/register` in the same mux.

**Dependencies:** `cavekit-register-handler.md` R1; `cavekit-config.md` R3.

### R2: RAT verification with Passwap + silent rehash
**Description:** All operations require an `Authorization: Bearer <RAT>` header. Verification uses Passwap's two-return form so that hash-algorithm rotation triggers a silent rehash event without exposing it to the client.

**Acceptance Criteria:**
- [ ] Verification calls `updatedHash, err := s.hasher.Verify(storedHash, bearerPlaintext)` (matches the pattern at `internal/api/oidc/client.go:250-257`).
- [ ] When `updatedHash != ""`, a `project.application.registration_access_token.rehashed` event is emitted to persist the new hash; the RAT plaintext is NOT changed and the change is not exposed to the client.
- [ ] When `RegistrationAccessToken.Lifetime > 0`, expiry is checked against the `registration_access_token_expires_at` column; expired RATs return 401 `invalid_token`.
- [ ] On verification failure → HTTP 401 with body `{"error":"invalid_token","error_description":"..."}` and `WWW-Authenticate: Bearer error="invalid_token"`.

**Dependencies:** R1.

### R3: Anti-enumeration on unknown `client_id`
**Description:** RFC 7592 §2.1 requires that unknown `client_id` and wrong-RAT both return 401 (NOT 404) so that an attacker cannot enumerate valid `client_id`s by status-code observation.

**Acceptance Criteria:**
- [ ] GET / PUT / DELETE against a `client_id` that does not exist returns HTTP 401 with body `{"error":"invalid_token","error_description":"..."}` (NOT 404).
- [ ] When `client_id` is unknown, the handler still calls `passwap.Verify` against a static dummy hash so response time matches the known-`client_id` path (cross-ref `cavekit-security-hardening.md` R4).
- [ ] All 401 responses (unknown `client_id`, wrong RAT, missing header) carry `WWW-Authenticate: Bearer error="invalid_token"`.

**Dependencies:** R2; `cavekit-security-hardening.md` R4.

### R4: GET — return current metadata
**Description:** GET returns 200 with the current client metadata. The body MUST omit fields the server cannot return as plaintext (`client_secret`, `registration_access_token`).

**Acceptance Criteria:**
- [ ] Status 200 on success.
- [ ] Body includes `client_id`, `client_id_issued_at`, `client_secret_expires_at`, `redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `application_type`, `client_name`, and any DCR-meta fields previously stored.
- [ ] Body OMITS `client_secret` (unretrievable) and `registration_access_token` (one-time issue) per RFC 7592 §2 MAY-omit allowance.
- [ ] Body re-emits `registration_client_uri` identical to the value returned by the original `cavekit-register-handler.md` R7 response.
- [ ] `Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-store`, `Pragma: no-cache`.

**Dependencies:** R2.

### R5: PUT — full replacement with re-clamp and RAT rotation
**Description:** PUT is a full replacement of mutable metadata. Every clamp from `cavekit-register-handler.md` R4 MUST run again. Every successful PUT rotates the RAT; the old RAT becomes immediately invalid.

**Acceptance Criteria:**
- [ ] `grant_types`, `response_types`, `token_endpoint_auth_method`, `application_type`, `redirect_uris`, and (when present) `audiences` are re-clamped per `cavekit-register-handler.md` R4 rules.
- [ ] Disallowed values → 400 `invalid_client_metadata`.
- [ ] Auth-method transition `none → client_secret_*` issues a new `client_secret` returned in the response body.
- [ ] Auth-method transition `client_secret_* → none` clears the stored secret (column written as empty-string via `OIDCConfigSecretChangedEvent("")` — equivalent to "no secret stored" for the app-lookup path; SQL NULL is NOT required); response omits `client_secret`.
- [ ] Auth-method transition `* → private_key_jwt` requires a valid `jwks_uri` in the new body; absent or invalid → 400 `invalid_client_metadata`.
- [ ] Auth-method transition to `client_secret_jwt` is rejected with 400 `invalid_client_metadata`.
- [ ] On every successful PUT a new RAT is generated, hashed via Passwap, persisted (emits `project.application.registration_access_token.rotated`), and the OLD RAT is immediately invalid for subsequent requests.
- [ ] PUT response is HTTP 200 with the new RAT in the body (same shape as the registration response).
- [ ] A retried PUT with the same (old) RAT after a successful first PUT returns 401 — documented as a known idempotency caveat in API docs (cross-ref `cavekit-console-ui-docs-and-observability.md` R3).
- [ ] PUT 200 response body MUST include `client_id_issued_at` (Unix seconds, sourced from the original registration time) — RFC 7592 §3.2 mandates the PUT response mirror the RFC 7591 §3.2.1 client-info shape, which includes this field. Equivalent to the GET path emission; PUT must not silently omit it. (F-001, 2026-04-27.)
- [ ] When the auth-method transition mints a fresh `client_secret` AND `OIDC.DCR.ClientSecretExpiresIn > 0`, PUT response `client_secret_expires_at` MUST be computed as `now + ClientSecretExpiresIn` (Unix seconds), NOT the `0=no expiry` sentinel. The 0 sentinel is reserved for the case where the AS policy explicitly sets no expiry (`ClientSecretExpiresIn == 0`). Same convention POST register uses via `clientSecretExpiresAtFor`. (F-002, 2026-04-27.)

**Dependencies:** R2; `cavekit-register-handler.md` R4, R5.

### R6: DELETE — remove client and revoke tokens
**Description:** DELETE removes the application AND invalidates outstanding access/refresh tokens for that client. RFC 7592 §4 REQUIRES token invalidation.

**Acceptance Criteria:**
- [ ] Successful DELETE returns HTTP 204 No Content.
- [ ] Before (or as part of) calling the existing `RemoveApplication` command (`internal/command/project_application.go:121` which emits `ApplicationRemovedEvent`), a sibling command MUST emit revocation events for every outstanding access/refresh token belonging to the client. The two pushes MAY be non-atomic (different aggregate types preclude a single-Push transaction). When non-atomic, revocation MUST happen first so a partial-failure leaves "revoked-but-app-remains" rather than the inverse "app-removed-but-tokens-active". (F-005 clarification, 2026-04-27.)
- [ ] Implementation path (a, default): a new `RevokeApplicationTokens(ctx, projectID, appID)` command emits revocation events; integration test `dcr_delete_revokes_tokens_test.go` issues an access + refresh token, performs DELETE, then asserts the access token is rejected by `/oauth/v2/introspect` (or, equivalently, by `/oidc/v1/userinfo` — both endpoints validate the access token through the same active-session check) and the refresh token is rejected by `/oauth/v2/token`. (F-003 userinfo-equivalence, 2026-04-27.)
- [ ] Implementation path (b, fallback if the M4 token-revocation primitives survey reveals (a) is infeasible in Phase 1): document the limitation in CHANGELOG + SECURITY.md and require operators to call `/oauth/v2/revoke` per token. The integration test is updated to assert 204 + the documented limitation note exists in release notes.
- [ ] The decision between (a) and (b) is recorded in the M4 worker report and reflected in CHANGELOG.
- [ ] DELETE is idempotent across retries: a second DELETE against an already-deleted client returns 401 (RAT verification fails — projection has no row) but never produces inconsistent state. A retried DELETE that follows a partial-failure first DELETE (revoked but not removed) succeeds — `RevokeApplicationTokens` emits zero new events when no active sessions remain; `ApplicationRemovedEvent` is the only push. (F-005 idempotency, 2026-04-27.)
- [ ] Revocation scope is `(instance_id, client_id)`. The kit assumes instance-wide `client_id` uniqueness from the snowflake generator. If a future ID generator weakens that assumption, this AC and the implementation MUST be revisited. (F-004, 2026-04-27.)

**Dependencies:** R2.

### R7: Shared validate / clamp / error helpers with register handler
**Description:** Validation, clamp logic, and the RFC 7591 error-body envelope are shared with `cavekit-register-handler.md` (same package `internal/api/oidc/dcr/`).

**Acceptance Criteria:**
- [ ] `internal/api/oidc/dcr/validate.go` is consumed by both POST register and PUT manage paths (single source of truth for clamp rules).
- [ ] `internal/api/oidc/dcr/errors.go` defines the RFC 7591 error envelope used by ALL DCR handler responses (POST + GET + PUT + DELETE).
- [ ] DCR error codes follow the `DCR-<5 alphanumeric>` zerrors prefix convention (e.g., `DCR-Wx2Y9`).

**Dependencies:** `cavekit-register-handler.md` R4.

### R8: `ManageFromContext` panics on missing context (programmer-error contract)
**Description:** `ManageFromContext(ctx)` (in `internal/api/oidc/dcr/manage.go`) currently returns `nil` when called outside the `manageVerifyDispatch` middleware chain, with each consumer guarding via `if mctx == nil { … WriteError(invalid_token) … }`. This R changes the contract: `ManageFromContext` MUST `panic` when called without a value previously stashed by the dispatcher. The panic is a programmer-error signal — production code paths reach this function only via the dispatcher (single-entry monopoly enforced by `NewHandler` per existing R1), so a missing value can only occur if a future RFC 7592 endpoint is wired without the dispatcher in its middleware chain. The panic provides an immediate stack trace pointing at the wiring mistake; the silent-nil-return path obscures the same mistake behind a generic 401 envelope.

**Acceptance Criteria:**
- [ ] `ManageFromContext(ctx)` returns `*ManageContext` (non-pointer-nilable contract) and `panic`s with a clear message — e.g. `"dcr.ManageFromContext called without manageVerifyDispatch in the chain — programmer error"` — when no value is found via the private `manageContextKey{}` lookup.
- [ ] Every consumer in `internal/api/oidc/dcr/manage_get.go`, `manage_put.go`, `manage_delete.go` (and any other present-or-future RFC 7592 file in the package) deletes its `if mctx == nil { … }` guard. Consumers may now treat the return value as non-nil.
- [ ] A unit test in `internal/api/oidc/dcr/manage_test.go` (or a new `manage_from_context_test.go`) asserts the panic when `ManageFromContext` is called with a raw `context.Background()` (no dispatcher value set).
- [ ] All existing manage-handler integration tests pass unchanged — the dispatcher monopoly means production paths never trigger the panic.
- [ ] grep-scan acceptance: `grep -rn 'mctx == nil\|mc == nil' internal/api/oidc/dcr/` returns only the panic site itself (or zero hits if the panic is structured as `if v, ok := …; !ok { panic(…) }` without a separate nil check).

Rationale: A panic is preferred over a typed error return because errors are for runtime conditions a caller might recover from. A missing `ManageContext` is a wiring bug — there is no recovery path other than fixing the code. Panic with an explicit message is the idiomatic Go contract for "this can never happen in correct code; if it does, fail loudly so the bug is caught in the first test run that exercises the misnamed handler." The panic is caught by the existing `middleware.RecoverHandler(writeRecoverError)` at `internal/api/oidc/op.go:300` so a single misconfigured request does not crash the server — the recover handler logs the panic with stack, which is exactly the diagnostic signal R8 is designed to surface.

**Dependencies:** R1 (handler mounting + dispatcher monopoly) — this R only makes sense because R1 already guarantees the dispatcher is the single entry point.

### R9: DCR routes MUST be wrapped in a dcr-shape recover middleware (post-loop revision F-001)
**Description:** R8's panic-on-missing contract claims the panic is caught by `middleware.RecoverHandler(writeRecoverError)` at `internal/api/oidc/op.go:300`. That assertion is incorrect: DCR routes mount via `apis.RegisterHandlerOnPrefix(dcr.HandlerPrefix, dcrWrapped)` in `cmd/start/start.go` — independent of `oidcServer.Handler`'s middleware chain. The OIDC `RecoverHandler` only wraps the OIDC server. A real R8 panic falls through to `middleware.FallbackRecoverHandler` (at `cmd/start/start.go:457-461`), which writes `text/plain "Internal Server Error"` instead of the RFC 7591 §3.2.2 `application/json` envelope DCR clients expect. R9 fixes this by requiring a dcr-shape recover middleware in the dcr handler chain.

**Acceptance Criteria:**
- [ ] `cmd/start/start.go` (or the equivalent router-mount site) wraps `dcrWrapped` in `middleware.RecoverHandler(dcrWriteRecoverError)` BEFORE the instance interceptor. `dcrWriteRecoverError` MUST emit `application/json` with the RFC 7591 §3.2.2 envelope (`{"error": "server_error", "error_description": "..."}`).
- [ ] An invariant test (sibling of `cmd/start/dcr_mount_test.go`) injects a deliberate panic into a stub handler mounted under the dcr prefix and asserts: status 500, `Content-Type: application/json`, body matches the dcr error envelope shape.
- [ ] Comments at `internal/api/oidc/dcr/manage.go:411`, `internal/api/oidc/dcr/manage_get_test.go:193`, and `internal/api/oidc/dcr/manage_from_context_test.go:11` are corrected to cite the new middleware (or removed if the wiring makes them redundant).

**Dependencies:** R1 (router mount), R8 (the panic this catches).

## Out of Scope
- RFC 7591 POST /register (handled in `cavekit-register-handler.md`).
- Bulk-delete of dynamically-registered apps.
- Per-org RAT lifetime overrides (Phase 2) — see `cavekit-org-dcr-policy.md`.
- Inline `jwks` updates (Phase 2) — see `cavekit-inline-jwks.md`.

## Cross-References
- See `cavekit-register-handler.md` R1: shared mux router.
- See `cavekit-register-handler.md` R4, R5: clamp + secret-issuance rules reused on PUT.
- See `cavekit-register-handler.md` R7: response shape echoed for GET / PUT.
- See `cavekit-config.md` R1: `RegistrationAccessToken.Enabled` / `Lifetime`.
- See `cavekit-security-hardening.md` R4: timing-side-channel mitigation (dummy-hash on unknown `client_id`).
- See `cavekit-security-hardening.md` R3: log redaction must cover RAT plaintext.
- See `cavekit-console-ui-docs-and-observability.md` R3: idempotency caveat documented.

## Source Traceability (brownfield)
- `internal/api/oidc/client.go:250-257` — Passwap `Verify(...)` two-return pattern with `updatedHash`. [VERIFIED] reused for RAT verification.
- `internal/command/project_application.go:121` — `RemoveApplication` emits `ApplicationRemovedEvent`. [VERIFIED] does NOT currently revoke issued tokens.
- `internal/command/oidc_session.go:266` — `RevokeOIDCSessionToken` is per-session only; no bulk equivalent today. [GAP] bulk `RevokeApplicationTokens` does not exist.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
- 2026-04-27: Post-loop /ck:check revisions:
  - R5 AC4: clarified "clears the stored secret" — empty-string column write via `OIDCConfigSecretChangedEvent("")`, NOT SQL NULL (functionally equivalent for app-lookup).
  - R5: added two new ACs (PUT response MUST emit `client_id_issued_at`; `client_secret_expires_at` MUST be computed from `ClientSecretExpiresIn` not hardcoded to 0). Findings F-001, F-002.
  - R6 AC2: clarified two-Push non-atomicity is acceptable; revocation-first ordering rationale codified. Finding F-005.
  - R6 AC3: added `/oidc/v1/userinfo` as accepted equivalent oracle alongside `/oauth/v2/introspect`. Finding F-003.
  - R6: added two new ACs (DELETE idempotency across retries; revocation scope = `(instance_id, client_id)`). Findings F-004, F-005.
- 2026-05-05 (v3 audit cleanup): Added R8 (`ManageFromContext` panic-on-missing — flips return-nil contract to panic-on-missing for clearer programmer-error diagnosis). Backed by existing recover middleware so a misconfigured request does not crash the server.
- 2026-05-05 (post-loop revision): Added R9 (DCR routes MUST be wrapped in a dcr-shape recover middleware — F-001). Inspection of the v3 build revealed R8's panic is NOT caught by the cited OIDC recover middleware because DCR routes mount independently of `oidcServer.Handler`. Without R9, a real R8 panic returns `text/plain "Internal Server Error"` instead of the RFC 7591 JSON envelope.
