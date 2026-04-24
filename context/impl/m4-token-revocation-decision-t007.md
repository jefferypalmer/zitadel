---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# T-007 — M4 Decision Gate: DELETE token-revocation path (a vs b)

Build site: context/plans/build-site.md
Cavekit: cavekit-manage-handler.md R6
Decision owner: DCR implementer (this loop)
Decision date: 2026-04-24

## Evidence

### Primitives that EXIST today

- `internal/command/oidc_session.go:266` `RevokeOIDCSessionToken(ctx, token, clientID)` — per-token revoker; takes a plaintext token string, enforces `clientID` match, emits exactly one `AccessTokenRevokedEvent` or `RefreshTokenRevokedEvent`.
- `internal/repository/oidcsession/oidc_session.go:130-180` — `AccessTokenRevokedEvent` (`project.application.token.access.revoked` wire-type lineage) and `RefreshTokenRevokedEvent` event types with factory functions (`NewAccessTokenRevokedEvent`, `NewRefreshTokenRevokedEvent`).
- `internal/command/project_application.go:121` `RemoveApplication(ctx, projectID, appID, resourceOwner)` — emits `ApplicationRemovedEvent` but does NOT revoke outstanding tokens.
- `internal/query/app.go:494` `AppByClientID` — lookup from clientID → app exists.

### Primitives that DO NOT exist today

- No `RevokeApplicationTokens` / `RevokeAllApplicationTokens` command (grep confirms: zero matches in `internal/command/`).
- No query helper to enumerate active OIDC sessions by `client_id` (no `OIDCSessionsByClientID`, `FindSessionsByApp`, etc. — `internal/query/session.go:311` `SearchSessions` filters by `SessionsSearchQueries` but no client_id accessor is wired).
- The OIDCSession projection carries a `client_id` column (set at session creation) so adding a query is straightforward; the blocker is volume, not schema.

## Decision

**Path (a) — `RevokeApplicationTokens` command, default.**

Rationale:
- RFC 7592 §4 is REQUIRES-level ("the authorization server MUST invalidate all issued ... access tokens and refresh tokens"). Path (b) contradicts the spec and ships a user-owned workaround as the default security posture.
- Path (a) builds on primitives that already exist at the event-sourcing layer (`AccessTokenRevokedEvent`, `RefreshTokenRevokedEvent`, the `oidc_session` projection with a `client_id` column).
- The missing pieces are:
  1. A query helper: `ActiveOIDCSessionsByClientID(ctx, instanceID, clientID) []Session` selecting sessions with outstanding (non-revoked) access or refresh tokens for the client. Implementable as a read against the existing `projections.oidc_session` projection plus a filter on the revocation sub-columns. If the projection does not persist token-level state, fall back to eventstore filter on `oidcSession` aggregates (slower but correct).
  2. The command itself: `(c *Commands) RevokeApplicationTokens(ctx, projectID, appID string)` that iterates the query output and pushes one `AccessTokenRevokedEvent` + optional `RefreshTokenRevokedEvent` per session — batched in a single `eventstore.Push` when possible.
- Both pieces are implementable in Phase 1 and do not require new DDL (the `oidc_session` projection already has the columns we need to read).

Path (b) is explicitly rejected because:
- It would require a CHANGELOG/SECURITY.md note saying "Zitadel's DCR DELETE does not revoke tokens — operators must call /oauth/v2/revoke per token" which is a shipped-incomplete-feature signal.
- Operators do not in practice know which tokens exist for a given client without projection access they do not have.
- Claude Code MCP clients in particular rely on DCR DELETE as a clean unregister; a leaky unregister is a UX and security regression.

## Scope of T-056

T-056 implements path (a):

1. Add `ActiveOIDCSessionsByClientID` (or `ActiveAppOIDCSessions`) query helper at `internal/query/oidc_session.go` (or `session.go` if that is the idiomatic location). Name to be decided at T-056 time based on existing naming conventions.
2. Add `(c *Commands) RevokeApplicationTokens(ctx, projectID, appID string) error` at `internal/command/project_application.go` (adjacent to `RemoveApplication`) OR at `internal/command/oidc_session.go` as a bulk sibling to `RevokeOIDCSessionToken` — decide at implementation time based on which aggregate the revocation events should attach to.
3. DELETE handler (T-056) sequence: RAT verify → RevokeApplicationTokens → RemoveApplication → 204.
4. Integration test `dcr_delete_revokes_tokens_test.go` issues an access + refresh token, performs DELETE, asserts the access token is rejected by `/oauth/v2/introspect` and the refresh token is rejected by `/oauth/v2/token`.

## Residual risk

- **Revocation atomicity**: if `RevokeApplicationTokens` succeeds but `RemoveApplication` fails, we end up with revoked tokens on a live app. Mitigation: push both sets of events in a single `eventstore.Push` transaction OR accept "revoked-but-app-remains" as non-worse than "app-removed-but-tokens-live" and document the order.
- **Volume**: an app with thousands of active sessions produces thousands of revocation events in one DELETE call. Mitigation: batch in chunks of ≤100 events per Push; defer to T-056 sizing.
- **Eventual consistency**: introspection queries the projection — until the revocation events are projected, an already-issued access token may still introspect as active. Mitigation: use the projection-lag retry pattern from `cavekit-iat.md` R7 inside the integration test.

## R6 acceptance-criteria mapping

- [x] Path (a) selected; rationale + scope for T-056 written.
- [ ] `RevokeApplicationTokens` command implemented — deferred to T-056.
- [ ] `dcr_delete_revokes_tokens_test.go` — deferred to T-056.
- [ ] CHANGELOG entry (path-a outcome) — deferred to T-082.
- [ ] SECURITY.md threat-model residual risk notes — deferred to T-083 (T1 / T4).
