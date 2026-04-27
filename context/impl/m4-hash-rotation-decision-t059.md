---
created: "2026-04-27T12:00:00Z"
last_edited: "2026-04-27T12:00:00Z"
---
# T-059 — M4 Decision Gate: Hash-rotation cross-cut

Build site: context/plans/build-site.md
Cavekit: cavekit-security-hardening.md R5
Decision owner: DCR implementer (T-051 / T-059 closer)
Decision date: 2026-04-27

## Decision

**Silent RAT-hash rotation IS implemented in scope (Phase 1).** R5 AC3
("If the silent-rehash path is deemed out of scope at M4, document the
limitation") is **N/A** — the path is in scope, shipped, and
structurally pinned.

## Implementation evidence

R5 AC1 — RFC 7592 verify path uses Passwap two-return form:
- `internal/api/oidc/dcr/manage.go:305` —
  `updatedHash, vErr := deps.RATVerifier.Verify(row.TokenHash, presented)`
- `RATVerifier` interface at `internal/api/oidc/dcr/manage.go:72-74`
  declares `Verify(encoded, presented string) (updated string, err error)`,
  matching `internal/api/oidc/client.go:250-257` (the existing OIDC
  client-secret verify path the kit cross-references).
- Production wiring at `cmd/start/start.go:755` passes
  `commands.SecretHasher()` directly — `*crypto.Hasher` embeds
  `*passwap.Swapper.Verify`, so the wire-up is compile-time-enforced
  to use the two-return form.

R5 AC2 — `project.application.registration_access_token.rehashed`
event persists the new hash:
- Event type at
  `internal/repository/project/dynamic_client_registration.go:27`.
- Reducer updates ONLY the hash column, NOT the expires_at column
  (per cavekit-manage-handler.md R2 lifetime-untouched rule):
  `internal/query/projection/app.go:reduceApplicationRegistrationAccessTokenRehashed`.
- Command at `internal/command/dynamic_client_registration.go:316`
  (`Commands.RehashRegistrationAccessToken`). Wired through
  `dcr.ManageDeps.Rehasher` → invoked by `dcr.VerifyRAT` when
  `updatedHash != ""`.
- Failure to persist the rehash is logged at WARN with
  project_id+app_id+err so operators get an observability signal
  (T-090 / F-007 fix, 2026-04-27).

R5 AC4 — `dcr_iat_projection_lag_test.go` ≥95% retry success: out
of scope for T-059; tracked by T-060 (Tier 5).

## Behavioural pinning

- Unit-style: `TestVerifyRAT_SilentRehash`
  (`internal/api/oidc/dcr/manage_test.go:164`) — fake verifier returns
  non-empty `updatedHash`; asserts Rehasher is invoked with
  `(projectID, orgID, appID, updatedHash)`.
- Failure path: `TestVerifyRAT_RehashFailureDoesNotFailVerification`
  (verification still succeeds when push fails).
- Failure path observability:
  `TestVerifyRAT_RehashFailureLogsWarn` (T-090) — slog.Warn carries
  the operator-correlation fields.
- Integration-style: `TestT059_HashRotation_RealPasswap_TwoReturnForm`
  (added with this T-059 decision) — uses a REAL `passwap.Swapper`
  configured for bcrypt-stored / argon2id-active rotation, stores a
  bcrypt-hashed RAT, exercises VerifyRAT, asserts (a) verify succeeds,
  (b) Rehasher receives a Passwap-encoded argon2id hash distinct from
  the original bcrypt encoding, (c) ManageContext.Rehashed=true.

## Cross-references

- T-051 (RAT verify w/ Passwap two-return) — implementation owner.
- T-090 (silent-rehash failure observability) — adds WARN logging.
- T-018 / T-060 — projection-lag retry-success tests (cross-cut R5
  AC4).
- cavekit-manage-handler.md R2 — lifetime-untouched-on-rehash rule.
- cavekit-iat.md R7 — projection-lag retry pattern (T18 threat-model
  mapping in cavekit-security-hardening.md R6).

## Status

R5 AC1 ✓ — two-return form pinned at interface signature + wiring +
behavioural test.
R5 AC2 ✓ — rehashed-event emission pinned (T-051) + observability
(T-090).
R5 AC3 ✓ — affirmative decision: silent-rehash IS in scope (this
artifact).
R5 AC4 → T-060 (cross-cut to T-018 + cavekit-iat.md R7).
