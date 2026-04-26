# Backpropagation Log

Append-only audit trail of `/ck:revise --trace` runs. Each entry
records the failure, classification, kit changes, regression test,
fix, and pattern category so cross-iteration trends become visible.

## Entry #1 — DE-001 / IAT lookup design gap

- **Date:** 2026-04-26
- **Triggered by:** `/ck:revise --trace` (option C — process current
  finding then stale flag) on user-recognised DE-001 from
  `context/impl/dead-ends.md`.
- **Classification:** `wrong_criterion` — kit-internal-inconsistency.
  cavekit-iat.md R3/R4/R5 individually self-consistent but jointly
  contradictory: R5 specified non-deterministic Passwap plaintext,
  R3 indexed `token_hash`, R4 declared `InitialAccessTokenByHash`.
  Passwap is non-deterministic by design — the registration handler
  cannot derive the lookup key from a presented Bearer.
- **Kit:** `cavekit-iat.md` → R3, R4, R5; cross-amend
  `cavekit-security-hardening.md` → R3.
- **Amendment summary:**
  - R3: drop `(token_hash)` index AC.
  - R4: drop `InitialAccessTokenByHash` AC; require `ByID` only;
    add anti-enum dummy-Verify-on-not-found AC.
  - R5: amend plaintext to `zdiat_<id>.<random>`; specify parser
    (strings.Cut first-dot split, ID alphabet `[A-Za-z0-9_-]+`,
    case-sensitive prefix); cross-ref security R3 redaction regex
    `zdiat_[^\s"',]+`.
  - security-hardening R3: append IAT-token redaction-regex AC
    flagging that half-redaction is unsafe.
- **Regression test:** `internal/command/iat_format_test.go::TestIATPlaintext_R5_EmbedsIDFormat`,
  `TestParseIATPlaintext_R5_FirstDotSplit`,
  `TestParseIATPlaintext_R5_RejectsMalformed`,
  `TestParseIATPlaintext_R5_AcceptsValid`.
  Failed to compile pre-fix (functions `GenerateIATPlaintextForID` /
  `ParseIATPlaintext` did not exist). Pass post-fix.
- **Test commit:** `ae2290c83`
- **Fix commit:** `1f37adf1e`
- **Pattern category:** `kit-internal-inconsistency`
- **Security review:** Performed before approval. Option 1
  (embed-ID-in-plaintext) selected over options 2 (HMAC column +
  new server secret) and 3 (list+verify, O(N) timing oracle).
  Three security ACs added during amendment that would not have
  appeared in a naive embed-ID design: anti-enum dummy-Verify
  (R4), parser contract restricting `<id>` alphabet (R5),
  full-token redaction regex (security R3).
- **Notes:** This is the first DE-* entry on the dead-ends file
  and the first backprop log entry. Pattern category counter:
  `kit-internal-inconsistency: 1`.

## Entry #2 — Stale 2026-04-24 pending flag (no-op, audit only)

- **Date:** 2026-04-26
- **Triggered by:** `/ck:revise --trace` option C (also-process the
  stale flag after Trace A completed).
- **Source:** `.cavekit/.auto-backprop-pending.json` recorded at
  2026-04-24T13:37:14Z. Command:
  `cd ../oidc && go test ./pkg/oidc/ -run TestAuthRequest_`.
  Failure excerpt: `FAIL\tgithub.com/zitadel/oidc/v3/pkg/oidc [setup failed]`.
- **Triage:** Re-running the same command in `/home/jeff/oidc` on
  2026-04-26 returns `ok 0.002s`. The original failure was a
  transient mid-build state during T-013 upstream RFC 8707 resource
  work (commit 1a138e7 on branch `feat/authrequest-resource-rfc8707`,
  CODE READY per loop-log iteration 3). No reproducer today.
- **Classification:** N/A — no current failure to backprop.
- **Kit changes:** None. The flag was logged for audit completeness;
  the file was deleted as part of trace A's mandatory cleanup.
- **Pattern category:** `infrastructural-transient` (recorded for
  cross-trace pattern tracking even though no kit work resulted).

## Pattern category counts

| Category | Count |
|----------|-------|
| kit-internal-inconsistency | 1 |
| infrastructural-transient (no-op) | 1 |
