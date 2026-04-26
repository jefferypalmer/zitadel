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
- **Fix commit:** (next commit — recorded after this entry lands)
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

## Pattern category counts

| Category | Count |
|----------|-------|
| kit-internal-inconsistency | 1 |
