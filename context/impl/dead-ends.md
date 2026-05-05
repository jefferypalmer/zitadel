---
created: "2026-04-26T22:00:00Z"
last_edited: "2026-04-26T22:00:00Z"
---
# Dead Ends — DCR Build Site

Build site: context/plans/build-site.md

Document approaches that were tried, why they don't work, and what the
forward path is. Future iterations re-read this file before picking
tasks so we don't relitigate decisions.

## DE-001 — T-037 cannot use InitialAccessTokenByHash as currently shipped

**Symptom:** During T-038 implementation (iter 14, 2026-04-26), tracing the
T-037 IAT-mode auth flow revealed a fundamental mismatch between the
plaintext format (T-021), the projection schema (T-019), and the lookup
helper (T-020).

**Mechanism:**
- T-021 plaintext format is `zdiat_` + base64url(48 random bytes). No
  embedded IAT ID, no embedded deterministic hash.
- T-019 projection stores `token_hash` as the Passwap-encoded form
  (non-deterministic — different salt every Hash() call).
- T-020 query helper `InitialAccessTokenByHash(ctx, tokenHash)` does
  `WHERE token_hash = $2` — assumes the caller can derive the lookup
  key from the presented Bearer.

You cannot derive the Passwap encoding from a presented plaintext (by
design — that's why Passwap is a hash function). So the kit's described
flow ("the handler hashes the presented plaintext token then calls this
lookup") cannot work with the T-021 plaintext + T-019 hash combination.

**Forward path — three options for /ck:revise to pick from:**

1. **Embed IAT ID in plaintext.** Change T-021 to
   `zdiat_<id>.<48-random-bytes-b64url>`. Handler extracts ID, calls
   `InitialAccessTokenByID`, then `VerifyIATPlaintext` against the
   stored Passwap hash. Schema unchanged. Plaintext gets longer.

2. **Add a deterministic lookup-only column.** New `token_lookup`
   column on `projections.initial_access_tokens` storing
   HMAC-SHA256(plaintext, server-secret). Handler computes the HMAC of
   the presented plaintext to look up the row, then verifies via
   Passwap. Requires a migration + a new server secret.

3. **List + verify.** Add an instance-scoped IAT search query
   (`SearchInitialAccessTokensByInstance`) and have the handler
   iterate every active IAT in the instance, calling
   `VerifyIATPlaintext` until one matches. O(N) per request where N is
   IATs-per-instance. Acceptable for small N (admin-issued, finite);
   becomes a timing oracle for large N.

**Recommendation:** Option 1. Smallest scope, no migration, no new
server secret, no scaling concern. Cost is a one-time format change
that hasn't shipped to any user yet (T-021 just landed mid-build).

**Status:** **RESOLVED 2026-04-26** via `/ck:revise --trace`. Option 1
(embed IAT ID in plaintext) selected after a security review found it
strictly more secure than the alternatives (no list-iteration timing
oracle, no new server secret in breach blast radius).

Resolution commits:
- `ae2290c83` — kit amendments (R3/R4/R5 of cavekit-iat.md +
  redaction-regex AC on cavekit-security-hardening.md R3) + regression
  test that fails to compile pre-fix.
- T-037 fix commit (next) — `GenerateIATPlaintextForID` /
  `ParseIATPlaintext` / `ResolveIAT` with anti-enum dummy-Verify;
  remove `InitialAccessTokenByHash` + SQL + `token_hash` index +
  `IATAuthNotImplemented` placeholder.

Security additions baked into the kit amendment (beyond the bare
"embed-ID" idea):
- Anti-enum dummy-Verify on parse-failure / not-found / wrong-instance
  branches (cavekit-iat.md R4 amendment + ResolveIAT impl).
- Parser contract via `strings.Cut` first-dot split + ID-alphabet
  restriction `[A-Za-z0-9_-]+` (cavekit-iat.md R5 amendment +
  `ParseIATPlaintext` impl).
- Full-token log-redaction regex `zdiat_[^\s"',]+`
  (cavekit-security-hardening.md R3 amendment + cross-ref from
  cavekit-iat.md R5).

## Phase 3 — operator-driven tasks (NOT dead ends; deferred-by-design)

### T-014 (cavekit-console-ui-docs-and-observability.md R3, build-site-phase3.md)
**Run the i18n pipeline against 22 locales — operator-driven.**
The pipeline (T-004 / T-005), translation-correctness contract (T-012),
and CI reproducibility verifier (T-015) are all in place. en.json was
extended with the four new ARIA-label keys
(DESCRIPTIONS.DCR.IAT.{REFRESH,COPY,REVEAL_TOGGLE,DISMISS}) so the
pipeline has source values to translate.

The actual translation requires a live `ANTHROPIC_API_KEY` and is
operator-driven (CI infrastructure or local dev with the key
exported). When run, every locale's missing keys are filled and the
pnpm script `translate-i18n:verify` confirms reproducibility on
subsequent runs.

Until the operator runs the pipeline, the four new keys resolve via
ngx-translate's English fallback in non-English locales — acceptable
for ARIA labels (T-018) but explicitly NOT a passing R3 outcome per
the kit. T-018 wires the ARIA bindings now; the locale fill is
backfilled by operator action.

### T-022 (build-site-phase3.md, "operational" cavekit)
**Image build + push + tag — operator-driven.**
Listed for release-sequence completeness; no kit acceptance criterion.
The builder loop ignores it.

### T-021 (build-site-phase3.md, end-to-end smoke)
**Operator-driven CI integration test.**
Requires booting Zitadel against (a) a fresh empty Postgres and (b) an
upgrade-simulation Postgres carrying v5.0.0-dcr.2 data, then exercising
the full register / replay-reject / RFC 7592 PUT / janitor / Cypress
re-run sequence. The acceptance assertions are too heavy for the
builder loop:
- requires a live Postgres
- requires the zitadel binary running with TLS / DB / queue all wired
- asserts log-line absence (`refusing to construct`)
- runs two consecutive Cypress passes

The component pieces are individually tested:
- T-009 / T-010 — framework guard panic + truth-table tests (unit)
- T-013 — static back-stop AST walk on every PR
- T-006 — VerifyAudience truth table (6 unit tests)
- T-007 — ManageFromContext panic test (unit)
- T-011 — janitor cancellation deadline (unit)
- T-020 — Cypress teardown helpers (idempotent)

T-021 stitches them together end-to-end; deliverable when CI runs the
green-fields + upgrade-from-dcr.2 smoke. Logged as operator-deferred,
not blocked by builder error.
