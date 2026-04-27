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

## Entry #3 — F-100 / AllowedRedirectURIHostPatterns userinfo bypass

- **Date:** 2026-04-27
- **Triggered by:** `/ck:revise --trace --from-finding F-100` after a
  `/ck:check` REJECT verdict surfaced two P0 security findings.
- **Source finding:** `context/impl/impl-review-findings.md` F-100,
  reported by `ck:inspector` during a Tier 0–3 mid-build review.
- **Classification:** `incomplete_criterion` — R4 had the right intent
  but didn't pin the host-extraction algorithm. T-034 implementer
  rolled an unsafe hand-cut parser to fill the gap.
- **Vulnerability:** `extractHost` cut the URL on `://` / `/?#` / `:`
  but never stripped the RFC 3986 userinfo segment before `@`.
  `https://victim.example.com:443@evil.com/cb` parsed to host=
  `victim.example.com`, matched `*.example.com`, and was accepted —
  while the actual host the browser resolves is `evil.com`. An
  attacker registering a client with attacker-controlled DNS could
  defeat the host allow-list and steal authorization codes.
- **Kit:** `cavekit-register-handler.md` → R4.
- **Amendment summary:**
  - Tighten existing AC: "the URL's `u.Hostname()`" matches host
    patterns (was just "matches").
  - Add: host extraction MUST use `net/url.Parse` + `u.Hostname()`;
    hand-rolled parsers FORBIDDEN.
  - Add: URLs with `u.User != nil` MUST be rejected as
    `invalid_redirect_uri` (RFC 7591 SHOULD NOT, OAuth 2.1 §4.1.2
    MUST NOT).
  - Add: clamp test suite MUST cover 4 named userinfo-bypass shapes
    including IPv6+userinfo.
- **Regression test:** `internal/api/oidc/dcr/validate_test.go::TestValidateAndClampMetadata_R4_UserinfoBypassRejected`.
  Covers all 4 named bypass shapes. Failed pre-fix on at least 1
  shape (`https://victim.example.com:443@evil.com/cb` was fully
  accepted); passes all 4 post-fix.
- **Test commit:** `191a54d46`
- **Fix commit:** `ab233a8a2`
- **Pattern category:** `unspecified-parser-contract` — the kit was
  permissive about parsing semantics (a different shape from DE-001's
  `kit-internal-inconsistency`, where the kit was internally
  contradictory).
- **Notes:** This is the second P0 from /ck:check 2026-04-27. F-101
  (anti-enum dummy hash) is the next trace target. F-100 fix is
  isolated to validate.go + the test — no cross-package dependencies,
  no schema changes, no migration.

## Entry #4 — F-101 / inverted anti-enum timing oracle

- **Date:** 2026-04-27
- **Triggered by:** `/ck:revise --trace --from-finding F-101` after a
  `/ck:check` REJECT verdict (the second of two P0s; F-100 was
  resolved in entry #3).
- **Source finding:** `context/impl/impl-review-findings.md` F-101.
- **Classification:** `incomplete_criterion` — the anti-enum AC (added
  in entry #1's DE-001 amendment) named the right defence but didn't
  constrain the dummy hash provenance. T-038 implementer hardcoded a
  `$argon2id$` literal; production cmd/defaults.yaml ships
  `Algorithm: bcrypt` + empty `Verifiers`, so passwap returned
  `ErrNoVerifier` instantly on the dummy and inverted the timing
  oracle.
- **Vulnerability:** Not-found / parse-failure / cross-instance paths
  returned in microseconds while the wrong-random branch ran real
  bcrypt-cost-4 verify in milliseconds. Worse than no defence.
- **Kit:** `cavekit-iat.md` → R4 (single anti-enum AC replaced with
  three).
- **Amendment summary:**
  - AC1 — provenance: dummy MUST come from `secretHasher.Hash(sentinel)`
    at startup; hand-written hash literals FORBIDDEN.
  - AC2 — startup probe: wiring code MUST `Verify(dummy, "x")` once at
    boot and panic on `passwap.ErrNoVerifier`.
  - AC3 — real-Passwap timing test: N≥50 iterations through the live
    swapper, ratio mean-not-found / mean-wrong-random ∈ [0.5, 2.0].
    Stub-only tests don't satisfy AC3.
- **Regression test:** `internal/api/oidc/dcr/wire_test.go` — three
  tests: `TestBuildAntiEnumDummyHash_F101_PanicsOnErrNoVerifier` (probe
  panic), `TestBuildAntiEnumDummyHash_F101_HappyPath` (matched-algorithm
  Verify), `TestResolveIAT_F101_RealPasswapTimingEquivalence` (live
  bcrypt swapper, 50 iterations, ratio 1.012 in measured run). All
  fail to compile pre-fix (BuildAntiEnumDummyHash + new ResolveIAT
  signature don't exist); pass post-fix.
- **Test commit:** `168dc7531`
- **Fix commit:** `fa34caa56`
- **T-040 wiring scaffold delivered in same fix** — at user request,
  the F-101 fix included `dcr.RegistrationDeps`, `dcr.NewHandler(deps)`,
  `cmd/start/start.go` wiring (anti-enum dummy hash + queries adapter
  + clamp config adapter + anonymous config adapter), exported
  `Commands.SecretHasher()` accessor, exported `oidc.SupportedSigningAlgs()`,
  and adapter types `oidc.DCRClampAdapter` / `oidc.DCRAnonAdapter`.
  This closes F-102 (ResolveIAT was dead code) by giving it a real
  production caller. T-040 RegisterClient now plugs into the deps
  struct cleanly.
- **Pattern category:** `unspecified-parser-contract` — same family as
  F-100 (kit permissive about a specific provenance/derivation rule,
  implementer filled with ineffective artifact). With this entry the
  category counter reaches 2.

## Entry #5 — F-102 / ResolveIAT dead-code (no-op, audit only)

- **Date:** 2026-04-27
- **Triggered by:** `/ck:revise --trace --from-finding F-102`.
- **Source finding:** `context/impl/impl-review-findings.md` F-102.
- **Triage:** F-102 was already marked RESOLVED at trace time. The
  F-101 fix (entry #4 / commit `fa34caa56`) included the
  `dcr.RegistrationDeps` + `dcr.NewHandler(deps)` wiring scaffold and
  the `cmd/start/start.go` adapter glue that gave
  `dcr.BuildAntiEnumDummyHash`, `command.ParseIATPlaintext`, and
  `dcr.NewHandler` real production callers. `grep` confirms 4 live
  call sites in `cmd/start/start.go` lines 699 / 703 / 706 / 713.
  Additionally, the F-101 regression test
  `TestResolveIAT_F101_RealPasswapTimingEquivalence` exercises
  `ResolveIAT` through the live Passwap path, closing the original
  "F-101 cannot surface in any integration test" worry.
- **Classification:** N/A — no current failure.
- **Kit changes:** None. Logged for audit completeness so the
  `--trace` history reflects the user's full runtime path through
  the /ck:check P0/P1 list.
- **Pattern category:** `closed-by-bundled-fix` — F-102 was a
  derived finding (rather than an independent root cause): the
  natural fix scope for F-101 subsumed it.

## Entry #6 — F-103 / response_type whitespace-order sensitivity (RFC 6749 violation)

- **Date:** 2026-04-27
- **Triggered by:** `/ck:revise --trace --from-finding F-103` after the
  `/ck:check` REJECT verdict (the last P1 finding).
- **Source finding:** `context/impl/impl-review-findings.md` F-103.
- **Classification:** `incomplete_criterion` — R4's "intersected with
  DCR.AllowedResponseTypes" AC didn't pin equality semantics. T-034
  implementer used exact-string `slices.Contains`. RFC 6749 §3.1.1
  defines `response_type` values as space-separated SETS, so
  `"token id_token"` and `"id_token token"` must compare equal.
  Spec-compliant clients sending the non-canonical spelling got 400.
- **Vulnerability:** Spec violation, not security — but actively
  breaks Claude Code MCP and any client that defensively sorts its
  own response_type tokens.
- **Kit:** `cavekit-register-handler.md` → R4 (canonicalization AC
  added; existing intersection AC tightened to refer to it).
- **Amendment summary:** Both requested values and allow-list MUST
  run through `canonicaliseResponseType` (`strings.Fields` + sort +
  join with single space) before set-membership comparison. Canonical
  form mirrors `zitadel/oidc/v3.ResponseTypeIDToken = "id_token token"`
  upstream spelling so the rest of Zitadel's OIDC stack — which
  switches on those exact literals at
  `internal/api/oidc/auth_request_converter.go::ResponseTypeToBusiness` —
  sees consistent values. Output preserves the operator-blessed
  allow-list spelling.
- **Brownfield-vs-greenfield discussion (recorded for future
  reference):** before approving the proposal, the user asked whether
  this matched existing Zitadel patterns. Investigation found Zitadel
  already trusts the upstream library's canonical spelling and never
  tokenizes itself (auth_request_converter.go switches on literal
  upstream constants). The chosen Path A (canonicalize-on-input,
  then string-equal) matches that pattern; the alternative Path B
  (compare token sets at every comparison) would have introduced a
  second response_type comparison style. Path A is greenfield-correct
  AND brownfield-consistent.
- **Regression test:** `internal/api/oidc/dcr/validate_test.go::TestValidateAndClampMetadata_R4_F103_ResponseTypeSetSemantics`
  — 5 subtests covering non-canonical vs canonical match (both
  directions), extra whitespace canonicalisation, single-token
  unchanged, disallowed-token rejected even with whitespace
  permutation. 3 of 5 fail pre-fix; all 5 pass post-fix.
- **Test commit:** `8c7907404`
- **Fix commit:** `97c862836`
- **Pattern category:** `unspecified-parser-contract` — **THIRD**
  entry in this family (F-100 host parser, F-101 dummy hash, F-103
  set-equality semantics). Triggers the cross-kit amendment
  recommendation per protocol (see warning below).

⚠️⚠️⚠️ **CROSS-KIT AMENDMENT RECOMMENDATION TRIGGERED** ⚠️⚠️⚠️

The `unspecified-parser-contract` pattern has now landed three times
in this session. Shared root cause: kit ACs name a defensive
mechanism or matching rule without pinning HOW the comparison /
construction is computed. Implementers fill the gap with whatever
feels natural — string-cut for hosts, hardcoded literal for hashes,
exact-string equality for response_types — and the gap-fillers
consistently miss spec semantics or production-config interactions.

Recommended cross-kit amendment at the **cavekit-writing skill**
level (`.claude/plugins/local/cavekit-marketplace/ck/skills/cavekit-writing/SKILL.md`
or wherever the skill's authoring guidance lives): any AC that names
a parser, hasher, dummy artifact, comparison rule, or matching rule
MUST also pin:

  (a) the exact library / function used (e.g. `net/url.Parse`,
      `strings.Fields`, `secretHasher.Hash`)
  (b) the equivalence semantics — string-equal? set-equal?
      case-sensitive? whitespace-sensitive? Algorithm-bound?
  (c) a startup probe or invariant test that exercises the REAL
      dependency (not a stub) on a known-bad input — the failure
      mode that indicates misconfiguration

This would have caught all three: F-100 (kit would have specified
`net/url.Hostname()`, ruling out the userinfo-bypass parser); F-101
(kit would have specified `secretHasher.Hash` + ErrNoVerifier
probe); F-103 (kit would have specified `strings.Fields` +
canonical sort).

The cavekit-writing skill amendment is OUT OF SCOPE for this DCR
build but should be filed as a separate `/ck:revise --trace
--from-skill cavekit-writing` after the build closes. Logging here
so the recommendation isn't lost.

## Pattern category counts

| Category | Count |
|----------|-------|
| kit-internal-inconsistency | 1 |
| infrastructural-transient (no-op) | 1 |
| unspecified-parser-contract | **3** 🚨 cross-kit amendment recommendation triggered (see entry #6 warning) |
| closed-by-bundled-fix (no-op) | 1 |

⚠️ **Pattern observation:** two entries (F-100, F-101) in the same session share
`unspecified-parser-contract`. The shared root cause is kit ACs that name
a defensive mechanism without pinning its construction/algorithm/derivation
rule. Implementers fill the gap with whatever feels reasonable, which has
twice now produced an artifact that passes unit tests (built against
permissive interfaces or string-equality stubs) while failing the actual
security invariant against real production dependencies.

If a third `unspecified-parser-contract` entry lands, recommend a cross-kit
amendment at the cavekit-writing skill level: any AC mentioning a parser,
hasher, dummy artifact, or string-extraction rule MUST also pin (a) the
exact library/function used, (b) a startup probe or invariant test that
exercises the *real* dependency (not a stub), (c) the failure mode that
indicates misconfiguration. This would have caught both F-100 and F-101
at sketch time.

---

## Entry #7 — F-201 (`client_secret_expires_in` plumbing)
- **Date:** 2026-04-27
- **Trigger:** /ck:check Tier 3 close-out — inspector found dispatcher dropped `OIDC.DCR.ClientSecretExpiresIn`; every issued secret advertised `0` "no expiry" sentinel regardless of policy.
- **Classification:** `incomplete_criterion` (pattern: `unspecified-config-plumbing`).
- **Kit amendment:** cavekit-register-handler.md R7 — replaced the bare AC with full plumbing contract (command → dcr → response, single source of truth = `clientSecretExpiresAtFor`).
- **Regression test:** `internal/api/oidc/dcr/dispatcher_test.go::TestDispatch_R7_F201_ClientSecretExpiresAt_PlumbedFromConfig` (sets lifetime=24h, asserts response field = ClientIDIssuedAt + 24h).
- **Test commit:** included in fix commit (single commit because both ship same field-add).
- **Fix commit:** `3751a0eaa`.

## Entry #8 — F-218 (redirect URI scheme allow-list)
- **Date:** 2026-04-27
- **Trigger:** /ck:check Tier 3 close-out — security audit found `javascript:` / `data:` / `file:` URIs accepted for `application_type=native`; XSS-distribution channel.
- **Classification:** `missing_criterion` (pattern: `unspecified-parser-contract` — **4th in this loop**, second redirect-URI-related kit gap after F-100).
- **Kit amendment:** cavekit-register-handler.md R4 — added 3 ACs: scheme allow-list (`http`/`https` + reverse-domain native), hard-rejected scheme set, scheme-bypass test coverage requirement (≥5 reject + 1 accept + 1 no-dot reject).
- **Regression test:** `internal/api/oidc/dcr/validate_test.go::TestValidateAndClampMetadata_R4_F218_RedirectURISchemeAllowList` (5 hard-reject shapes × 2 app types + 1 native+custom-scheme accept + 1 no-dot reject + 1 web+custom reject).
- **Fix commit:** `dd9c395f8`.

## Entry #9 — F-203 (v2 refresh path narrowing gap)
- **Date:** 2026-04-27
- **Trigger:** /ck:check Tier 3 close-out — inspector found only `refreshTokenV1` was wired through `narrowAudienceByTokenResources`; the primary `RefreshToken` v2 path silently broadcast original session.Audience.
- **Classification:** `missing_criterion` (pattern: `ambiguous-handler-scope` — kit said "the refresh-token handler" without distinguishing v1 vs v2).
- **Kit amendment:** cavekit-rfc8707-resource.md R5 — replaced AC2 with explicit "BOTH refresh-token paths" requirement + test-coverage clause.
- **Regression test:** `internal/api/oidc/rfc8707_token_test.go::TestF203_V2RefreshPathWiredToNarrow` (source-string inspection of v2 branch).
- **Fix commit:** `77a09426a`.

## Entry #10 — F-200 (IAT slot never consumed)
- **Date:** 2026-04-27
- **Trigger:** /ck:check Tier 3 close-out — inspector found `grep -rn ConsumeInitialAccessToken internal/api/oidc/ internal/command/dynamic_client_registration.go` returned ZERO call sites. The R2 race-safety harness, per-slot UniqueConstraint, and Errors.DCR.IAT.Exhausted error path were all dead code in production.
- **Classification:** `missing_criterion` (pattern: `unspecified-handler-contract` — same shape as F-101, kit AC described consumption in plain English but didn't pin which layer owns the call).
- **Kit amendment:** cavekit-register-handler.md R6 — added "dispatcher MUST consume slot before registration push" AC + integration-test pin.
- **Regression test:** `internal/api/oidc/dcr/dispatcher_test.go::TestDispatch_R6_F200_IAT_ConsumeFailure_Returns401` (source-inspection of dispatcher consume call site + Validate-without-ConsumeIAT panic + anonymous-mode-skips assertion).
- **Fix commit:** `cfd940f54`. Added `RegistrationDeps.ConsumeIAT` + `Validate()` enforcement + dispatcher integration + start.go closure bridging to `commands.ConsumeInitialAccessToken`.

## Entry #11 — F-217 (mount middleware stack)
- **Date:** 2026-04-27
- **Trigger:** /ck:check Tier 3 close-out — security audit found DCR + AS metadata handlers mounted bare via `apis.RegisterHandlerOnPrefix` without `instanceInterceptor` or `limitingAccessInterceptor`. `authz.GetInstance(ctx)` returns emptyInstance → `featureGateMiddleware` always reads feature-flag false → endpoint unreachable in default config OR cross-tenant write if any host-routing layer side-steps the gate.
- **Classification:** `missing_requirement` (pattern: `unspecified-mount-contract` — no AC required the standard interceptor stack).
- **Kit amendment:** cavekit-register-handler.md R1 — added 2 ACs: mount-middleware contract + mount-stack regression test requirement.
- **Regression test:** `cmd/start/dcr_mount_test.go::TestDCRMount_F217_HasInterceptorStack` (source-string inspection of start.go for both wrap chains; defensive assertions that no bare-mount calls remain).
- **Fix commit:** `2df7245c9`.

---

## Pattern category summary (cumulative across all 11 entries)
| Category | Count |
|----------|-------|
| unspecified-parser-contract | **4** 🚨 cross-kit amendment STILL recommended (F-100, F-101, F-103, F-218) |
| unspecified-handler-contract | **2** 🚨 (F-101 dummy hash provenance, F-200 IAT consume) — emerging pattern |
| unspecified-config-plumbing | 1 (F-201) |
| ambiguous-handler-scope | 1 (F-203) |
| unspecified-mount-contract | 1 (F-217) |
| kit-internal-inconsistency | 1 (DE-001) |
| infrastructural-transient (no-op) | 1 (F-102) |
| closed-by-bundled-fix (no-op) | 1 |

⚠️ **Two patterns at the cross-kit amendment threshold:**
1. `unspecified-parser-contract` (4 entries) — already triggered the recommendation at entry #6. Still untriggered amendment.
2. `unspecified-handler-contract` (2 entries) — emerging. F-101 (dummy hash provenance) and F-200 (IAT consume call site) both shipped because the kit AC described a defensive mechanism in plain English without pinning which layer/file/function owns the call. If a third entry lands, escalate to a cavekit-writing skill amendment: every AC mentioning a defensive call (consume / verify / hash / log-redact) MUST also name (a) the producer interface and (b) the consumer call site.

Recommend running `/ck:design` (or a dedicated cavekit-writing skill amendment) to address both meta-patterns before the next sketch cycle.
