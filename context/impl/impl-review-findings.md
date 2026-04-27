---
created: "2026-04-24T13:30:00Z"
last_edited: "2026-04-27T00:00:00Z"
---
# Codex Peer Review — Tier 0 Findings

Build site: context/plans/build-site.md
Tier: 0
Base ref: cc74a36b6 (pre-tier-0 main HEAD)
Reviewer: Codex gpt-5-codex
Review date: 2026-04-24

## Findings

| ID | Severity | File | Line | Description | Status |
|----|----------|------|------|-------------|--------|
| F-001 | P1 | internal/api/oidc/token_exchange.go | 44 | T-004 removed the `resource`-parameter rejection from `/token` token-exchange but the remainder of RFC 8707 (audience plumbing via T-014/T-027/T-045, allow-list validation via T-026) has not landed yet. Today a request with `resource=...` succeeds and mints a token whose `aud` claim never reflects the supplied resource — this is worse than the prior explicit `invalid_target` rejection per RFC 8707 §2 (AS should return `invalid_target` when it cannot honor the resource). Either keep rejecting until T-026/T-027/T-045 land, or accelerate the propagation pipeline so there is never a gap. | RESOLVED-AUTHORIZE / OPEN-TOKEN |

## Resolution status (2026-04-26)

**/authorize path: CLOSED.** Tier 2 cluster T-026 + T-027 + T-028 (commits 3124fd94a, 2591cb012) shipped together as the F-001 closer per Option B. The /authorize sidecar now validates `resource` against `AllowedAudiences` and rejects out-of-list values with the RFC 8707 §2 `invalid_target` 400 envelope BEFORE the request reaches the auth-request creation path; in-list values are merged into `OIDCSession.Audience` and surface in the issued access-token `aud` claim.

**/token path: still open until T-045 (Tier 3).** The 6 token grant handlers (token_code, refresh, client_credentials, device, exchange, jwt_profile) do not yet call `ValidateResources` or `writeInvalidTargetError`; the helpers and the typed `IsInvalidTargetError` predicate are in place so T-045 is a one-liner per handler. Until T-045 lands, a /token request with `resource=...` still mints a token whose `aud` does not reflect the resource — same behavior as before the cluster, but now device-flow tokens DO get the merge because device-auth shares the `/authorize` sidecar pre-validation entry.

Recommend marking F-001 as RESOLVED only after T-045 + T-046 close /token coverage.

## Recommended remediation

Option A (revert + sequence): revert T-004 and land it together with T-026 at Tier 2 so the parameter is only accepted once the allow-list gate exists, then wire propagation at T-027/T-045.

Option B (accelerate): land T-026/T-027 (Tier 2) in the same tier cadence as T-004, i.e., bundle the gate + propagation so acceptance and enforcement ship together. T-045 (Tier 3) can follow separately since it only extends existing behavior to more grants.

Option C (interim gate): replace the removed rejection with a narrower interim rejection that (a) rejects syntactically invalid URIs with `invalid_target`, (b) accepts valid URIs but continues to omit them from `aud` until T-027 lands, and (c) ships a CHANGELOG / release-note warning flagging the interim gap.

Recommendation: **Option B** — bundling T-004 with T-026/T-027 into a single coherent change preserves RFC 8707 contract semantics at all tier boundaries. The build-site ordering that placed T-004 in Tier 0 and T-027 in Tier 2 introduces an unnecessary correctness gap across tier commits.

Decision owner: human (user). Waiting on direction before revert or bundling.

## Update (2026-04-24, post-T-013 code-ready)

T-013 (upstream `github.com/zitadel/oidc` PR) is now code-complete on
`../oidc` branch `feat/authrequest-resource-rfc8707`. Once that PR
merges and Zitadel bumps the dep past the merge SHA, `r.Data.Resource`
will be available on `AuthRequest` in the `/authorize` path, so T-014
can wire propagation directly — no sidecar needed. This adds a new
remediation option:

- **Option D (new)**: land the upstream PR first, bump the dep, then
  land T-014+T-026+T-027+T-045 in a single coherent PR that closes
  the F-001 window. T-004 stays as-is because the next-tier code path
  uses the accepted `resource` value. This is the cleanest outcome
  when the upstream merge has a short SLA.

Preferred path depends on upstream merge timeline. Short SLA →
Option D; long SLA → Option B (bundle T-004+T-026+T-027 in Tier 2
with the interim sidecar from T-012).

---

# /ck:check Findings — 2026-04-27 (Tier 0–3 mid-build review)

Build site: context/plans/build-site.md
Tier reviewed: 0–3 (38 of 86 tasks DONE)
Base ref: 3220f3d9a (pre-Tier-2 main)
Reviewer: ck:inspector (opus) + ck:surveyor (opus) + ck:verifier (opus)
Review date: 2026-04-27

## Findings

| ID | Severity | File | Line | Description | Status |
|----|----------|------|------|-------------|--------|
| F-100 | **P0** | internal/api/oidc/dcr/validate.go | 297-317 (extractHost) + 284-295 (matchesAnyHostPattern) | `AllowedRedirectURIHostPatterns` bypass via URL userinfo. extractHost cuts on `://`, `/`, `?`, `#` then splits port on `:` but never strips the RFC 3986 userinfo segment before `@`. URL `https://app.example.com:8080@evil.com/cb` parses to host=`app.example.com` and matches `*.example.com`; real host is `evil.com`. **Authorization-code exfiltration** — attacker registers a client with attacker-controlled DNS, defeats the host allow-list, steals codes via the malicious redirect. validate_test.go covers wildcards/IPv6/exact match but ZERO userinfo-bearing URLs. Reveals **kit gap** in cavekit-register-handler.md R4 — host-extraction algorithm unpinned. | RESOLVED 2026-04-27 (kit ae of cavekit-register-handler.md R4 + fix in dcr/validate.go: `net/url.Parse` + `u.Hostname()` + reject `u.User != nil`; 4 bypass shapes pinned by TestValidateAndClampMetadata_R4_UserinfoBypassRejected) |
| F-101 | **P0** | internal/api/oidc/dcr/auth.go | 178 (dummyPassWapHash) + internal/command/iat.go:328-343 (VerifyIATPlaintext) + cmd/defaults.yaml:984-998 | Anti-enumeration dummy hash defeats itself — **INVERTED timing oracle**. dummyPassWapHash hardcoded as `$argon2id$v=19$m=65536,t=2,p=1$...` but cmd/defaults.yaml ships `Algorithm: bcrypt` with empty `Verifiers` list. passwap.Swapper.Verify on `$argon2id$`-encoded string returns ErrNoVerifier immediately — zero crypto work. Real bcrypt-cost-4 verify takes ~5ms; dummy returns in microseconds. not-found / malformed / cross-instance paths now MEASURABLY FASTER than wrong-random — *inverted* oracle, **worse than no defence**. auth_test.go stubVerifier short-circuits on `encoded == s.matchHash` so unit tests never decode the dummy. Reveals **kit gap** in cavekit-iat.md R4 anti-enum AC — dummy hash is unspecified relative to the configured hasher. | RESOLVED 2026-04-27 (kit amendment splits AC into 3: provenance + startup probe + real-Passwap timing test; fix introduces `dcr.BuildAntiEnumDummyHash` + `dcr.RegistrationDeps` + `dcr.NewHandler` wiring scaffold; start.go now constructs deps from configured secretHasher with ErrNoVerifier panic probe; ResolveIAT signature takes dummy hash via parameter not package literal; F-102 dead-code closed by the wiring) |
| F-102 | P1 | internal/api/oidc/dcr/auth.go | 198-257 (ResolveIAT) | T-037 production path is dead code. `grep -rn "ResolveIAT\|ParseIATPlaintext"` finds zero non-test callers. T-040 dispatcher (consumer) still pending. Kit edit + tests claim "T-037 lands in full" but no production code reaches the function — F-101 cannot surface in any integration test because nothing reaches ResolveIAT. T-037 should be downgraded from DONE to PARTIAL until T-040 lands the wiring. F-101 fix (move dummy-hash construction to wiring site) addresses both. | RESOLVED 2026-04-27 (the F-101 fix landed `dcr.NewHandler(deps)` constructor wired from `cmd/start/start.go`; `BuildAntiEnumDummyHash(commands.SecretHasher())` now has a real production caller. T-040 will fill in the actual handler bodies that invoke ResolveIAT — the deps + scaffolding are ready) |
| F-103 | P1 | internal/api/oidc/dcr/validate.go:104 + internal/domain/application_oidc.go (rfc7591ResponseTypes) | response_types clamp is whitespace-order-sensitive. RFC 6749 §3.1.1 defines value as a **space-separated SET** — `"token id_token"` MUST equal `"id_token token"`. Clamp does exact `slices.Contains`; domain mapper switches on literal string. Spec-compliant clients sending `"token id_token"` get 400. Reveals kit gap in cavekit-register-handler.md R2 + R4 (response_types semantics not spec'd). | RESOLVED 2026-04-27 (kit AC adds canonicalization: tokens split on whitespace + sorted alphabetically + joined; mirrors zitadel/oidc/v3 canonical spelling so no inconsistency w/ existing OIDC stack. Fix adds `canonicaliseResponseType` + `intersectResponseTypes`; allow-list spelling preserved on output. 5 subtests P incl. non-canonical-vs-canonical, extra-whitespace, single-token, disallowed-rejected) |
| F-104 | P2 | internal/api/grpc/admin/iat.go:93-108 + internal/query/initial_access_tokens_search.sql | ListInitialAccessTokens lying API contract — proto declares ListQuery + ListDetails; impl ignores both. SQL has no LIMIT/OFFSET; ListDetails never populated. Trim proto or implement pagination. cavekit-iat.md R6 + impl drifted. | NEW |
| F-105 | P2 | apps/api/test-integration-api.yaml + context/impl/impl-config.md (T-048) | Anonymous-mode integration coverage silently deferred. T-048 sets `RequireInitialAccessToken=true`, gating AC4/AC5 anonymous resolution to unit-test only. No follow-up task tracks this. Add an integration-fixture variant with anonymous mode + DefaultProjectID/DefaultOrgID set via instance-feature commands. | NEW |
| F-106 | P3 | internal/query/projection/initial_access_token.go:170 + internal/query/initial_access_token.go:37 | consumed_slots SMALLINT[] silently overflows at use_index 32768 on finite=true tokens with very high max_uses. Document a kit-level cap on max_uses ≤ 32767, OR migrate column to INT[]. Inspector flagged this in Tier 2 review; restated. | OPEN |

## Verdict

**REJECT** — 2 P0 findings block forward progress. T-040 (RegisterClient keystone) MUST NOT land until F-100 + F-101 are routed through `/ck:revise --trace --from-finding F-100` / `F-101`. Both reveal kit gaps that need backprop, not just code fixes.

## Recommended next actions

1. **Route F-100 and F-101 through `/ck:revise --trace`** — both reveal kit gaps requiring user-approved kit amendments before code fixes. F-100 amends cavekit-register-handler.md R4 to pin the host-extraction algorithm (use net/url + reject userinfo). F-101 amends cavekit-iat.md R4 to require the dummy hash come from the same hasher instance + adds a startup probe AC.
2. **Bundle F-102 into F-101 fix** — moving dummy-hash construction to a wiring-site initialization call also gives ResolveIAT a real production caller as soon as T-040 ships.
3. **Defer F-103 / F-104 / F-105 / F-106** — log + revisit at next /ck:check boundary; not blocking.
4. **Downgrade T-037 status** — flip from DONE to PARTIAL in `context/impl/impl-register-handler.md` until T-040 wiring lands.
