---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-26T20:30:00Z"
---
# Loop Log — DCR Build Site

Build site: context/plans/build-site.md

### Iteration 1 — 2026-04-24
- T-001: OIDC.DCR yaml block — DONE. Files: cmd/defaults.yaml. Build P (yaml-parse), Tests N/A. Next: T-002
- T-002: KeyDynamicClientRegistration=17 + Features field + enumer — DONE. Files: internal/feature/feature.go, internal/feature/key_enumer.go. Build P, Tests P (`go test ./internal/feature/...`). Next: T-003

### Iteration 2 — 2026-04-24 (Tier-0 close-out)
- T-003: CORS reuse inspection — DONE. Artifact: m0-cors-reuse-t003.md. No new CORS config. Next: T-004
- T-004: token_exchange resource-param rejection removed — DONE. Files: internal/api/oidc/token_exchange.go. Kit ref to existing test was stale (file not present); new coverage lands in T-046. Next: T-005
- T-005: M5 AuthRequest.Resource decision — DONE. Grep confirmed zitadel/oidc v3.47.5 lacks Resource field → sidecar path (b). Artifact: m5-authrequest-resource-decision-t005.md. T-013 (upstream PR) flagged as human-owned. Next: T-006
- T-006: M0 log-redaction survey — DONE. Artifact: m0-log-redaction-survey-t006.md. HTTP + gRPC middleware log NO bodies; AccessLog already redacts Authorization/cookie. T-061 defensive wrappers still required. Next: T-007
- T-007: M4 DELETE-revocation path decision — DONE. Path (a) RevokeApplicationTokens selected; RFC 7592 §4 REQUIRES language + existing event-sourcing primitives justify it. Artifact: m4-token-revocation-decision-t007.md. Next: (Tier-0 complete — stopping for user review per user option #1)

Tier 0 summary: 7/7 DONE (T-001..T-007). Stopping at tier boundary.
- Human-owned carryover: T-069 (confirm console UI placement), T-075 (open 19 locale tickets) — flag these when resuming Tier 1+.
- T-013 previously human-owned — now CODE READY on `../oidc` branch `feat/authrequest-resource-rfc8707` (commit 1a138e7). Remaining human action: push branch + open upstream PR.

### Iteration 7 — 2026-04-26 (Tier 2 — full wave complete, 15/17 done)
- T-029 (8d41f0fbe): discovery registration_endpoint dual-gated. Files: server.go (Server.dcrEnabled + dcrAdvertised + registrationEndpointURL), dcr/handler.go (HandlerPrefix const), op.go, start.go, dcr_discovery_test.go. 9 subtests P incl. NeverNullInJSON.
- T-030 (ba0c31155): RFC 8414 AS metadata at /.well-known/oauth-authorization-server. Files: as_metadata/handler.go (Metadata struct + NewHandler + issuerWarner), Server.AsMetadata builder, start.go mount. 4 test groups P. R3 cross-doc byte-identity deferred to T-047.
- T-031 (593eda666): DCR mux router with POST/GET/PUT/DELETE method-aware routing. Files: dcr/handler.go (gorilla mux + featureGateMiddleware + 4 stubs). 7+6 subtests P incl. gate-overrides-routing.
- T-019 (78b8f520a): projections.initial_access_tokens table + 3 reducers. Files: projection/initial_access_token.go + test (6 subtests P). Schema deviations: SMALLINT[] for consumed_slots (no INT[] in framework), BIGINT for max_uses/uses_consumed.
- T-020 (c53263536): IAT query helpers ByID + ByHash with go:embed SQL. Files: query/initial_access_token.go + 2 SQL files + test (6 subtests P via sqlmock).
- T-021 (52210faa4): IAT plaintext format (zdiat_ + 48-byte b64url) + Passwap hashing + CreateInitialAccessToken + VerifyIATPlaintext commands. Files: command/iat.go + test (3 tests + prefix-collision guard P). M1 grep clean.
- T-017 (1f82fb621): race-safe ConsumeInitialAccessToken with 3-retry loop + RevokeInitialAccessToken. Files: command/iat.go (IATSnapshot + IATLookup + Consume + Revoke) + iat_consume_test.go (9 subtests P).
- T-018 (659a2d853): dcr_iat_concurrency_test.go via fake Pusher simulating UniqueConstraint. 3 scenarios (10/3, 4/4, 5/4) clean for -race -count=1000.
- T-022 (ba59f8a10): admin.proto Create/List/Revoke RPCs + InitialAccessTokenView msg + Initial Access Tokens swagger tag. Generated stubs build clean.
- T-023+T-024 (9bd0320fc): admin gRPC handler bodies + dual-gate (yaml off → UNIMPLEMENTED, runtime flag off → FAILED_PRECONDITION). Files: admin/iat.go + admin/server.go (dcrYAMLEnabled field) + start.go wiring. 7 subtests P pinning gate matrix.
- T-025: serialization-characteristic godoc already in T-017 ConsumeInitialAccessToken + T-021 CreateInitialAccessToken docstrings. Verified verbatim phrase present.
- Tier 2 status: 15/17 done. Remaining: T-032 (shared dcr/errors.go + validate.go skeleton — Tier 2, blocks Tier 3 register-handler bodies). T-018-related projection-lag test (T-060) is Tier 5 not Tier 2.
- Build P (`go build ./cmd/... ./internal/... ./pkg/...` clean). Tests P across all touched packages.

### Iteration 6 — 2026-04-26 (Tier 2 — F-001 closer cluster, 3/17 done)
- T-026: AllowedAudiences allow-list — DONE. Files: rfc8707_validate.go, rfc8707_sidecar.go, op.go. ValidateResources + factory NewAuthorizeResourceSidecar(allowed). 12+6+1 subtests P. Build P, Tests P.
- T-028: invalid_target envelope — DONE. Bundled w/ T-026 (same file). writeInvalidTargetError + 3 envelope subtests P. /token wiring deferred to T-045.
- T-027: resources → audience merge — DONE. Files: auth_request.go, device_auth.go, rfc8707_audience_test.go. createAuthRequestScopeAndAudience signature gains resources; mergeResourcesIntoAudience helper. 3 callers wired (V1, V2, device-auth). 8 subtests P.
- F-001 status: RESOLVED on /authorize path. Open on /token until T-045 lands the per-grant validate+propagate.
- Stop point: F-001 closer cluster complete per user instruction. Awaiting confirmation before destructive event-schema work (T-019 projection table) or further Tier 2.

### Iteration 5 — 2026-04-26 (Tier 1 close-out — 9/9 done)
- T-014b: V2 login resource threading. `Resources` added to authrequest.AddedEvent (additive json:omitempty), command.AuthRequest, write model, reduce, conversion. WithResources fluent setter keeps the 25+ existing positional NewAddedEvent test call sites stable. 6 subtests green incl. back-compat unmarshal.
- T-008: dual-gate handler mount. dcr/handler.go stub returns 403 `feature_disabled` when runtime flag off, 200 stub when on; cmd/start/start.go conditionally mounts /oidc/v1/register before oidcPrefixes when yaml Enabled=true. 4 subtests green.
- T-015: SSRF-guarded JWKS fetcher. Full deny matrix (RFC 1918 / loopback / link-local incl. 169.254.169.254 / IPv6 ULA + link-local + loopback), DNS-rebind defense (single resolve per hop, pinned dialer), 3-hop redirect cap with per-hop re-validation, 1 MiB body cap, scheme guard, AllowLoopbackInDev override.
- T-016: 24 jwks_fetcher subtests covering deny matrix + redirect chains (3 OK / 4 refused) + redirect-trap to private IP + body cap (oversized + exact-at-limit) + literal-IP rejection + happy path. All green. dcr_ssrf_test.go integration test deferred to land alongside T-031/T-057 when the live register handler exists.
- T-011: IAT events on project aggregate. Added/Consumed/Revoked event types + factories + mappers + RegisterFilterEventMapper. Per-slot UniqueConstraint `iat_uses:<id>:<use_index>` for finite max_uses; nil constraint when max_uses=0. 9 subtests green incl. wire-type pin, finite-vs-unbounded constraint matrix, distinct-IAT-distinct-slot.
- Kit update: cavekit-discovery-and-as-metadata.md R4 absorbed runtime issuer-path warning (option ii from session Q3) — runtime check lives in T-030 handler where per-request issuer is available.
- Build site: T-014b inserted into Tier 1 (effort S, blocked by T-012 + T-014).
- Tier 1 status: 9/9 (or 10/10 incl T-014b). All builds and targeted tests green. F-001 still OPEN — ships when T-026/T-027 land in Tier 2.

### Iteration 4 — 2026-04-24 (Tier 1 — 4/9 done)
- Pre-flight: Fixed "missing generated proto packages" tree-gap. They are gitignored; `nx run @zitadel/api:generate-stubs generate-assets generate-statik` regenerates. `go build ./cmd/... ./internal/... ./pkg/...` clean. `backend/main.go` has a pre-existing commented-out `main()` making `go build ./...` fail — same at cc74a36b6, not caused by this work.
- T-009: DONE — DCRConfig.Validate startup refuse on empty defaults in anonymous mode. 7 subtests green.
- T-010: DONE (with R5 deviation doc) — WARN on ExternalDomain-with-slash. Kit's "issuer=URL" assumption doesn't match Zitadel's hostname-only ExternalDomain; runtime check lands with T-029/T-030. 5 subtests green.
- T-012: DONE — RFC 8707 sidecar (context key + middleware + accessors). Installed in OIDC HTTP chain. 9 subtests green.
- T-014: DONE (V1 only) — domain.AuthRequest.Resources + converter wire-through. V2 login path (command.AuthRequest via authrequest.AddedEvent) is out-of-scope; needs event-schema work. Flagged.
- Codex review (reminder): F-001 still OPEN — the T-004 accept-without-validation window remains until T-026/T-027 land. Tier 2 closure plan: bundle T-026/T-027 so `/authorize` resource flow ships correct; T-045 fills token-exchange `aud` at Tier 3.

### Iteration 3 — 2026-04-24 (cross-repo pivot: upstream oidc library)
- Scope expansion: user scoped ../oidc into the build. Ran minimal ck:init + targeted research on pkg/oidc/authorization.go + pkg/op/auth_request.go.
- New cavekit at ../oidc/context/kits/cavekit-authrequest-resource.md (R1..R5, 5 tasks all Small).
- New build-site at ../oidc/context/plans/build-site.md (O-001..O-005, 3 tiers).
- Executed full 5-task build:
  - O-001: AuthRequest.Resource field + json/schema tags — DONE (pkg/oidc/authorization.go).
  - O-002: CopyRequestObjectToAuthRequest carries Resource — DONE (pkg/op/auth_request.go).
  - O-003: TestAuthRequest_DecodeResource (absent/single/multiple) — DONE, green.
  - O-004: TestCopyRequestObjectToAuthRequest_Resource (copy/leave-existing) — DONE, green.
  - O-005: go build ./... + go test ./... green; struct-literal audit clean.
- Tier-0 codex peer review finding F-001 updated: Option D added (land upstream PR → bump dep → wire propagation).

### Iteration 8 — 2026-04-26 (Tier 2 close-out — T-032)
- T-032: DONE. Files: internal/api/oidc/dcr/errors.go (new — ErrorEnvelope + WriteError + 8 RFC 7591 code consts + DCR-<5alpha> zerrors prefix doc), internal/api/oidc/dcr/validate.go (new — doc-only skeleton announcing ValidateAndClampMetadata + ApplyDefaultsRFC7591 + CheckRedirectURIs API for T-033/T-034/T-054), internal/api/oidc/dcr/handler.go (refactor — consume shared writer + error-code consts; private errorEnvelope/writeError removed). Build P, Tests P (`go test ./internal/api/oidc/dcr/...` 0.008s — 17 subtests still green).
- Tier 2 status: 16/16 DONE. Frontier next wave: T-033 / T-034 / T-037 / T-038 / T-045 / T-047 / T-048 (Tier 3 register + manage handler bodies + AS-metadata cross-doc test).

### Iteration 9 — 2026-04-26 (Tier 3 entry — T-048)
- T-048: DONE (with kit-path drift). Files: apps/api/test-integration-api.yaml (added OIDC.DCR.{Enabled: true, RequireInitialAccessToken: true}). **Drift:** kit R7 AC1 named internal/integration/config/client.yaml — that struct has no OIDC tree. Actual integration server config is apps/api/test-integration-api.yaml. AC2 (DefaultProjectID/OrgID) intentionally unset — instance default org is dynamic; integration runs IAT-only. AC3 (TestInstance_BasicLoadsConfig) — test does not exist in tree. yaml syntax validated via python yaml.safe_load.
- Build P (yaml only). Tests N/A (no code changes).
- Tier 3 frontier: T-033 / T-034 / T-037 / T-038 / T-044 / T-045 / T-047 / T-049 still ready.

### Iteration 10 — 2026-04-26 (Tier 3 — T-047)
- T-047: DONE. Files: internal/api/oidc/dcr_discovery_test.go (+128 lines: TestDiscoveryAndAsMetadata_R3_SharedFieldsByteIdentical + TestDiscoveryAndAsMetadata_R3_BothOmitRegistrationWhenDisabled + newServerFixtureForR3 helper). Builds both docs from single Server fixture; asserts struct-field equality + JSON-RawMessage byte-identity on issuer/authorization_endpoint/token_endpoint/jwks_uri/registration_endpoint; full disabled-matrix verifies key-absent (no `"registration_endpoint": null`). Build P, Tests P (5 new subtests).

### Iteration 11 — 2026-04-26 (Tier 3 — T-044)
- T-044: DONE (AC3 deferred to T-079). Files: internal/api/oidc/dcr_config_test.go (+TestDCRConfig_NoTLSKnobs_R10 reflection scan), context/impl/m_t044_tls_posture_inspection.md (new artifact). AC1 (same TLS as /oidc/v1/userinfo) verified structurally via shared apis server in start.go. AC2 (no DCR-specific TLS knobs) pinned by reflection test rejecting TLS/Cert/HTTPS/Insecure/MTLS field names on DCRConfig + DCRJwksURIConfig. AC3 (deployment-guide TLS-termination note) deferred to T-079 doc task. Build P, Tests P.
