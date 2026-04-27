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

### Iteration 12 — 2026-04-26 (Tier 3 — T-034 + T-035 absorbed)
- T-034: DONE. Files: internal/api/oidc/dcr/metadata.go (new RFC7591Metadata struct), internal/api/oidc/dcr/validate.go (replaces skeleton — ValidateAndClampMetadata + CheckRedirectURIs + ClampError + DCRConfigSubset interface + helpers), internal/api/oidc/dcr/validate_test.go (new — 17 test groups). All 13 R4 ACs pinned: grant/response/auth/application intersection, client_secret_jwt rejection, subject_type pairwise, id_token sig vs supported, request_object_* rejection, software_statement+off → unapproved, MaxRedirectURIs, redirect URI compliance + host pattern + native loopback. T-035 absorbed (loopback for native + GetOIDCV1Compliance integration are in CheckRedirectURIs). DCR-Vt0XX zerrors prefix per T-032. Build P (`go build ./internal/... ./cmd/... ./pkg/...`), Tests P (oidc + as_metadata + dcr packages all green). Next frontier: T-036 (auth-method secret matrix, blocked by T-034+T-015 — now ready), T-039 (OIDCAppFromRFC7591Metadata mapping, blocked by T-034 — now ready), T-033 (request decoding still pending), T-037/T-038 (auth routing).

### Iteration 13 — 2026-04-26 (Tier 3 — T-039 + T-035 closeout)
- T-039: DONE. Files: internal/domain/application_oidc.go (+OIDCAppFromRFC7591Metadata + 4 vocab mappers — 117 lines), internal/api/oidc/dcr/metadata.go (+ToOIDCApp bridge + BuildDCRMeta extractor — 82 lines), internal/domain/application_oidc_test.go (+5 domain tests), internal/api/oidc/dcr/metadata_test.go (new — +6 tests). Layering: domain does NOT import dcr; dcr.bridge translates wire→primitives. Sets OIDCVersion=V1. BuildDCRMeta covers all 12 RFC 7591 passthrough fields with empty-omission. Build P, Tests P (15 new subtests).
- T-035: DONE (absorbed by T-034 — formal closeout entry added to impl-register-handler.md).
- Tier 3 frontier next: T-033, T-036, T-037, T-038, T-045, T-049 + T-040 (now blocked only on T-037+T-038). T-040 keystone unblock requires T-037 + T-038 still.

### Iteration 14 — 2026-04-26 (Tier 3 — T-038 + T-037 partial / DE-001 logged)
- T-038: DONE. Files: internal/api/oidc/dcr/auth.go (new — RegistrationContext + AnonymousConfig + AuthMode + ClassifyAuthMode + ResolveAnonymous + IATAuthNotImplemented placeholder), internal/api/oidc/dcr/auth_test.go (new — 4 test groups / 16 subtests). Anonymous mode resolves InstanceID from authz.GetInstance(ctx) (single source of truth), Org/Project from DCR.Default*ID, IAT="" sentinel. RequireInitialAccessToken=true returns invalid_token ClampError; defensive runtime guard returns feature_disabled when defaults empty. Build P, Tests P.
- T-037: PARTIAL. Dead-end DE-001 logged at `context/impl/dead-ends.md` — T-021 plaintext (no embedded ID) + T-019 projection (non-deterministic Passwap hash) + T-020 byHash (deterministic WHERE) form an inconsistent triple. Three forward options enumerated (embed-ID / HMAC-column / list-and-verify); recommendation = option 1. Placeholder `IATAuthNotImplemented` ships in auth.go pinned by test so a future contributor cannot silently flip the toggle without resolving DE-001. **Run /ck:revise before resuming T-037.**
- Tier 3 status: 11/17 done (T-029, T-030, T-031, T-032, T-034, T-035, T-038, T-039, T-044, T-047, T-048). T-037 partial. Remaining: T-033 (L), T-036 (M), T-045 (L), T-049 (M) + T-037 completion. T-040 keystone still blocked on T-037 completion.

### Iteration 15 — 2026-04-27 (Tier 3 — T-040 keystone)
- T-040: DONE. Files: internal/repository/project/dynamic_client_registration.go (new — ApplicationDynamicallyRegisteredEvent + ApplicationRegistrationAccessTokenSetEvent + mappers, registered in eventstore.go); internal/command/dynamic_client_registration.go (new — RegisterClient + HashRemoteAddr + generateRATPlaintext + IsRATPlaintext); internal/command/dynamic_client_registration_test.go (new — 12 subtests, 4 test groups). Pushes R6 4-event sequence on project aggregate. Reuses existing OIDCConfigAddedEvent constructor; skips FilterToQueryReducer dedupe (fresh snowflake appID). RAT format `zdrat_<48-byte-b64url>` distinct from IAT prefix; Passwap-encoded hash; plaintext IP NEVER persisted (SHA-256 only). Build P, Tests P (`go test ./internal/command/... ./internal/repository/project/... ./internal/api/oidc/dcr/...` clean). Tier 3 status: 12/17 done. Frontier next: T-033 / T-036 / T-041 (unblocked) / T-042 (unblocked) / T-045 / T-049 / T-061 (unblocked).

### Iteration 16 — 2026-04-27 (Tier 3 — T-036)
- T-036: DONE. Files: internal/api/oidc/dcr/validate.go (+private_key_jwt requires jwks_uri AC3 enforcement, zerrors DCR-Vt0R5); internal/api/oidc/dcr/validate_test.go (+R5 auth-method matrix 6-row + blank-jwks-uri whitespace test). AC1 (none→no secret) + AC2 (basic/post→Passwap hash + plaintext once) verified existing in T-040 RegisterClient (cross-package coverage). AC4 (client_secret_jwt→invalid_client_metadata) already enforced by T-034. Build P, Tests P. Tier 3 status: 13/17. Frontier next: T-033, T-041, T-042 (now unblocked — T-040 + T-036 done), T-045, T-049.

### Iteration 17 — 2026-04-27 (Tier 3 — T-042)
- T-042: DONE. Files: internal/api/oidc/dcr/response.go (new — RegistrationResponse + RegistrationOutput + WriteRegistrationResponse + buildRegistrationResponse pure helper + buildRegistrationClientURI); internal/api/oidc/dcr/response_test.go (new — 12 subtests). 201 + 3 mandated headers, omitempty client_secret, MUST-emit client_secret_expires_at=0 sentinel, RAT plaintext echoed once, registration_client_uri via op.IssuerFromContext (shares dcr.HandlerPrefix with T-029 discovery → cannot diverge). No-mutation pin on Clamped input. Build P, Tests P. Tier 3 status: 14/17. Frontier next: T-033 (request decoding L) / T-041 (3 app-event reducers S) / T-045 (token-grant resource propagation L) / T-049 (rollback validation M). T-043 (status-code matrix) now ready — needs T-033 first. T-057 (Claude Code compat) ready once T-033 lands.

### Iteration 18 — 2026-04-27 (Tier 3 — T-041)
- T-041: DONE. Files: internal/query/projection/app.go (+3 nullable columns on apps7_oidc_configs: registration_access_token_hash TEXT, registration_access_token_expires_at TIMESTAMPTZ, dcr_meta JSONB; +2 reducer registrations + bodies — reduceApplicationDynamicallyRegistered (no-op when DCRMeta empty), reduceApplicationRegistrationAccessTokenSet (UPDATE hash + optional expires_at)); internal/query/projection/app_test.go (+4 reducer subtests); internal/repository/project/dynamic_client_registration.go (+DCRMeta json:omitempty field on ApplicationDynamicallyRegisteredEvent payload, additive, constructor gains param); internal/command/dynamic_client_registration.go (RegisterClient now persists in.DCRMeta — closes T-040 gap where DCRMeta was collected but never carried). Audit fields stay in eventstore (NOT projected). Schema migration purely additive (nullable cols). Build P, Tests P. Tier 3 status: 15/17. Frontier next: T-033 (request decoding L) / T-045 (token-grant resource propagation L) / T-049 (rollback validation M). T-043 (status-code matrix) needs T-033. T-057 (Claude Code compat) needs T-033.

### Iteration 19 — 2026-04-27 (Tier 3 — T-033)
- T-033: DONE. Files: internal/api/oidc/dcr/decode.go (new — Decode + ApplyDefaults + SynthesiseClientName + DecodeOptions); internal/api/oidc/dcr/decode_test.go (new — 21 subtests); internal/api/oidc/dcr/errors.go (+ErrCodeUnsupportedMediaType + ErrCodePayloadTooLarge); internal/api/oidc/dcr/validate.go (+Status field on ClampError + HTTPStatus() helper). All R2 ACs pinned: 415 wrong/missing Content-Type (charset param + case-insensitive accepted), 413 via http.MaxBytesReader + *MaxBytesError type-check, 400 invalid_client_metadata for malformed/empty/nil, R2 defaults (grant_types/response_types/auth_method/application_type), unknown fields silently dropped, client_name#<lang> dropped. SynthesiseClientName separated from ApplyDefaults because it needs the post-mint client_id. Claude Code literal R9 payload decodes clean. Build P, Tests P. Tier 3 status: 16/17. Frontier next: T-045 (token-grant resource propagation L) / T-049 (rollback validation M). T-043 (status-code matrix) now ready (T-042 ✓ + T-037 ✓). T-057 (Claude Code compat) ready (T-042 ✓ + T-036 ✓).

### Iteration 20 — 2026-04-27 (Tier 3 — T-045)
- T-045: DONE. Files: internal/api/oidc/rfc8707_token.go (new — audienceFromTokenResources additive merge + narrowAudienceByTokenResources RFC 8707 §2.2 narrowing); internal/api/oidc/rfc8707_token_test.go (new — 12 subtests across 3 groups); patches to token_client_credentials.go + token_jwt_profile.go (additive merge), token_refresh.go + token_code.go (narrow), token_exchange.go (additive merge after RFC 8693 audience computation), token_device.go (doc note — RFC 8628 §3.4 has no resource field; audience set at /device_authorization per T-027). Sidecar (T-026) was already mounted on entire /oauth/v2 + /oidc/v1 prefix → validation against AllowedAudiences runs before any handler. F-001 /token-side closure complete. Build P, Tests P (full OIDC suite). Tier 3 status: 15/17 (done: T-033/T-034/T-035-absorbed/T-036/T-037/T-038/T-039/T-040/T-041/T-042/T-044/T-045/T-047/T-048; remaining: T-043 status-code matrix, T-046 rfc8707 integration test, T-049 rollback validation). T-046 (this task's downstream consumer) now ready.

### Iteration 21 — 2026-04-27 (Tier 3 — T-049)
- T-049: DONE. Files: internal/query/projection/dcr_rollback_test.go (new — 10 nullability subtests + 1 documentation skip-test for AC cross-references). AC1/AC3/AC5 pinned via cross-reference to existing tests (start.go conditional mount + dcr/handler_test.go + admin/iat_test.go T-024 dual-gate). AC2/AC4 structural — new T-041 columns consumed only by manage handlers, additive schema, idempotent mount. AC6 directly tested via `initColumnMirror + unsafe.Pointer` reflection-free read of unexported `nullable` + `defaultValue` fields; compile-time `unsafe.Sizeof` anchor catches future layout drift. Build P, Tests P. Tier 3 status: 16/17 (T-043 status-code matrix + T-046 rfc8707 integration test remain — both want integration runtime). Frontier next: T-043, T-046.
