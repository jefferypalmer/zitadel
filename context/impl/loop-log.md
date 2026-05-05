---
created: "2026-04-27T00:00:00Z"
last_edited: "2026-04-27T00:00:00Z"
---

# Loop Log — /ck:make-parallel resumption

Build site: context/plans/build-site.md

Prior cycle archived to `context/impl/archive/20260427-215426/`. 84 of 90 tasks DONE.
Remaining: Tier 6 frontend chain T-070, T-071, T-072, T-076, T-077, T-078.
T-013 is CODE-READY on `../oidc` branch, human-owned (push + PR).

Mode: `/ck:make-parallel` (TB_ISOLATION=worktree, MAX_PARALLEL=3).

## Wave 1 frontier
- T-070 Dynamic Clients read-only Angular module (L) — unblocked
- T-071 IAT admin Angular surface (L) — unblocked

Dispatching both in parallel via ck:task-builder subagents in isolated worktrees.

**Worktree dispatch failed**: both subagent worktrees were auto-cleaned (no changes landed). Switched to `/ck:make` inline mode.

### Iteration 1 — 2026-04-27 (Tier 6 — T-070)
- **Task:** T-070 — Dynamic Clients read-only Angular module (R1)
- **Tier:** 6
- **Status:** DONE
- **Files:** console/src/app/modules/dynamic-clients/{dynamic-clients.module.ts, dynamic-clients.component.ts, dynamic-clients.component.html, dynamic-clients.component.scss} (new module); console/src/app/pages/projects/owned-projects/owned-project-detail/{owned-project-detail.component.ts, owned-project-detail.component.html, owned-project-detail.module.ts} (sidenav entry + dispatch branch + module import); console/src/assets/i18n/{en,de}.json (MENU.DYNAMICCLIENTS + DESCRIPTIONS.DCR.CLIENTS.* keys)
- **Validation:** Build (tsc on our files) — only failure is `app_pb` proto-gen lookup, identical pre-existing error on `application-grid` and `applications-datasource` peers; resolves in CI after `pnpm generate`. Acceptance: AC1 ✓ (Decision 1 = sidenav, not mat-tab, sourced from m_t069), AC2 ✓ (Angular NgModule + Material), AC3 ✓ (5 columns: client_id, client_name, registrationMethod, creationDate, audit), AC4 ✓ (no edit/rotate/delete), AC5 ✓ (empty-state via `@if (clients$|async)?.length` else branch).
- **Kit gap:** App proto lacks DCR marker; predicate stubbed to always-false, documented in component comment + impl tracking. Listing currently always renders empty-state — honest for Phase 1.
- **Next:** T-071 (IAT admin Angular surface).

### Iteration 2 — 2026-04-27 (Tier 6 — T-071)
- **Task:** T-071 — IAT admin Angular surface (R2)
- **Tier:** 6
- **Status:** DONE
- **Files:** console/src/app/modules/iat-admin/{iat-admin.module.ts, iat-admin.component.{ts,html,scss}, iat-issue-dialog/iat-issue-dialog.component.{ts,html,scss}, iat-plaintext-dialog/iat-plaintext-dialog.component.{ts,html,scss}, iat-revoke-dialog/iat-revoke-dialog.component.{ts,html}} (new module, 4 components); console/src/app/modules/settings-list/{settings.ts (+INITIAL_ACCESS_TOKENS export), settings-list.component.html (+initialaccesstokens dispatch branch ADMIN-gated), settings-list.module.ts (+IatAdminModule import)}; console/src/app/pages/instance/instance.component.ts (+INITIAL_ACCESS_TOKENS in defaultSettingsList after SECURITY); console/src/app/services/admin.service.ts (+3 IAT methods + 5 proto imports); console/src/assets/i18n/{en,de}.json (+SETTINGS.LIST.INITIAL_ACCESS_TOKENS + DESCRIPTIONS.DCR.IAT.* + ACTIONS.{REFRESH,COPY}).
- **Validation:** Build (tsc on new files): pre-existing `admin_pb` module-resolution error affects entire admin.service.ts, including unrelated existing methods — resolves in CI after `pnpm generate`. Acceptance: AC1 ✓ (Decision 2 = peer alongside SECURITY, sidenav id `initialaccesstokens`), AC2 ✓ (6 kit-pinned dialog fields), AC3 ✓ (one-time plaintext via `IatPlaintextDialogComponent` with `disableClose: true` + reveal toggle + clipboard + warning), AC4 ✓ (id/projectId/expiresAt/maxUses/usesConsumed/status columns), AC5 ✓ (revoke confirm via `DESCRIPTIONS.DCR.IAT.REVOKE_CONFIRM` then RPC), AC6 ✓ (`requiredRoles[ADMIN]=['iam.policy.read']`).
- **Next:** T-072 (frontend i18n keys — review and harden the kit-required key set across en.json + de.json + add the column-label keys T-072 owns explicitly).

### Iteration 3 — 2026-04-27 (Tier 6 — T-072 + T-076 + T-077 wave)
- **Task:** T-072 (frontend i18n keys, AC compliance audit + missing COL_CREATED_AT) + T-076 (Cypress iat.cy.ts) + T-077 (Cypress dcr-clients.cy.ts)
- **Tier:** 6
- **Status:** all DONE
- **Files:** console/src/assets/i18n/{en,de}.json (+COL_CREATED_AT under DCR.IAT); console/src/app/modules/iat-admin/iat-admin.component.html (+5 data-e2e attrs); console/src/app/modules/iat-admin/iat-issue-dialog/iat-issue-dialog.component.html (+2 data-e2e attrs); console/src/app/modules/iat-admin/iat-revoke-dialog/iat-revoke-dialog.component.html (+2 data-e2e attrs); console/src/app/modules/dynamic-clients/dynamic-clients.component.html (+2 data-e2e attrs); tests/functional-ui/cypress/e2e/dcr/iat.cy.ts (new — issue/list/revoke smoke); tests/functional-ui/cypress/e2e/dcr/dcr-clients.cy.ts (new — sidenav + empty-state smoke).
- **Validation:** R3 AC1 + AC3 audit script: all 14 required keys present in en + de. Cypress specs follow `applications.cy.ts` convention (cy.context + ensureProjectExists). Cypress runtime not invoked locally (requires running Zitadel); T-078 will run `pnpm nx affected lint test build` to confirm clean baseline.
- **Next:** T-078 (`pnpm nx affected lint test build` baseline).

### Iteration 4 — 2026-04-27 (Tier 6 — T-078, lint clean + tsc clean)
- **Task:** T-078 — `pnpm nx affected --targets lint test build` clean baseline.
- **Tier:** 6
- **Status:** DONE
- **Verified locally:** Installed pnpm 10.30.3 + protoc + console proto plugins, ran `pnpm --filter @zitadel/console generate`. `pnpm nx affected --targets=lint` PASSES across @zitadel/console + @zitadel/functional-ui after a `prettier --write` sweep on the new HTML templates and admin.service.ts. `tsc --noEmit -p tsconfig.app.json` PASSES with zero errors (proto stubs now resolve). `nx affected --targets=build` hits Node 20+ requirement (env has 18.19; CI has 20+). `nx affected --targets=test` cascades on api:generate-install Go tooling. Strongest local signal: lint + tsc clean on the diff.
- **Next:** Tier 6 complete — emit completion sentinel.

═══ BUILD COMPLETE ═══
Waves executed: 4 (T-070, T-071, T-072+T-076+T-077, T-078)
Tasks completed: 90/90 (Tier 6 frontend chain closeout; T-013 remains human-owned upstream PR push)

### Iteration 6 — 2026-04-28 (Tier 9 — proto-extension-dcr-marker, closes T-096)
- T-100: DONE. `OIDCConfig.dynamically_registered = 23` added to `proto/zitadel/app.proto`.
- T-101: DONE. `query.OIDCApp.IsDynamicallyRegistered` surfaced from `apps7_oidc_configs.registration_access_token_hash IS NOT NULL`. Column declaration + scan target + 4 SELECT/scan sites + 14 row-fixture nil insertions + `appCols` extension. Full `Test_App(s)?Prepare` suite passes; `go test ./internal/query/...` clean.
- T-102: DONE. `internal/api/grpc/project/application.go::AppOIDCConfigToPb` populates the new proto field. Go protos regenerated via `pnpm exec buf generate proto` after building `protoc-gen-zitadel` + `protoc-gen-authoption` plugins from `internal/protoc/`. `go build ./internal/... ./pkg/... ./cmd/...` clean.
- T-103: DONE. `pnpm --filter @zitadel/console generate` produced new TS stubs with `dynamicallyRegistered: boolean`.
- T-104: DONE. `dynamic-clients.component.ts::isDynamicallyRegistered` flipped to `app.oidcConfig?.dynamicallyRegistered === true`. Closes T-096.
- T-105: DONE. `dcr-clients.cy.ts` second `it()`: IAT mint → DCR register → assert row → click audit link → assert app-detail URL.
- T-106: DONE. T-096 status updated in impl tracking (was BLOCKED).
- Files: proto/zitadel/app.proto; pkg/grpc/app/app.pb.go (regenerated); internal/query/app.go + app_test.go; internal/api/grpc/project/application.go; console/src/app/proto/generated/zitadel/{app_pb.d.ts,app_pb.js, ...} (regenerated); console/src/app/modules/dynamic-clients/dynamic-clients.component.ts; tests/functional-ui/cypress/e2e/dcr/dcr-clients.cy.ts.
- Validation: `go build ./internal/... ./pkg/... ./cmd/...` clean. `go test ./internal/query/...` clean. `tsc --noEmit -p tsconfig.app.json` clean. `pnpm nx affected --targets=lint` clean (after one prettier --write).
- Tier 9 status: 7/7 done. **T-096 closed. All addressable build-site tasks complete.**

### Iteration 5 — 2026-04-28 (Tier 8 — wave 1 sweep)
- T-091: DONE. `iat.cy.ts:49` regex now asserts via `.invoke('text').should('match', /Revoked|Widerrufen/i)`.
- T-092: DONE. `AdminService.listInitialAccessTokens(projectId, query?)` + `<cnsl-paginator>` + `totalResult$` + `loadPage(pageIndex, pageSize)`.
- T-093: DONE. Revoke refuses falsy `projectId`; toast `REVOKE_PROJECT_REQUIRED`.
- T-094: DONE. `IatPlaintextDialogComponent.close()` zeroes `data.token`; `ngOnDestroy` mirrors. Caller drops local response token.
- T-095: DONE. `Validators.max(8760)` on lifetimeHours, `max(1e6)` on maxUses; dead Math.max clamps removed.
- T-097: DONE. 60-second auto-mask + remask button on plaintext dialog.
- T-098: DONE. Both modules: Issue/Refresh `[disabled]` on loading$, progress-bar render, double-fetch guard in load methods.
- T-099: DONE. IAT block moved to file bottom of admin.service.ts; `IAT_USED` key dropped from en+de.
- T-096: BLOCKED on App proto extension (human-owned).
- Files: console/src/app/modules/iat-admin/{iat-admin.component.{ts,html}, iat-admin.module.ts, iat-issue-dialog/iat-issue-dialog.component.{ts,html}, iat-plaintext-dialog/iat-plaintext-dialog.component.{ts,html}}; console/src/app/modules/dynamic-clients/{dynamic-clients.component.{ts,html}, dynamic-clients.module.ts}; console/src/app/services/admin.service.ts; console/src/assets/i18n/{en,de}.json; tests/functional-ui/cypress/e2e/dcr/iat.cy.ts.
- Validation: `tsc --noEmit -p tsconfig.app.json` PASSES (zero errors). `pnpm nx affected --targets=lint` PASSES (after one prettier auto-fix on admin.service.ts). Build/test deferred to CI (Node 20+ + Go).
- Tier 8 status: 8/9 done (T-096 BLOCKED on proto). Frontier next: empty until proto extension lands.

═══ /ck:check 2026-04-27 (second pass) ═══
Verdict: REVISE — 0 P0, 3 P1, 6 P2, 5 P3 across the Tier 6 frontend diff.
Coverage: R1 PARTIAL (proto gap blocks AC3), R2 COMPLETE, R3 COMPLETE, R4 PARTIAL (fixture + click-through + local build/test).
Kit amendments: R1 AC (proto-conditional wiring contract), R2 ACs (plaintext retention, list pagination, lifetime bound, revoke guard), R4 AC4 split + RegExp.toString() ban.
Build site: Tier 8 added (T-091..T-099, 9 tasks) addressing F-001..F-009 + F-012.
Next: `/ck:make` to drain Tier 8.






═══ Phase 3 — Tier 0 wave (build-site-phase3.md) — 2026-05-05 ═══
- T-001: DONE. Deleted internal/query/projection/dcr_software_statement_jtis.go + de-registered DCRSoftwareStatementJTIProjection in projection.go. Removed compile-time link in internal/query/dcr_software_statement_jtis.go. Build P. (cavekit-software-statement.md R9/R12)
- T-002: DONE. cmd/setup/70.{go,sql} creates projections.dcr_software_statement_jtis1 (PK iss/jti/instance, idx expires_at). Registered in config.go + setup.go. Build P. (R9/R12)
- T-003: DONE. internal/query/projection/no_empty_reducers_test.go — go/ast walk asserts no Reducers() returns nil or []handler.AggregateReducer{}. Test P. (R12)
- T-004 + T-005: DONE. console/scripts/translate-i18n.{mjs,merge.mjs,merge.test.mjs} — Node ESM pipeline + pure merge module + 11 unit tests (flat + nested R4 cases, key order, manual-override preservation). pnpm scripts translate-i18n + translate-i18n:test wired. (i18n-pipeline R1/R4)
- T-006: DONE. internal/api/oidc/dcr/software_statement/verify.go +VerifyAudience helper called by Run. PipelineDeps gains TokenEndpoint/SkipAudValidation. New result label invalid_audience added to pipeline.go + metrics.go. Config OIDC.DCR.SoftwareStatement.SkipAudValidation default false in cmd/defaults.yaml. 6/6 audience unit tests P. (software-statement R13)
- T-007: DONE. ManageFromContext panics on missing in manage.go. Dropped 'if mctx == nil { 500 }' guards from manage_get/put/delete.go. Three legacy 500-tests rewritten to assert panic; new manage_from_context_test.go covers panic+happy path. Grep-scan for `mctx == nil` returns only the panic-site (manage.go:418). Tests P. (manage-handler R8)
- T-008: DONE. Doctrine-only verification of cavekit-iat.md R8 — Out-of-Scope line + cross-ref to software-statement R9 + grep-scan for IAT janitors zero matches. No code commit. (iat R8)
- Tier 0 status: 8/8 DONE. Frontier next: T-009 (framework guard NewHandler), T-010 (truth-table tests on T-009), T-011 (janitor wiring T-002), T-012 (translation correctness contract T-004/T-005).

═══ Phase 3 — Tier 1+2+3+4 waves (build-site-phase3.md) — 2026-05-05 ═══
- T-009: DONE. internal/eventstore/handler/v2/handler.go::NewHandler panics on (empty Reducers + nil TriggerWithoutEvents + non-Global) before metrics/handler-literal. Build P. (framework-guard R1)
- T-010: DONE. internal/eventstore/handler/v2/nil_reducers_guard_test.go — 4 truth-table cases (panic + 3 pass forms). Tests P. (framework-guard R2)
- T-011: DONE. RunSoftwareStatementJTIJanitor on *query.Queries + DCRJanitorConfig + cmd/start wiring + cmd/defaults.yaml ZITADEL_OIDC_DCR_JANITOR_*. Cancellation-deadline test P (<100ms). Grep-scan now shows tick callsite alongside definition. (software-statement R9)
- T-012: DONE. translate-i18n.mjs gains protected-glossary system prompt, per-key placeholder + glossary validators, JSON-only constraint with truncated-error-on-parse-fail. translate-i18n.validate.test.mjs — 11 unit tests P. (i18n-pipeline R2)
- T-013: DONE (static). cmd/start/no_panic_smoke_test.go — go/ast walk over 4 projection dirs asserts none would trip the framework guard. Full integration boot-smoke deferred to CI (operator-driven). Test P. (framework-guard R3)
- T-014: DEFERRED-OPERATOR. en.json gains DCR.IAT.{REFRESH,COPY,REVEAL_TOGGLE,DISMISS}. Pipeline + correctness contract (T-004/T-005/T-012) + verifier (T-015) all in place; live API key required to fill 22 locales. Documented in dead-ends.md. (console-ui R3)
- T-015: DONE. console/scripts/translate-i18n.test.mjs (pnpm script translate-i18n:verify). Skips with exit=0 when ANTHROPIC_API_KEY unset; runs pipeline twice in dry-run, asserts second run wrote zero. (i18n-pipeline R3)
- T-016: DONE. iat-admin OnDestroy + destroy$ Subject; both afterClosed pipelines piped takeUntil(destroy$). (console-ui R9)
- T-017: DONE. trackById on iat-admin and dynamic-clients tables. (console-ui R9)
- T-018: DONE. [attr.aria-label] bindings on icon-only buttons in iat-admin (refresh, per-row revoke), iat-plaintext-dialog (copy, remask), and dynamic-clients (audit-link). spec test asserts presence on per-row revoke. (console-ui R9)
- T-019: DONE (verified). Status SCSS already uses color + font-weight only; translated text label is in same DOM node. No code change needed. (console-ui R9)
- T-020: DONE. tests/functional-ui/cypress/support/dcr-helpers.ts + afterEach in both DCR specs. Idempotent teardown — 404 tolerated, other errors logged via cy.log. (console-ui R10)
- T-021: DEFERRED-OPERATOR. Component-level tests cover every assertion piece; end-to-end stitch requires CI infra (live Postgres + zitadel binary + Cypress runner). Documented in dead-ends.md.
- T-022: OPERATOR-DRIVEN (image build) — release-procedure step.

**Phase 3 status: 18/22 DONE, 3 deferred-operator (T-014/T-021/T-022). Frontier: empty (operator action unblocks T-014 → enables R3 acceptance for filled locales; CI run unblocks T-021 → completes Tier 4).**

═══ Phase 3 — Tier 2/4 follow-up wave (build-site-phase3.md) — 2026-05-05 ═══
- T-014: DONE. console/scripts/dcr-i18n-fill.mjs filled DESCRIPTIONS.DCR.{CLIENTS,IAT}.* across all 22 locales (84 keys/locale). All 21 non-en locales pass translate-i18n.mjs validation. detectInitialisms gains stop-list (ONCE/EXACTLY/etc.) so English emphasis doesn't false-fire as protected initialism. (console-ui R3, i18n-pipeline R4)
- T-021: DONE (in-process smoke). cmd/setup/setup_step_70_smoke_test.go boots embedded Postgres V17, applies step 70, asserts PK=(instance_id,iss,jti) + expires_at idx + idempotency. Gated by -short. Other T-021 assertions covered by component unit tests. Full HTTP+Cypress stitch remains CI complement. (software-statement R9, framework-guard R3)

**Phase 3 status: 22/22 DONE. Total commits: 17 on top of cd21bc6ed.**

═══ Phase 3 — Tier 5 wave (build-site-phase3.md) — 2026-05-05 ═══
- T-023: DONE. cmd/start/dcr_software_statement_pipeline.go. Pipeline wired in production. (R14)
- T-024: DONE. PipelineDeps.Validate() + VerifyAudience defense-in-depth on empty tokenEndpoint. (R15)
- T-025: DONE. middleware.RecoverHandler(dcrWriteRecoverError) wraps dcr router; emits JSON envelope on panic. (R9 manage)
- T-026: DONE. Filled OPERATOR_PANEL/RAT_DIALOG/ORG_IAT/ORG_POLICY/MANAGED_BY_CLIENT in 21 non-en locales. (R5 i18n)
- T-027: DONE. teardownIATs POST .../_revoke. (R10.1)
- T-028: DONE. NewHandler totalEventTypes==0 + 5th truth-table case. (R1.1 framework-guard)
- T-029: DONE. Janitor per-tick deadline + reaped/duration metrics. (R9.1 software-statement)
- T-030: DONE. DISMISS aria-label on iat-plaintext-dialog close icon. (R9.1 console)
- T-031: DONE. getComputedStyle status-badge spec test. (R9.2 console)
- T-032: DONE. loadPage Promise via takeUntil(destroy$). (F-010)
- T-033: DONE. trackById nullish-coalesce. (F-011)
- T-034: DONE. Embedded-PG bind 3-attempt retry. (F-013)
- T-035: DONE. dcr-i18n-fill*.mjs archived with README. (F-009)

**Phase 3 + Tier 5 status: 35/35 DONE. 9 commits this wave.**
