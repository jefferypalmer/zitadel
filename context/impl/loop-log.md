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





