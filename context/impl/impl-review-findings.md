---
created: "2026-04-27T23:00:00Z"
last_edited: "2026-04-27T23:00:00Z"
---

# Review Findings — /ck:check Tier 6 second pass (2026-04-27)

Build site: context/plans/build-site.md
Source review: `git diff daeecb46c..HEAD` (commits 93749b70d → b2f5a1fe3, Tier 6 closeout).
Verdict: REVISE — 0 P0, 3 P1, 6 P2, 5 P3.

| Finding | Severity | File | Status | Build-site task |
|---------|----------|------|--------|------------------|
| F-001: Cypress IAT spec uses `RegExp.toString()` inside `.should('contain.text', …)` — stringifies the regex literal; assertion never matches | P1 | `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts:49` | NEW | T-091 |
| F-002: IAT admin list unbounded — `listInitialAccessTokens` wrapper omits the `query: ListQuery` field; an instance with thousands of IATs DOM-renders all rows | P1 | `console/src/app/services/admin.service.ts:1161-1167`, `console/src/app/modules/iat-admin/iat-admin.component.ts:36-41` | NEW | T-092 |
| F-003: Revoke dispatches `RevokeInitialAccessTokenRequest` with `projectId=""` for orphan rows; backend semantics for instance-scoped IATs undefined; no client guard | P1 | `console/src/app/modules/iat-admin/iat-admin.component.ts:90` | NEW | T-093 |
| F-004: T-070 listing hard-codes `listApps(projectId, 100, 0)` first page; once predicate flips real, the 101st DCR client silently disappears | P2 | `console/src/app/modules/dynamic-clients/dynamic-clients.component.ts:38-55` | NEW | T-096 |
| F-005: Plaintext token retained on `MatDialogRef.data` after close; AC3 satisfied at UX layer only, not structurally | P2 | `console/src/app/modules/iat-admin/iat-plaintext-dialog/iat-plaintext-dialog.component.ts:21,32` | NEW | T-094 |
| F-006: `IatIssueDialogComponent.lifetimeHours` accepts scientific-notation input (e.g. `1e3` → 3.6M seconds) — `Validators.min(0)` only; no max | P2 | `console/src/app/modules/iat-admin/iat-issue-dialog/iat-issue-dialog.component.ts:25-26,56-57` | NEW | T-095 |
| F-007: `loading$` BehaviorSubject set in both new modules but never bound to spinner/disable; double-click can dispatch parallel fetches | P2 | `iat-admin.component.ts:22,35,40`, `dynamic-clients.component.ts:25,39,54` | NEW | T-098 |
| F-008: Plaintext reveal has no auto-hide / re-mask; shoulder-surf window unbounded | P2 | `console/src/app/modules/iat-admin/iat-plaintext-dialog/iat-plaintext-dialog.component.ts:18,27-29` | NEW | T-097 |
| F-009: IAT methods placed mid-secret-generator block in `admin.service.ts:1155-1174`; cosmetic split of the file's domain grouping | P2 | `console/src/app/services/admin.service.ts:1155-1174` | NEW | T-099 (bundled w/ F-012) |
| F-010: ADMIN gate consistent with peers in `settings-list.component.html:47` | P3 | `console/src/app/modules/settings-list/settings-list.component.html` | RESOLVED (no defect) | — |
| F-011: DE-locale never exercised by CI; spec uses an OR regex that masks the gap | P3 | `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts:33-35` | NEW | (deferred; consider when adding multi-locale CI run) |
| F-012: `DESCRIPTIONS.DCR.CLIENTS.IAT_USED` defined in en.json + de.json:331 but unreferenced in any template | P3 | `console/src/assets/i18n/en.json:331`, `de.json:331` | NEW | T-099 (bundled w/ F-009) |
| F-013: All Cypress `data-e2e` selectors verified present in templates committed in the same wave | P3 | (verification only) | RESOLVED (no defect) | — |
| F-014: `data.token` typed as plain `string`; would benefit from a `string & { __brand: 'plaintext' }` brand to catch accidental retention in TS | P3 | `console/src/app/modules/iat-admin/iat-plaintext-dialog/iat-plaintext-dialog.component.ts` | NEW | (deferred; cosmetic) |

## Cross-cutting root cause

Three PARTIAL coverage findings (R1 AC3, R4 AC2 fixture, R4 AC2 click-through) trace to a single proto gap: `App` has no DCR marker. T-096 captures the forward-fix; the proto extension itself is upstream of this kit.

## Verdict

**REVISE** — three P1 issues block merge. T-091 (regex fix) is XS, T-093 (revoke guard) is XS, T-092 (paginator) is M. Total Tier 8 effort is dominated by T-092 + T-094 + T-097.

## Next

Run `/ck:make` to address Tier 8 (T-091..T-099). The completion sentinel from the prior `/ck:make` run remains valid for Tier 6 — these are fresh tasks routed through a new tier.
