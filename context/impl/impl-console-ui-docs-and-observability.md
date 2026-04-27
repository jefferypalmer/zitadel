---
created: "2026-04-27T00:00:00Z"
last_edited: "2026-04-27T00:00:00Z"
---
# Implementation Tracking: console-ui-docs-and-observability (Tier 6 — frontend chain resumption)

Build site: context/plans/build-site.md

Tier 6 closeout — frontend chain T-070, T-071, T-072, T-076, T-077, T-078.
Backend tasks T-066/T-067/T-068/T-069/T-073/T-074/T-075/T-079/T-080/T-081/T-082/T-083/T-084/T-085/T-086 already DONE in archived cycle (`context/impl/archive/20260427-215426/impl-console-ui-docs-and-observability.md`).

| Task | Status | Notes |
|------|--------|-------|
| T-070 | DONE | New `console/src/app/modules/dynamic-clients/` module (DynamicClientsComponent + .html + .scss + module.ts). Sidenav entry `DYNAMICCLIENTS` (i18nKey `MENU.DYNAMICCLIENTS`) appended after `GRANTS` on `owned-project-detail`. Template branch `@if currentSetting.id === 'dynamicclients'` renders `<cnsl-dynamic-clients [projectId]="projectId">`. Module imported into `OwnedProjectDetailModule`. Columns per R1 AC3: client_id / client_name / registrationMethod / creationDate / audit-link. Audit link (Decision 3): row icon button with `[routerLink]="['/projects', projectId, 'apps', row.id]"` — existing app-detail page already mounts `<cnsl-changes [changeType]="ChangeType.APP">`. R1 AC4 satisfied: zero edit/rotate/delete affordances. R1 AC5 satisfied: `@empty`-style branch on `(clients$ \| async)?.length` renders `DESCRIPTIONS.DCR.CLIENTS.EMPTY` when listing is empty. **Kit gap surfaced:** the `App` proto exposed via `mgmt.listApps` carries no DCR-specific marker (no `dcr_meta`, no `registration_access_token_hash`, no `registration_method`). Until proto is extended, `isDynamicallyRegistered` predicate returns `false` and listing is the empty state always — honest for Phase 1 since DCR clients ARE Applications and surface in the regular Applications listing too. One-line switchover when proto lands. Documented inline in component file with TODO. New i18n keys `MENU.DYNAMICCLIENTS` + `DESCRIPTIONS.DCR.CLIENTS.{TITLE,DESCRIPTION,EMPTY,REGISTRATION_METHOD,METHOD_ANONYMOUS,METHOD_IAT,IAT_USED,COL_CLIENT_ID,COL_CLIENT_NAME,COL_CREATED_AT,COL_AUDIT,VIEW_AUDIT}` added to en.json + de.json (T-072 will validate full set). Validation: `tsc --noEmit -p tsconfig.app.json` errors on our files limited to `Cannot find module 'src/app/proto/generated/zitadel/app_pb'` — identical pre-existing error on peer modules `application-grid` and `applications-datasource`; resolved by `pnpm generate` in CI before `pnpm build`. Files: console/src/app/modules/dynamic-clients/{dynamic-clients.module.ts, dynamic-clients.component.ts, dynamic-clients.component.html, dynamic-clients.component.scss}; console/src/app/pages/projects/owned-projects/owned-project-detail/{owned-project-detail.component.ts, owned-project-detail.component.html, owned-project-detail.module.ts}; console/src/assets/i18n/{en,de}.json. |

## Follow-up gaps (not part of this build site)

- **proto-extension-dcr-marker**: extend `App` proto in `proto/zitadel/app.proto` with a `bool dynamically_registered` field (or expose `dcr_meta` JSON pass-through) so console can filter the Applications list for DCR clients without backend changes. One-line switchover in `dynamic-clients.component.ts::isDynamicallyRegistered`.
