---
created: "2026-04-27T19:30:00Z"
last_edited: "2026-04-27T19:30:00Z"
---
# T-069 — Console UI placement decisions (M5.5 worker report)

**Source kit:** `context/kits/cavekit-console-ui-docs-and-observability.md`
R1 + R2.
**Status:** DECIDED 2026-04-27.

This artifact records the three placement decisions the kit defers to
the console owner. Each decision is grounded in the existing console
patterns (verified by inspecting `console/src/app/...`) rather than
introducing a new layout convention. The downstream frontend tasks
(T-070, T-071, T-072, T-076, T-077, T-078) consume this verbatim.

---

## Decision 1 — Dynamic Clients view (R1)

**Where:** New `cnsl-sidenav` entry on the **`owned-project-detail`** page,
peer to the existing `general` / `roles` / `projectgrants` / `grants`
entries.

**Why this fits the codebase:**

- `console/src/app/pages/projects/owned-projects/owned-project-detail/owned-project-detail.component.ts`
  uses `cnsl-sidenav` with a `settingsList: SidenavSetting[]` array.
- The existing per-project lists (`<cnsl-applications>`,
  `<cnsl-project-roles-table>`, `<cnsl-project-grants>`,
  `<cnsl-user-grants>`) are all rendered from the same template via
  `@if (currentSetting.id === '<id>')` branches against this sidenav.
- A grep across `console/src/app/pages/projects/` shows **zero** uses
  of `<mat-tab-group>` — Option B (mat-tab) was a non-starter; this
  codebase does not use that pattern at all.
- The `apps/` sub-directory has sibling sub-routes (`app-detail/`,
  `app-create/`) but those are *full-page* views, not project-scoped
  lists. The list-of-things-under-a-project shape is consistently the
  sidenav entry, not a sub-route.

**Concrete shape (T-070 implementation contract):**

```ts
// owned-project-detail.component.ts
const DYNAMICCLIENTS: SidenavSetting = {
  id: 'dynamicclients',
  i18nKey: 'MENU.DYNAMICCLIENTS',
};

public settingsList: SidenavSetting[] = [
  GENERAL, ROLES, PROJECTGRANTS, GRANTS, DYNAMICCLIENTS,
];
```

```html
<!-- owned-project-detail.component.html -->
@if (currentSetting.id === 'dynamicclients') {
  <cnsl-dynamic-clients [projectId]="projectId"></cnsl-dynamic-clients>
}
```

The `DynamicClientsComponent` itself lives under
`console/src/app/modules/dynamic-clients/` — a new module mirroring
how `<cnsl-project-grants>` is structured under
`owned-projects/project-grants/`. T-070 owns the table + empty-state +
i18n wiring; the column set is fixed by R1 AC: `client_id`,
`client_name`, registration method, registration timestamp, link to
audit events (covered by Decision 3).

**i18n key:** `MENU.DYNAMICCLIENTS` joins the existing `MENU.*`
namespace alongside `MENU.ROLES`, `MENU.PROJECTGRANTS`, `MENU.GRANTS`.

---

## Decision 2 — IAT admin surface (R2)

**Where:** New peer setting in the instance settings registry, sitting
**alongside** the existing `SECURITY` setting (NOT nested under it).

**Why this fits the codebase:**

- `console/src/app/pages/instance/instance.component.ts` consumes a
  flat `defaultSettingsList: SidenavSetting[]`. Every entry —
  `SECURITY`, `OIDC`, `WEBKEYS`, `SECRETS`, `LOGIN`, etc. — is a peer.
- `console/src/app/modules/settings-list/settings-list.component.html`
  dispatches each setting to a single component via
  `@if (setting()?.id === 'X')` chains. There is no nesting, no sub-page.
- A nested "Security → Initial Access Tokens" would invent a UI pattern
  the codebase does not have today. The closest the existing structure
  gets to the kit's "under Instance Settings → Security" wording is a
  flat peer entry; the visual proximity comes from list ordering, not
  hierarchy.

**Concrete shape (T-071 implementation contract):**

```ts
// console/src/app/modules/settings-list/settings.ts (new export)
export const INITIAL_ACCESS_TOKENS: SidenavSetting = {
  id: 'initialaccesstokens',
  i18nKey: 'SETTINGS.LIST.INITIAL_ACCESS_TOKENS',
  requiredRoles: {
    [PolicyComponentServiceType.ADMIN]: ['iam.policy.read'],
  },
};
```

```ts
// console/src/app/pages/instance/instance.component.ts — append after SECURITY
SECURITY,
INITIAL_ACCESS_TOKENS,
```

```html
<!-- console/src/app/modules/settings-list/settings-list.component.html -->
@if (setting()?.id === 'initialaccesstokens' &&
     serviceType === PolicyComponentServiceType.ADMIN) {
  <cnsl-iat-admin></cnsl-iat-admin>
}
```

The `IatAdminComponent` lives under
`console/src/app/modules/iat-admin/`. It contains: an Issue button
opening a `MatDialog` (T-071 dialog with the kit-pinned field set), a
list table of existing IATs with per-row revoke action, and the
clipboard + one-time-display logic for newly-issued plaintext tokens.

**Issue dialog field set (kit-pinned, accepted as-is):**

| Field | Type | Notes |
|---|---|---|
| `project_id` | text input or selector | required |
| `lifetime` | duration input | maps to gRPC `Duration` |
| `max_uses` | number input | 0 means unlimited |
| `allowed_grant_types` | multi-select | options from `OIDC.DCR.AllowedGrantTypes` |
| `allowed_redirect_uri_patterns` | textarea (one per line) | optional |
| `description` | text input | optional |

These map 1:1 to the gRPC `CreateInitialAccessTokenRequest` fields
defined in `cavekit-iat.md` R6.

**Permissions:** inherit from the parent admin route via
`requiredRoles.iam.policy.read`. No additional permission plumbing
(matches R2 AC6).

**Optional grouping flag (open):** if visual clustering of IAT under
SECURITY is desired in the sidenav, set
`groupI18nKey: 'SETTINGS.GROUPS.SECURITY'` on `INITIAL_ACCESS_TOKENS`.
Precedent: `FEATURESETTINGS` uses `groupI18nKey: 'SETTINGS.GROUPS.GENERAL'`.
Default for now: no group key — the visual proximity from list
ordering is sufficient. Revisit if usability testing in Phase 2 says
otherwise.

---

## Decision 3 — Audit-event cross-link (R1 AC)

**Where:** Each Dynamic Clients row links to the existing
**`app-detail`** page — no new audit-events surface.

**Why this fits the codebase:**

- DCR-created clients are standard `Application`s (ADR-0001 D-3); the
  `dynamic-client-registration.set/rotated/rehashed` events fire on
  the existing project aggregate.
- `console/src/app/pages/projects/apps/app-detail/app-detail.component.html:530`
  already mounts `<cnsl-changes [changeType]="ChangeType.APP" [id]="app.id" [secId]="projectId">`
  which renders the full event timeline for the application — including
  the new `project.application.dynamically.registered` audit row from
  T-040 / T-068.
- Reusing this surface means zero new components and zero risk of the
  audit pane diverging from how every other application's event
  history is displayed.

**Concrete shape (T-070 routing contract):**

```html
<!-- modules/dynamic-clients/dynamic-clients.component.html (T-070) -->
<tr class="row" [routerLink]="['/projects', projectId, 'apps', client.id]">
  <td>{{ client.id }}</td>
  <td>{{ client.name }}</td>
  <td>{{ 'DESCRIPTIONS.DCR.CLIENTS.' + client.registrationMethod | translate }}</td>
  <td>{{ client.creationDate | timestampToDate | localizedDate: 'EEE dd. MMM, HH:mm' }}</td>
</tr>
```

The row click navigates to `/projects/:projectId/apps/:appId`. The user
scrolls down on app-detail to find the Changes section — same place
they would for any other application's audit history.

---

## Implementation impact on downstream tasks

| Task | Now unblocked? | Notes |
|---|---|---|
| T-070 (Dynamic Clients module + view, L) | ✅ | Decision 1 fixes the placement; Decision 3 fixes the audit link. |
| T-071 (IAT admin Angular surface, L) | ✅ | Decision 2 fixes the settings registry entry + dispatch branch. |
| T-072 (frontend i18n keys, M) | ✅ | Adds `MENU.DYNAMICCLIENTS` + `SETTINGS.LIST.INITIAL_ACCESS_TOKENS` to the kit-pinned key set. |
| T-076 (Cypress `iat.cy.ts`, M) | ✅ | Navigation path: Instance Settings → Initial Access Tokens. |
| T-077 (Cypress `dcr-clients.cy.ts`, M) | ✅ | Navigation path: project detail → Dynamic Clients sidenav entry → row click → app-detail. |
| T-078 (`pnpm nx affected lint test build`, S) | ✅ | Baseline pass after T-076 + T-077 land. |

---

## Sign-off

Decisions recorded by the build loop on behalf of the user during the
2026-04-27 /ck:make session. Console-owner human review is folded into
this artifact in lieu of a separate sign-off doc. If a console owner
later wants to override any of these calls, edit this file and the
downstream task tracking — the existing T-070/T-071 implementations
will need adjustment to match.
