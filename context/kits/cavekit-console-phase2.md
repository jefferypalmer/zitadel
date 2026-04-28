---
created: "2026-04-28T00:00:00Z"
last_edited: "2026-04-28T00:00:00Z"
complexity: unknown
---

# Cavekit: Console Phase 2 (Edit-DCR-App, Org IAT Admin, Org DCR Policy, Full i18n Rollout)

## Scope
Defines the Phase 2 console surfaces for Dynamic Client Registration. Adds an operator-facing edit-DCR-app panel under Project → App Detail (gated on `app.oidcConfig.dynamicallyRegistered`); a per-org Initial Access Token admin UI mirroring the instance-level Phase 1 surface; a per-org DCR policy editor exposing the gRPC surface from `cavekit-org-dcr-policy.md`; a Registration Access Token rotation action with plaintext-once dialog; and the full localization rollout (22 locales) for both backend yaml `Errors.DCR.*` keys (Phase 1 + Phase 2) and console JSON `DESCRIPTIONS.DCR.*` strings. End-to-end coverage via Cypress for each new surface.

## Source
- Phase 2 design (Approach A) — user-approved.
- Phase 1 carve-outs: `cavekit-console-ui-docs-and-observability.md` Out of Scope ("Edit-DCR-app affordance in console (Phase 2)", "Per-org IAT admin (Phase 2)", "Localized translations beyond English + German for Phase 1").
- Brownfield reference patterns: `console/src/app/pages/projects/apps/app-detail/`, `console/src/app/modules/iat-admin/`, `console/src/app/modules/iat-plaintext-dialog/`, `console/src/app/modules/settings-list/settings.ts`, `console/src/app/pages/orgs/org-settings/org-settings.component.ts`, `tests/functional-ui/cypress/e2e/dcr/*.cy.ts`.
- Spec references: RFC 7591 §3.2.1 (registration response shape), RFC 7592 §2 (client-managed metadata).

## Requirements

### R1: DCR operator panel in App Detail
**Description:** When the management `App` proto reports `oidcConfig.dynamicallyRegistered=true` (the field promoted to a hard requirement in `cavekit-console-ui-docs-and-observability.md` R1 and shipped by Phase 1 Tier 9 / T-100), the existing `AppDetailComponent` renders a new operator-only panel above the standard OIDC-config block. The panel surfaces operator-owned actions; client-owned RFC 7592 metadata is read-only per R2.

**Acceptance Criteria:**
- [ ] `AppDetailComponent` conditionally renders a `<dcr-operator-panel>` block at the top of the OIDC-config section when `app.oidcConfig?.dynamicallyRegistered === true`; otherwise the block is absent (NOT hidden via CSS — fully unrendered).
- [ ] The panel displays the registration_client_uri value (read-only string) with a copy-to-clipboard button.
- [ ] The panel displays a "RAT last rotated" timestamp sourced from the latest `project.application.registration_access_token.rotated` event for the app (or empty string if the RAT has never been rotated since registration).
- [ ] The panel displays a "Rotate Registration Access Token" button gated by R3.
- [ ] The panel displays a "Deactivate" toggle that calls the existing `DeactivateApp` command (no new gRPC).
- [ ] The panel displays a "Delete" button that calls the existing `RemoveApp` command (which Phase 1 already emits `project.application.dynamic_client.deleted` for, per `cavekit-manage-handler.md` R6).
- [ ] All panel actions are gated by the existing `project.app.write$` / `project.app.write:{projectId}` permission roles (no new permission strings).
- [ ] When the user lacks write permission, action buttons are disabled with a tooltip explaining the missing role; the panel is still visible read-only.

**Dependencies:** `cavekit-console-ui-docs-and-observability.md` R1; `cavekit-manage-handler.md` R6.

### R2: Editable scope guardrails (RFC 7592 client-owned fields are read-only)
**Description:** Operator-owned fields (description, project assignment, deactivate state) are editable. RFC 7592 client-owned metadata (`redirect_uris`, `grant_types`, `response_types`, `scope`, `token_endpoint_auth_method`, `application_type`) is rendered read-only with an explanatory label, since clients self-manage these via the `PUT /oidc/v1/register/{client_id}` endpoint.

**Acceptance Criteria:**
- [ ] In the App Detail view for a DCR-registered app, the form controls bound to `redirect_uris`, `grant_types`, `response_types`, `scope`, `token_endpoint_auth_method`, and `application_type` render in a disabled state.
- [ ] Each disabled control carries the visible label text from i18n key `DESCRIPTIONS.DCR.MANAGED_BY_CLIENT` ("managed by client (RFC 7592)") and a link to `/apis/openidoauth/dynamic-client-registration#management-rfc-7592`.
- [ ] The "Move app to another project" affordance remains enabled (this is operator-owned, not RFC 7592 client-owned).
- [ ] Description (operator metadata) remains editable.
- [ ] No client-owned fields appear in the gRPC `UpdateApp` request body when the panel submits — operator edits never silently overwrite client-managed metadata.

**Dependencies:** R1; `cavekit-manage-handler.md` R5.

### R3: RAT rotation action with plaintext-once dialog
**Description:** Operators can rotate a Registration Access Token without the client's involvement (e.g., for incident response). A new gRPC `RotateRegistrationAccessToken` on `ManagementService` is exposed via the panel; the response carries the new RAT plaintext once, surfaced in a plaintext-once dialog using the same hardening pattern as the IAT issue dialog from `cavekit-console-ui-docs-and-observability.md` R2.

**Acceptance Criteria:**
- [ ] `proto/zitadel/management.proto` `ManagementService` gains `RotateRegistrationAccessToken(RotateRegistrationAccessTokenRequest) returns (RotateRegistrationAccessTokenResponse)` with `auth_option` permission `project.app.write` and HTTP / OpenAPI annotations matching the existing app-action pattern.
- [ ] The command emits `project.application.registration_access_token.rotated` (the same event already defined in `cavekit-manage-handler.md` R5 for client-initiated PUT rotation; operator-initiated rotation reuses the event so the audit log is uniform). Audit consumers distinguish operator-driven from client-driven rotations via the eventstore-recorded `creator` / actor field — the same convention Zitadel uses elsewhere (e.g., `user.password.changed` covers self-service and admin-initiated; the actor field disambiguates). No payload extension or split event type is added.
- [ ] The console panel button calls this RPC and displays the plaintext RAT in a `<rat-plaintext-dialog>` modal.
- [ ] The modal uses `disableClose: true` so ESC / click-outside cannot drop the token unintentionally (mirrors the IAT-plaintext hardening from `cavekit-console-ui-docs-and-observability.md` R2).
- [ ] The modal auto-masks the plaintext after 60 seconds (configurable client-side constant); the masked state replaces the visible string with a fixed placeholder.
- [ ] The modal zeroes the in-memory plaintext reference on close and does NOT pass it back through `MatDialogRef.afterClosed()`.
- [ ] An "I have saved it" confirmation button is required to close the modal; absence of explicit confirmation keeps the modal open.
- [ ] The new RAT is delivered ONLY through this dialog flow — never rendered in the App Detail view, never listed in any subsequent GET response (`cavekit-manage-handler.md` R4 already mandates GET omits RAT plaintext; this AC pins the same contract for the rotation flow).

**Dependencies:** R1; `cavekit-manage-handler.md` R5, R6; `cavekit-console-ui-docs-and-observability.md` R2.

### R4: Per-org IAT admin module
**Description:** A new console module mirrors the instance-level IAT admin from Phase 1 but scoped to the authenticated org context. Identical UX — issue, list, revoke, plaintext-once dialog — with the same structural hardening. The gRPC surface is the existing IAT API (no new RPCs) but called with the calling user's org as resource owner; pagination 100 per page matches Phase 1.

**Acceptance Criteria:**
- [ ] A new Angular module exists at `console/src/app/modules/org-iat-admin/` mirroring the structure of `console/src/app/modules/iat-admin/`.
- [ ] The Issue dialog accepts: `project_id` (limited to projects owned by the calling org), `lifetime`, `max_uses`, `allowed_grant_types` (multi-select), `allowed_redirect_uri_patterns` (textarea), `description`.
- [ ] The Issue dialog reuses the plaintext-once dialog pattern from `cavekit-console-ui-docs-and-observability.md` R2 (structural plaintext-retention bounds, lifetime upper validator, projectId-required validator) — no divergence in hardening between instance- and org-scope surfaces.
- [ ] The List view paginates via `ListInitialAccessTokensRequest.query: ListQuery` with default page size 100 (matches Phase 1 R2 amendment).
- [ ] The List view filters server-side to IATs whose resource owner equals the calling org's id; cross-org IATs are not visible to the calling user.
- [ ] The Revoke action calls `RevokeInitialAccessToken` with the existing IAT API; no new RPC introduced.
- [ ] All actions inherit permission from the parent org-settings route (no new permission strings beyond `policy.read` / `policy.write` covered by R6).

**Dependencies:** `cavekit-iat.md` R6; `cavekit-console-ui-docs-and-observability.md` R2; R6.

### R5: Per-org DCR policy editor
**Description:** A new Angular module exposes the gRPC surface from `cavekit-org-dcr-policy.md` R6 for the calling org. Form fields map directly to the policy fields: `AllowedAudiences` (one URI per line, validated per `cavekit-org-dcr-policy.md` R4) and `RegistrationAccessTokenLifetime` (numeric input bounded per `cavekit-org-dcr-policy.md` R5). Validation errors map to the new i18n keys.

**Acceptance Criteria:**
- [ ] A new Angular module exists at `console/src/app/modules/org-dcr-policy/`.
- [ ] The form exposes a textarea bound to `AllowedAudiences` (one URI per line; trimming + empty-line skip on submit) and a duration input bound to `RegistrationAccessTokenLifetime`.
- [ ] Submit calls `UpdateOrgDCRPolicy` from `cavekit-org-dcr-policy.md` R6.
- [ ] A "Reset to instance default" button calls `ResetOrgDCRPolicy` from `cavekit-org-dcr-policy.md` R6 and clears local form state on success.
- [ ] Server-side validation errors mapped to i18n keys `Errors.DCR.OrgPolicy.InvalidAudienceSubset` and `Errors.DCR.OrgPolicy.InvalidLifetimeCap` are displayed inline against the offending field; the rendered string is the localized translation, not the raw key.
- [ ] When the calling user lacks `policy.write`, the form renders read-only with the same managed-by-link pattern used by R2.
- [ ] The form's initial state is hydrated from `GetOrgDCRPolicy`; an org with no override displays the merged effective values (per `cavekit-org-dcr-policy.md` R3) with a visual indicator that they are inherited from the instance default.

**Dependencies:** `cavekit-org-dcr-policy.md` R3, R4, R5, R6; R6.

### R6: Org Settings sidenav entries
**Description:** Two new `SidenavSetting` exports surface the org-scope IAT admin and org DCR policy editor in the Organization Settings navigation. A new sidenav group label encompasses them.

**Acceptance Criteria:**
- [ ] `console/src/app/modules/settings-list/settings.ts` gains a `ORG_INITIAL_ACCESS_TOKENS` `SidenavSetting` export with i18n key `SETTINGS.LIST.ORG_INITIAL_ACCESS_TOKENS` and `requiredRoles` `mgmt: ['policy.read']`.
- [ ] Same file gains a `ORG_DCR_POLICY` `SidenavSetting` export with i18n key `SETTINGS.LIST.ORG_DCR_POLICY` and `requiredRoles` `mgmt: { read: 'policy.read', write: 'policy.write' }`.
- [ ] Both new entries are added to `defaultSettingsList` in `console/src/app/pages/orgs/org-settings/org-settings.component.ts`.
- [ ] A new sidenav group is introduced with i18n key `SETTINGS.GROUPS.DCR` ("Dynamic Client Registration" in English; "Dynamische Clientregistrierung" in German); both new entries belong to that group.
- [ ] Entries are hidden (filtered out, not greyed) for users whose roles do not include `policy.read` — matches the existing sidenav role-gating pattern.

**Dependencies:** R4, R5; R8.

### R7: Backend yaml i18n — full Phase 2 rollout to 22 locales
**Description:** Every new `Errors.DCR.*` key introduced by Phase 2 (kits 1, 2, 3) is translated for every locale shipped under `internal/api/ui/login/static/i18n/`. Translation quality matches Phase 1 T-075 — hand-translated, not machine-passthrough English. The existing `internal/i18n/dcr_keys_test.go` is extended to cover every new key.

**Acceptance Criteria:**
- [ ] Every key listed under R9 of `cavekit-org-dcr-policy.md`, R10 of `cavekit-software-statement.md`, and R7 of `cavekit-inline-jwks.md` is present in all 22 yaml locale files.
- [ ] `internal/i18n/dcr_keys_test.go` covers every new key; absence in any locale fails the test.
- [ ] Each locale's value is a non-empty, non-raw-key string and is locale-appropriate phrasing (no machine-passthrough copies — verbatim English in a non-English locale fails review).
- [ ] Fallback behavior from `cavekit-console-ui-docs-and-observability.md` R3 is preserved: when a locale's bundle is somehow missing a key at runtime, a rendered English string is emitted, never the raw key.

**Dependencies:** `cavekit-org-dcr-policy.md` R9; `cavekit-software-statement.md` R10; `cavekit-inline-jwks.md` R7; `cavekit-console-ui-docs-and-observability.md` R3.

### R8: Console JSON i18n — full Phase 1 + Phase 2 rollout to 22 locales
**Description:** Phase 1 shipped console JSON strings for English + German only with English-fallback for the remaining 20 locales. Phase 2 ships hand-translated strings for the full 22-locale set in `console/src/assets/i18n/*.json` covering every `DESCRIPTIONS.DCR.*` key (Phase 1 set + Phase 2 additions), the new `SETTINGS.LIST.ORG_INITIAL_ACCESS_TOKENS`, `SETTINGS.LIST.ORG_DCR_POLICY`, `SETTINGS.GROUPS.DCR`, and every dialog title / button label introduced by R1–R6.

**Acceptance Criteria:**
- [ ] Every `DESCRIPTIONS.DCR.*` key from `cavekit-console-ui-docs-and-observability.md` R3 is present in all 22 console JSON locale files with a non-empty, non-raw-key string value.
- [ ] Keys `SETTINGS.LIST.ORG_INITIAL_ACCESS_TOKENS`, `SETTINGS.LIST.ORG_DCR_POLICY`, `SETTINGS.GROUPS.DCR`, `DESCRIPTIONS.DCR.MANAGED_BY_CLIENT`, and every dialog title / button label introduced by R1–R6 are present in all 22 locale files.
- [ ] The console TypeScript build is the test gate — an unknown i18n key referenced from a template causes a TS compile error; no new i18n key is introduced without an entry in every locale file.
- [ ] No locale file contains a literal duplicate of the English-source string for a non-English locale (machine-passthrough copies fail review per the same rule as R7).

**Dependencies:** R6; `cavekit-console-ui-docs-and-observability.md` R3.

### R9: End-to-end test coverage (Cypress)
**Description:** Cypress E2E specs cover the four new surfaces happy-path: the operator panel edit / deactivate / delete flows, RAT rotation with plaintext-once dialog masking, org IAT admin issue + revoke, and org DCR policy set + clear.

**Acceptance Criteria:**
- [ ] `tests/functional-ui/cypress/e2e/dcr/app-edit.cy.ts` exists and asserts: (a) the operator panel renders for a DCR-registered app fixture; (b) the panel does NOT render for a non-DCR-registered app fixture; (c) Deactivate works (UI reflects the new state); (d) Delete works (app no longer appears in the project's app list).
- [ ] `tests/functional-ui/cypress/e2e/dcr/app-edit.cy.ts` further asserts that RAT rotation issues a new RAT, the plaintext-once dialog renders with `disableClose: true`, the displayed plaintext is masked after the 60s auto-mask elapses (test uses `cy.clock` / `cy.tick` to advance time), and the dialog cannot be closed without the explicit confirmation button.
- [ ] `tests/functional-ui/cypress/e2e/dcr/org-iat.cy.ts` exists and asserts: org-scope IAT issue + list shows the issued IAT, revoke removes it from the active list.
- [ ] `tests/functional-ui/cypress/e2e/dcr/org-policy.cy.ts` exists and asserts: setting an `AllowedAudiences` subset and a valid `RegistrationAccessTokenLifetime` succeeds; setting an out-of-bounds value renders the localized error inline; "Reset to instance default" clears the override.
- [ ] All three new specs follow the convention from `applications.cy.ts` and the existing `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts` (login + throwaway project + cleanup hook).
- [ ] All `.should()` and `.contains()` regex assertions are passed as `RegExp` literals, not via `RegExp.toString()` (matches `cavekit-console-ui-docs-and-observability.md` R4 hardening).

**Dependencies:** R1, R3, R4, R5; `cavekit-console-ui-docs-and-observability.md` R4.

### R10: Audit and OTel surfaces
**Description:** Phase 2 console additions are server-mediated — they call existing or new gRPC RPCs whose audit / OTel emission is defined by other Phase 2 kits. This requirement is documentation-only: the existing observability table in the DCR MDX page is updated to enumerate the new metric (`zitadel.dcr.org_policy_changes_total`) and the existing RAT-rotation event surface so operators can correlate console actions with telemetry.

**Acceptance Criteria:**
- [ ] `apps/docs/content/apis/openidoauth/dynamic-client-registration.mdx` observability section is updated to list `zitadel.dcr.org_policy_changes_total` (from `cavekit-org-dcr-policy.md` R7) and `project.application.registration_access_token.rotated` events with a note that operator-initiated rotation (from R3) and client-initiated rotation (from `cavekit-manage-handler.md` R5) emit the same event so audit consumers cannot distinguish them by event type alone.
- [ ] No new console-side OTel spans are introduced — UI is server-mediated and inherits server spans by virtue of the gRPC call chain.
- [ ] No new console-side metrics are introduced.
- [ ] The MDX page section is updated to cross-reference the OTel attribute additions from `cavekit-org-dcr-policy.md` R7 (`dcr.policy.scope`) and `cavekit-inline-jwks.md` R7 (`dcr.jwks.source`).

**Dependencies:** `cavekit-org-dcr-policy.md` R7; `cavekit-inline-jwks.md` R7; `cavekit-software-statement.md` R11; `cavekit-console-ui-docs-and-observability.md` R5, R6, R7, R8.

## Out of Scope
- Per-user IAT admin (IAT scope is always org or instance — never per-user).
- Inline `jwks` editor in console — clients self-manage via RFC 7592 PUT (operator UI for editing JWK Set is intentionally absent; per `cavekit-inline-jwks.md` Out of Scope).
- `software_statement` uploader in console — operators do not manipulate software statements; clients deliver them on registration (per `cavekit-software-statement.md` Out of Scope).
- Edit-DCR-app exposure of RFC 7592 client-owned fields — covered by R2 read-only constraint; operators cannot edit `redirect_uris` / `grant_types` / etc.
- Console support for `software_statement` audit log filtering by `iss` / `jti` (Phase 1 audit-log surface inherited unchanged).
- Per-org `TrustedIssuers` UI — instance-only in Phase 2 per `cavekit-software-statement.md` Out of Scope.

## Cross-References
- See `cavekit-console-ui-docs-and-observability.md` R1, R2, R3, R4, R5, R6, R7, R8: extended by every requirement here; the proto field `app.oidcConfig.dynamicallyRegistered` (R1) is the gating predicate for R1; the IAT plaintext-dialog hardening (R2) is reused by R3 + R4; i18n fallback contract (R3) bounds R7 + R8; Cypress conventions (R4) bound R9; observability docs (R7, R8) extended by R10.
- See `cavekit-manage-handler.md` R5, R6: client-initiated RAT rotation event reused by R3 operator path; DELETE event surface referenced by R1.
- See `cavekit-iat.md` R6: instance-level IAT gRPC reused by R4 (no new RPCs).
- See `cavekit-org-dcr-policy.md` R3, R4, R5, R6, R7, R9: gRPC consumed by R5; i18n keys mirrored in R7.
- See `cavekit-software-statement.md` R10, R11: i18n keys + OTel attributes mirrored in R7 + R10.
- See `cavekit-inline-jwks.md` R7: i18n keys + OTel attribute mirrored in R7 + R10.

## Changelog
- 2026-04-28: Initial Phase 2 draft.
