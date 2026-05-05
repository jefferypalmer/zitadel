---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-05-05T18:00:00Z"
complexity: complex
---

# Cavekit: Console UI, Docs, and Observability

## Scope
Defines the Phase-1 Console UI surfaces for DCR (M5.5: read-only Dynamic Clients tab under Project settings + Initial Access Token admin under Instance Settings → Security), the enumerated i18n keys (English + German maintained, other 19 locales English-fallback with translation tickets), Cypress smoke tests, MDX documentation pages (DCR guide + Claude Code MCP walkthrough), CHANGELOG entry, SECURITY.md threat-model section, ADR, and the audit/observability surface (events as audit log, OTel spans, OTel metrics with `zitadel.` prefix).

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §10 (docs), §11 (audit/observability), §12.14 (PR scope), §13.2 M5.5 (UI), §15.2 (UI scope), pass-11 §2 (i18n keys), pass-12 §9 (translation tickets)
- Spec references: RFC 7591 §4 (recommended documentation), RFC 7592 §2 (operations).

**Reference style guide:** This kit's UI acceptance criteria reference Zitadel's existing console patterns by file/path locator. There is no separate `DESIGN.md` in this repo at root; existing console patterns under `console/src/app/pages/projects/apps/` (e.g., `app-detail/`, `app-create/`) are the visual contract.

## Requirements

### R1: Dynamic Clients UI (read-only) under Project settings
**Description:** A console surface lists DCR-registered apps for a project with their audit metadata. No edit affordances — users manage their own clients via the RFC 7592 endpoint.

**Acceptance Criteria:**
- [ ] M5.5 pre-work confirms with the console owner whether Dynamic Clients is (a) a NEW sub-route at `console/src/app/pages/projects/apps/dynamic-clients/` colocated with `app-detail/` and `app-create/`, OR (b) a `<mat-tab-group>` tab inside the existing project-detail view (no new routing). Decision recorded in M5.5 worker report.
- [ ] The implementation uses Angular + NgModule + RouterModule + Material components, matching existing project-app patterns.
- [ ] The Dynamic Clients view lists registered apps with at least: client_id, client_name, registration method (anonymous / IAT-id), registration timestamp, link to view audit events.
- [ ] No edit affordances are present (no "Edit metadata" button, no "Rotate RAT" button — those are user-managed via RFC 7592).
- [ ] The view renders without errors when zero DCR-registered apps exist (uses the empty-state i18n key from R3).
- [ ] **The management `App` proto MUST expose a DCR marker.** Add `bool dynamically_registered` to `OIDCConfig` in `proto/zitadel/app.proto`; surface it through `query.OIDCApp.IsDynamicallyRegistered` (derived from `apps7_oidc_configs.registration_access_token_hash IS NOT NULL`); populate the proto field in the management converter. The frontend predicate then becomes `app.oidcConfig?.dynamicallyRegistered === true`. (Originally added 2026-04-27 as a conditional/Phase-1 carve-out. **Promoted 2026-04-28 to a hard requirement** — Tier 9 of the build site implements it; T-096 closes when the predicate flips.)

**Dependencies:** `cavekit-iat.md` R6 (admin gRPC for cross-link); `cavekit-register-handler.md` R6 (audit events provide the metadata); proto extension `App.dynamically_registered` (follow-up, not Phase 1).

### R2: Initial Access Tokens admin UI under Instance Settings → Security
**Description:** Admins can issue, list, and revoke IATs from the console. Wraps the gRPC from `cavekit-iat.md` R6.

**Acceptance Criteria:**
- [ ] An admin surface under Instance Settings → Security exposes Issue / List / Revoke for IATs. Exact subdirectory verified with console owner at M5.5 kickoff.
- [ ] Issue dialog accepts: project_id, lifetime, max_uses, allowed_grant_types (multi-select), allowed_redirect_uri_patterns (textarea), description.
- [ ] On issue, the dialog displays the plaintext IAT EXACTLY ONCE with a copy-to-clipboard button and an explicit "you cannot retrieve this again" warning.
- [ ] **Plaintext-token retention is structurally bounded**: the modal MUST (a) use `disableClose: true` so ESC / click-outside cannot drop the token unintentionally, (b) zero the in-memory token reference (`data.token = ''`) on close, (c) never pass the plaintext back through `MatDialogRef.afterClosed()`, and (d) optionally re-mask after a bounded reveal duration. AC3's "EXACTLY ONCE / unrecoverable" requires the structural contract, not just the UX-layer one. (Added 2026-04-27 from /ck:check Tier 6 finding F-005 — discovered that `data.token` is held on the `MatDialogRef` until GC; the kit's previous AC3 only constrained the UX layer.)
- [ ] **List view paginates** via `ListInitialAccessTokensRequest.query: ListQuery`. Default page size 100; surface `ListInitialAccessTokensResponse.details.totalResult` for the count chip. An unbounded fetch is a foot-gun on instances with thousands of IATs. (Added 2026-04-27 from /ck:check Tier 6 finding F-002 — `listInitialAccessTokens` wrapper omitted the `query` field entirely.)
- [ ] **Lifetime-input bounds**: the Issue dialog's `lifetimeHours` field MUST validate against a sensible upper bound (recommend 8760 = one year). Without an upper validator, scientific-notation input (`1e3` → 3.6M seconds) silently accepts unreasonable lifetimes. (Added 2026-04-27 from /ck:check Tier 6 finding F-006.)
- [ ] **Revoke guard for empty projectId**: the IAT admin Revoke action MUST refuse to dispatch when `token.projectId` is falsy (server-side semantics for instance-scoped IATs are undefined; client must enforce the projectId-required invariant or document the empty case). (Added 2026-04-27 from /ck:check Tier 6 finding F-003.)
- [ ] List view shows id, project_id, expires_at, max_uses, uses_consumed, revoked status.
- [ ] Revoke action prompts confirmation using the `DESCRIPTIONS.DCR.IAT.REVOKE_CONFIRM` i18n key, then calls `RevokeInitialAccessToken`.
- [ ] All actions inherit permission from the parent admin route (no additional permission plumbing).

**Dependencies:** `cavekit-iat.md` R6; R3 (i18n).

### R3: Enumerated i18n keys
**Description:** All console DCR strings are English + German for Phase 1; other 19 locales receive English fallback. Backend DCR error keys (`Errors.DCR.*`) live under `internal/api/ui/login/static/i18n/*.yaml`; frontend strings under `console/src/assets/i18n/*.json`. Strengthen to require that the same key set resolves to non-key text in **every** supported locale under `console/src/assets/i18n/*.json`. The bootstrap mechanism is machine translation (one Anthropic-API call per missing locale, per `cavekit-i18n-pipeline.md`); machine output is committed and is replaced over time by human-translated locale-PRs. ngx-translate's missing-key fallback to English is acceptable as a runtime safety net but is NOT a substitute for shipped translations — production users selecting a non-English locale should see translated text on first load, not English fallbacks for new feature surfaces.

**Acceptance Criteria:**
- [ ] `console/src/assets/i18n/en.json` contains the following keys (flat, dot-separated namespace): `DESCRIPTIONS.DCR.CLIENTS.TITLE`, `DESCRIPTIONS.DCR.CLIENTS.EMPTY`, `DESCRIPTIONS.DCR.CLIENTS.REGISTRATION_METHOD`, `DESCRIPTIONS.DCR.CLIENTS.IAT_USED`, `DESCRIPTIONS.DCR.IAT.TITLE`, `DESCRIPTIONS.DCR.IAT.ISSUE_BUTTON`, `DESCRIPTIONS.DCR.IAT.DIALOG_TITLE`, `DESCRIPTIONS.DCR.IAT.LIFETIME_LABEL`, `DESCRIPTIONS.DCR.IAT.MAX_USES_LABEL`, `DESCRIPTIONS.DCR.IAT.REVOKE_BUTTON`, `DESCRIPTIONS.DCR.IAT.REVOKE_CONFIRM`.
- [ ] Same keys present in `console/src/assets/i18n/de.json` with human-translated values.
- [ ] Column-label keys for `expires_at`, `created_at`, `uses_consumed` are also added under the same namespace.
- [ ] Backend error keys `Errors.DCR.*` are added to `internal/api/ui/login/static/i18n/*.yaml` (English canonical). Required keys, traceable to the kit-3 R8 status-code matrix and the kit-2 R1/R2 unique-constraint error: `Errors.DCR.FeatureDisabled`, `Errors.DCR.InvalidClientMetadata`, `Errors.DCR.InvalidRedirectURI`, `Errors.DCR.InvalidSoftwareStatement`, `Errors.DCR.UnapprovedSoftwareStatement`, `Errors.DCR.InvalidToken`, `Errors.DCR.IAT.Exhausted`, `Errors.DCR.IAT.SlotAlreadyConsumed`, `Errors.DCR.IAT.NotFound`, `Errors.DCR.IAT.Expired`, `Errors.DCR.IAT.Revoked`. German translations maintained for the same keys; other 19 locales fall back to English.
- [ ] Integration test `dcr_i18n_fallback_test.go` asserts that with an unsupported `Accept-Language`, error_description falls back to English and NEVER emits a raw translation key (e.g., `Errors.DCR.SomeKey`).
- [ ] **Translator preserves go-i18n's rendered fallback string when `*MessageNotFoundErr` fires.** `internal/i18n/translator.go::localize()` MUST NOT discard the rendered template returned alongside the not-found error from go-i18n's Localizer. Without this branch, every i18n consumer in the repo emits the raw key string when a request arrives with an `Accept-Language` whose bundle has no translation for the requested ID, regardless of whether the bundle's default language has it. (Added 2026-04-27 from /ck:check finding F-T6-002 — discovered while implementing the fallback test above; closed a real cross-package bug.)
- [ ] **For every supported locale, each `Errors.DCR.*` key resolves to a non-empty, non-raw-key string.** The original Phase-1 plan was to translate only English + German and let go-i18n fall back to English for the remaining 20 locales; T-075 instead translated all 22 locales by hand. Either approach satisfies this AC: a locale's `Errors.DCR.*` block is either present and human-translated OR absent (in which case the fallback test above guarantees English emission). What is NOT acceptable is a locale where the keys are present but partially-empty / partially-English-copied — that is a translation-quality regression, not a fallback. (Rewritten 2026-04-27 from /ck:check finding F-T6-005 — original AC was process-prescriptive, "open 19 GitHub tickets"; replaced with outcome-prescriptive language.)
- [ ] Per-locale translation tickets do NOT block Phase 1 merge.
- [ ] Every key in `DESCRIPTIONS.DCR.CLIENTS.*` and `DESCRIPTIONS.DCR.IAT.*` (and any other DCR-namespaced subtrees) exists in all 22 locale files under `console/src/assets/i18n/`. Verifiable via a shell loop that JSON-parses each locale and asserts `CLIENTS in DESCRIPTIONS.DCR and IAT in DESCRIPTIONS.DCR`.
- [ ] Translated values preserve all `{placeholder}` / `{count}` ICU tokens verbatim from the English source.
- [ ] No translated value is identical to the English source (would indicate translation skipped) UNLESS the value is itself locale-neutral (e.g., a brand name, an HTTP method, a status code symbol) — flagged via reviewer judgment, not a hard test.
- [ ] The translation bootstrap is reproducible: re-running the pipeline against the same source produces the same outputs (deterministic prompt + `temperature=0`). Tested via a CI dry-run that diffs two consecutive pipeline outputs.
- [ ] `ngx-translate` retains its English-fallback config as a runtime safety net, but R3 acceptance does NOT consider a fallback resolution as a passing locale — every locale must have explicit values for the enumerated DCR keys.

**Dependencies:** R1, R2; `cavekit-i18n-pipeline.md` (translation bootstrap mechanism).

### R4: Cypress smoke tests
**Description:** Two Cypress E2E specs cover the console paths end-to-end with admin login.

**Acceptance Criteria:**
- [ ] `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts` exists and: logs in as instance admin via `cy.login()`, creates an IAT, asserts the list shows it, revokes it, asserts it no longer appears in active list.
- [ ] `tests/functional-ui/cypress/e2e/dcr/dcr-clients.cy.ts` exists and: logs in as admin, lands on a project with at least one DCR-registered app fixture, asserts the Dynamic Clients view shows the app with its DCR metadata, follows the link to the audit-events view.
- [ ] Tests follow the convention from `applications.cy.ts` (login + throwaway project + cleanup hook).
- [ ] `pnpm nx affected --targets lint test build` is clean after the additions. **Local-environment fallback**: when the developer environment cannot run all three targets (e.g., Node 18.x for `build`, missing Go toolchain for `test`'s `@zitadel/api:generate-install` upstream), `lint` clean + `tsc --noEmit -p console/tsconfig.app.json` clean is the strongest local signal; `build` and `test` are CI gates by design. The Cypress specs themselves require a running Zitadel instance and run in CI, not locally. (Amended 2026-04-27 from /ck:check Tier 6 finding F-T6-103 — the original AC straddled two execution environments without acknowledging the split.)
- [ ] **Cypress assertion grammar**: regexes in `.should()` and `.contains()` MUST be passed as `RegExp` literals, never as `RegExp.toString()`. The latter stringifies to `/pattern/flags` (with literal slashes) and is then matched as a substring against rendered text — a silent always-false. Cypress reviewers should grep for `\.toString\(\)` in spec files and reject it. (Added 2026-04-27 from /ck:check Tier 6 finding F-001 — the Tier 6 IAT smoke shipped with this exact bug.)

**Dependencies:** R1, R2; `cavekit-iat.md` R6.

### R5: MDX documentation pages
**Description:** Two new MDX pages and updates to two existing MDX pages cover RFC references, the Claude Code walkthrough, the metadata table, and the upgrade note.

**Acceptance Criteria:**
- [ ] `apps/docs/content/apis/openidoauth/dynamic-client-registration.mdx` is created and references RFC 7591, 7592, 8414, 9700, OIDC Reg 1.0, RFC 8707, RFC 8252.
- [ ] The page contains a "Using with Claude Code / MCP" section with a concrete `claude mcp add --transport http https://...` walkthrough.
- [ ] The page contains an endpoint table, a metadata table (supported / clamped / ignored / rejected), an error-code table, IAT mode + admin API usage, SSRF + rate-limit guarantees, security considerations (mirroring SECURITY.md), two curl examples (confidential web + public native), discovery + RFC 8414 samples, the config reference, and the upgrade note.
- [ ] `apps/docs/content/guides/integrate/claude-code-mcp.mdx` is a short MCP walkthrough that links back to the DCR API reference.
- [ ] `apps/docs/content/apis/openidoauth/endpoints.mdx` gains a DCR subsection + RFC 8414 note.
- [ ] `apps/docs/content/apis/openidoauth/authn-methods.mdx` notes `none` as Phase-1 supported.
- [ ] The hostname-root deployment requirement (cross-ref `cavekit-discovery-and-as-metadata.md` R4) is documented in BOTH the DCR guide and the deployment docs.
- [ ] The PUT idempotency caveat (cross-ref `cavekit-manage-handler.md` R5) is documented as a known limitation in the API docs.
- [ ] `CHANGELOG.md` carries a feature entry leading with "Works with Claude Code out-of-the-box" and mentioning the hostname-root requirement.
- [ ] `SECURITY.md` gains a threat-model subsection enumerating T1–T20 (cross-ref `cavekit-security-hardening.md` R6).
- [ ] `docs/adr/ADR-XXXX-dynamic-client-registration.md` is created (the `docs/adr/` directory is created if absent) and captures the §2 architecture decisions plus product sign-off for the rotating-IP residual risk.

**Dependencies:** `cavekit-security-hardening.md` R6; `cavekit-discovery-and-as-metadata.md` R4; `cavekit-manage-handler.md` R5, R6.

### R6: Audit log via eventstore events
**Description:** DCR operations ARE the audit log — every registration / read / update / delete and every IAT op emits an eventstore event with the structured fields enumerated below.

**Acceptance Criteria:**
- [ ] Every DCR HTTP operation emits at least one eventstore event with payload containing `{instance_id, org_id, project_id, client_id, iat_id, software_statement_jti, remote_addr_sha256, user_agent, registration_method}` (where applicable per operation).
- [ ] `remote_addr_sha256` is the SHA-256 of the IP string returned by `internal/api/http/header.go:107` `RemoteIPStringFromRequest` (XFF first hop, fallback `r.RemoteAddr`); raw IP is never persisted.
- [ ] The XFF trust-boundary (no `CF-Connecting-IP` / `X-Real-IP` / RFC 7239 `Forwarded` parsing) is documented in SECURITY.md.

**Dependencies:** `cavekit-register-handler.md` R6; `cavekit-iat.md` R1; `cavekit-manage-handler.md` R5, R6; R5.

### R7: OpenTelemetry spans
**Description:** Five OTel spans are emitted for DCR operations. Span attributes contain identifier values only, never secret values.

**Acceptance Criteria:**
- [ ] Span `oidc.dcr.register` is emitted on every `POST /oidc/v1/register`.
- [ ] Span `oidc.dcr.read` is emitted on every `GET /oidc/v1/register/{client_id}`.
- [ ] Span `oidc.dcr.update` is emitted on every `PUT /oidc/v1/register/{client_id}`.
- [ ] Span `oidc.dcr.delete` is emitted on every `DELETE /oidc/v1/register/{client_id}`.
- [ ] Span `oidc.dcr.iat.consume` is emitted on every IAT consumption.
- [ ] Span attributes never contain `client_secret`, `registration_access_token`, IAT plaintext, or `software_statement` content.

**Dependencies:** R6.

### R8: OpenTelemetry metrics
**Description:** Five OTel metrics are emitted under the Zitadel-conventional dotted `zitadel.` prefix (matches `backend/v3/instrumentation/metrics/metric.go`). Underscore style is NOT used.

**Acceptance Criteria:**
- [ ] Counter `zitadel.dcr.registrations_total` with labels `result`, `auth_method`, `application_type`.
- [ ] Histogram `zitadel.dcr.request_duration_seconds`.
- [ ] Counter `zitadel.dcr.errors_total` with label `code`.
- [ ] Counter `zitadel.dcr.iat.consumed_total`.
- [ ] Counter `zitadel.dcr.iat.exhausted_total`.
- [ ] No DCR metric is emitted with the `dcr_*_total` underscore style.

**Dependencies:** none (orthogonal to other kits).

### R9: Console hygiene — subscription cleanup, trackBy, ARIA, status text
**Description:** Frontend code in DCR Console modules (`console/src/app/modules/iat-admin/`, `console/src/app/modules/dynamic-clients/`) follows four hygiene patterns the wider Zitadel Console either already uses or should use: (1) Subscription cleanup — every `.subscribe(...)` on an Observable not auto-completed by Angular is piped through `takeUntil(this.destroy$)`, where `destroy$ = new Subject<void>()` is completed in `ngOnDestroy()`. (2) trackBy on mat-tables — every `*matRowDef="let row; columns: …"` includes `trackBy: trackByFn` where `trackByFn = (_: number, row: { id: string }) => row.id`. Prevents full re-render on paginator change. (3) ARIA labels on icon-only buttons — every `<button mat-icon-button>` in DCR templates has an explicit `[attr.aria-label]="'KEY' | translate"` matching its tooltip — `matTooltip` does NOT expose to assistive tech. (4) Status text accompanies color — status indicators (active / revoked / pending) include a screen-reader-visible text label, not color-as-only-signal. SCSS MUST NOT use `text-indent: -9999px`, `font-size: 0`, or `display: none` to hide text from sighted users while preserving it for AT — the text is rendered visibly alongside the colored badge.

**Acceptance Criteria:**
- [ ] `iat-admin.component.ts` implements `OnDestroy`, declares `private destroy$ = new Subject<void>()`, completes it in `ngOnDestroy()`. Both `afterClosed().subscribe(...)` calls (currently lines 76, 127) are piped through `takeUntil(this.destroy$)`.
- [ ] `iat-admin.component.html` `<table mat-table>` row definition includes `trackBy: trackById` bound to a component method `trackById = (_: number, row: { id: string }) => row.id`.
- [ ] `dynamic-clients.component.html` row definition includes the same trackBy pattern.
- [ ] Every `<button mat-icon-button>` in `iat-admin.component.html`, `iat-plaintext-dialog.component.html`, `iat-revoke-dialog.component.html`, `iat-issue-dialog.component.html`, and `dynamic-clients.component.html` has an `[attr.aria-label]="'KEY' | translate"` attribute. Required key names (added to en.json + machine-translated to all 22 locales per R3 + i18n-pipeline kit): `DESCRIPTIONS.DCR.IAT.{REFRESH,REVOKE_BUTTON,COPY,REVEAL_TOGGLE,DISMISS}` — extend with any others discovered during implementation.
- [ ] Status badges in `iat-admin.component.html` (active / revoked) render a translated text label in the same DOM node as the colored span. The text MUST be visible (no `text-indent: -9999px`, no `display: none`) — verifiable by visual smoke and by `getComputedStyle()` assertion in a unit test.
- [ ] `console/src/app/modules/iat-admin/iat-admin.component.spec.ts` adds an `aria-label` presence test on the per-row revoke button.
- [ ] No regression in existing R1/R2 Dynamic-Clients/IAT-admin functionality (existing Cypress smokes from R4 still pass, plus the new R10 teardown additions).

**Dependencies:** R1, R2 (the UI surfaces these hygiene rules apply to); R3 + `cavekit-i18n-pipeline.md` for the additional ARIA-label i18n keys.

### R10: Cypress teardown leaves zero artifacts
**Description:** The Cypress smoke specs in `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts` and `dcr-clients.cy.ts` (R4) create persistent state — IATs are issued, clients are registered. Without explicit teardown, repeated runs accumulate rows in the test instance and eventually cause assertion noise (e.g., 'list is empty' assertions failing because prior-run artifacts are present). Each spec MUST clean up its own artifacts in an `afterEach()` block using the same gRPC clients used for setup.

**Acceptance Criteria:**
- [ ] `iat.cy.ts` has an `afterEach()` that revokes every IAT issued during the test (idempotent — tolerates already-revoked).
- [ ] `dcr-clients.cy.ts` has an `afterEach()` that deletes every client registered during the test (via the management gRPC client; tolerates already-deleted).
- [ ] Re-running each spec twice in immediate sequence (`npx cypress run --spec '…/iat.cy.ts' && npx cypress run --spec '…/iat.cy.ts'`) shows zero state accumulation: the count of IAT rows / DCR clients in the instance after the second run equals the count before the first run (modulo unrelated test fixtures).
- [ ] Teardown failures (e.g., RPC unavailable) are logged but do NOT fail the test (preserve diagnostic signal from the actual assertions; teardown is best-effort).
- [ ] Helper functions (e.g., `teardownIATs(projectId)`) live in a shared `tests/functional-ui/cypress/support/dcr-helpers.ts` so both specs reuse the same logic.

**Dependencies:** R1, R2, R4 (the existing UI surfaces and Cypress harness).

### R10.1: Cypress teardown helpers MUST use real backend endpoints (post-loop revision F-005)
**Description:** R10's helpers (`teardownIATs`, `teardownDCRClients`) live in `tests/functional-ui/cypress/support/dcr-helpers.ts`. The first cut of `teardownIATs` issued `DELETE /admin/v1/initial_access_tokens/{id}` — but that endpoint does not exist; the admin proto only registers `POST /admin/v1/initial_access_tokens/{iat_id}/_revoke`. Combined with `failOnStatusCode: false` and a 404-tolerance branch ("idempotent"), the helper became a silent no-op: every IAT created during the spec survived teardown. The kit's "re-run twice → zero accumulation" invariant was structurally unsatisfied even though `afterEach()` blocks were in place.

**Acceptance Criteria:**
- [ ] `teardownIATs` uses `POST /admin/v1/initial_access_tokens/{iat_id}/_revoke` with body `{ project_id }` — matching `RevokeInitialAccessTokenRequest`.
- [ ] `teardownDCRClients` uses `DELETE /management/v1/projects/{projectId}/apps/{appId}` and is verified against the live management gateway proto.
- [ ] A positive-control test (or sanity assertion) fails when the helper URL no longer matches the proto. Options: (a) emit a distinct cy.log on 404 vs 200 so a reviewer notices; (b) add a one-time pre-flight that asserts the endpoint returns 200 on a known-good fixture before counting subsequent 404s as idempotent.
- [ ] Re-running each spec twice in immediate sequence and asserting zero accumulation MUST exercise the live revoke / delete path — not a 404 silenced by `failOnStatusCode: false`.

**Dependencies:** R10 (the helpers being corrected).

### R9.1: Required ARIA-label keys MUST actually be bound to a `mat-icon-button` (post-loop revision)
**Description:** R9 enumerates `DESCRIPTIONS.DCR.IAT.{REFRESH, REVOKE_BUTTON, COPY, REVEAL_TOGGLE, DISMISS}` as required ARIA-label keys. The first cut of T-018 wired four of them (REFRESH on the refresh button, REVOKE_BUTTON on the per-row revoke + tooltip, COPY on the plaintext-dialog copy, REVEAL_TOGGLE on the plaintext-dialog remask). DISMISS was populated in 22 locales but bound to no `[attr.aria-label]` in any template — the close button on `iat-plaintext-dialog` is a `mat-raised-button` with visible text content, not a `mat-icon-button` subject to the rule. Either the kit's required-key list is wrong (DISMISS is unused) or an icon-only dismiss button is missing. R9.1 forces the resolution.

**Acceptance Criteria (resolution path A — wire DISMISS):**
- [ ] An icon-only dismiss button (e.g., a close `<button mat-icon-button>` in the dialog header) is added to `iat-plaintext-dialog.component.html` with `[attr.aria-label]="'DESCRIPTIONS.DCR.IAT.DISMISS' | translate"` (or to whichever DCR template owns "dismiss" semantics).

**Acceptance Criteria (resolution path B — drop DISMISS from required list):**
- [ ] R9 is amended to remove DISMISS from the required ARIA-label key list, AND the DISMISS key is removed from en.json + the 22 locale files (or marked locale-neutral if reused for tooltip text elsewhere).

Either path satisfies R9.1; the implementer chooses based on the current dialog UX.

**Dependencies:** R9 (the rule being enforced).

### R9.2: getComputedStyle assertion MUST be present in spec, not just visual smoke (post-loop revision)
**Description:** R9 requires status-text-accompanies-color be "verifiable by visual smoke AND `getComputedStyle()` assertion in a unit test". The current implementation passes the visual half but the unit test (`iat-admin.component.spec.ts`) only asserts `aria-label` presence on the per-row revoke button. The getComputedStyle assertion was deferred. R9.2 makes that gap explicit and provides a concrete expectation.

**Acceptance Criteria:**
- [ ] `iat-admin.component.spec.ts` adds a test that pushes a row with `revoked: true` into `tokens$`, calls `fixture.detectChanges()`, queries the rendered status badge, and asserts via `getComputedStyle()` that none of `text-indent`, `font-size`, or `display` would hide the translated text from sighted users (`text-indent` not extreme negative, `font-size` non-zero, `display` not `none`).
- [ ] Test runs as part of `pnpm nx affected --targets=test`.

**Dependencies:** R9 (the rule being enforced).

## Out of Scope
- Edit-DCR-app affordance in console (Phase 2) — see `cavekit-console-phase2.md`.
- Bulk IAT operations in console.
- Per-org IAT admin (Phase 2) — see `cavekit-console-phase2.md`.
- Localized translations beyond English + German for Phase 1.
- Console redesign / theme changes (re-uses existing patterns).
- Blog post (tracked in Linear, not in this kit).
- Adoption of `ChangeDetectionStrategy.OnPush` (performance debt; deferred).
- Server-side validation error → form-field error mapping (UX polish; deferred).
- Human-translated locale PRs (machine translations are the v3 release floor; humans replace later).

## Cross-References
- See `cavekit-config.md` R1: feature flag inferred from runtime config.
- See `cavekit-iat.md` R6: gRPC surface that IAT admin UI consumes.
- See `cavekit-register-handler.md` R6, R9: audit event payload + Claude Code compat test.
- See `cavekit-manage-handler.md` R5, R6: PUT idempotency + DELETE token-revocation note in CHANGELOG.
- See `cavekit-discovery-and-as-metadata.md` R4: hostname-root deployment doc.
- See `cavekit-security-hardening.md` R6: T1–T20 evidence map mirrored in SECURITY.md.
- See `cavekit-i18n-pipeline.md`: translation bootstrap mechanism that R3 depends on for full-locale coverage.

## Source Traceability (brownfield)
- `console/src/app/pages/projects/apps/` — existing project-app routes; pattern reference for R1. [VERIFIED] plural `projects/apps/` path corrected per pass 11.
- `tests/functional-ui/cypress/e2e/applications.cy.ts` — Cypress login + project-fixture pattern. [VERIFIED] reused for R4.
- `internal/api/ui/login/static/i18n/*.yaml` — backend i18n. [VERIFIED] correct path per pass 9.
- `console/src/assets/i18n/*.json` — frontend i18n. [VERIFIED] correct path per pass 9.
- `backend/v3/instrumentation/metrics/metric.go` — OTel naming convention `zitadel.*`. [VERIFIED] reference for R8.
- `internal/api/http/header.go:107` — `RemoteIPStringFromRequest`. [VERIFIED] reused by R6.
- `internal/api/assets/asset.go:77` — `logging.WithFields(...).WithError(err).Warn(msg)` pattern. [VERIFIED] structured-log convention.
- `docs/adr/` — [GAP] directory may not exist; created by R5 if absent.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
- 2026-04-27: R3 amended from /ck:check Tier 6 review (findings F-T6-002 + F-T6-005). Added explicit translator-fallback AC ("Translator preserves go-i18n's rendered fallback string when `*MessageNotFoundErr` fires") that closes a real cross-package i18n bug discovered while writing the fallback test. Rewrote the previous "M5.5 worker opens 19 GitHub tickets" AC to be outcome-prescriptive ("each supported locale either ships translations or correctly falls back to English") — process-prescriptive original was superseded by T-075's direct hand-translation of 20 locales.
- 2026-04-27 (post-Tier-6 /ck:check): R1, R2, R4 amended from second-pass review.
  - R1 AC: explicit "wiring contract is empty-state until App proto exposes a DCR marker" (finding F-T6-101).
  - R2 AC: structural plaintext-retention bounds (finding F-005), list pagination via ListQuery (F-002), lifetime upper bound (F-006), revoke guard for empty projectId (F-003).
  - R4 AC: split build/test/lint local-vs-CI execution semantics (F-T6-103); reject `RegExp.toString()` in Cypress assertions (F-001).
- 2026-04-28: R1 AC promoted from conditional/Phase-1 carve-out to a hard requirement that the App proto MUST carry a DCR marker. Tier 9 of the build site (T-100..T-106) implements the proto field, query surface, mgmt converter, codegen, frontend predicate flip, and Cypress fixture closure. T-096 (BLOCKED in Tier 8) closes when T-104 lands.
- 2026-05-05 (v3 audit cleanup): Strengthened R3 to require full locale coverage (every key resolves in all 22 locales, not just stub presence). Added R9 (frontend hygiene: subscription cleanup, trackBy, ARIA, status text) and R10 (Cypress teardown). Cross-referenced new `cavekit-i18n-pipeline.md` for translation bootstrap mechanism.
- 2026-05-05 (post-loop revision): Added R10.1 (Cypress teardown helpers MUST use real backend endpoints — F-005), R9.1 (DISMISS aria-label MUST be wired or dropped — surveyor finding), R9.2 (getComputedStyle assertion MUST be present in spec — surveyor finding).
