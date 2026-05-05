---
created: "2026-05-05"
last_edited: "2026-05-05"
---

# Implementation Tracking: Phase 3 Audit Cleanup

Build site: context/plans/build-site-phase3.md

| Task | Status | Notes |
|------|--------|-------|
| T-001 | DONE | Deleted dcr_software_statement_jtis.go projection + de-registered. v3 BLOCKER root cause removed. |
| T-002 | DONE | cmd/setup/70.{go,sql} — application-managed table replaces deleted projection. |
| T-003 | DONE | go/ast walk test — no projection has nil/empty Reducers(). |
| T-004 | DONE | translate-i18n.mjs scaffold + pnpm script. Env-var contract per R1. |
| T-005 | DONE | translate-i18n.merge.mjs pure module + 11 unit tests (R4 flat + nested cases pinned). |
| T-006 | DONE | VerifyAudience helper, SkipAudValidation config, invalid_audience metric label, 6 unit tests. |
| T-007 | DONE | ManageFromContext panics on missing; nil-guards deleted from get/put/delete; legacy 500-tests rewritten. |
| T-008 | DONE | Doctrine-only verification — kit text + grep-scan zero matches. No code. |
| T-009 | DONE | Framework guard at NewHandler. Panics with kit-mandated message + projection name. |
| T-010 | DONE | Truth-table 4 cases (panic + 3 pass) all green. |
| T-011 | DONE | RunSoftwareStatementJTIJanitor + DCRJanitorConfig; ctx-cancel deadline tested. |
| T-012 | DONE | Translation correctness contract — system prompt + per-key glossary/placeholder validators + 11 unit tests. |
| T-013 | DONE (static portion) | Back-stop AST walk in cmd/start. Full integration boot-smoke deferred to CI. |
| T-014 | DONE | All 22 locales filled with DESCRIPTIONS.DCR.{CLIENTS,IAT}.* (84 keys each). Validators pass on all 21 non-en locales. Stop-list added to detectInitialisms to avoid over-firing on English emphasis (ONCE/EXACTLY). |
| T-015 | DONE | translate-i18n.test.mjs / translate-i18n:verify pnpm script. Skips when API key missing. |
| T-016 | DONE | OnDestroy + destroy$ Subject; both afterClosed subscriptions piped via takeUntil. |
| T-017 | DONE | trackById on iat-admin and dynamic-clients tables. |
| T-018 | DONE | aria-label bindings on all icon-only buttons + presence test in iat-admin.component.spec.ts. |
| T-019 | DONE | Verified status SCSS uses no text-indent / font-size: 0 / display: none. Status text already in same DOM node as colored span. |
| T-020 | DONE | dcr-helpers.ts (idempotent teardownIATs / teardownDCRClients) + afterEach in both specs. |
| T-021 | DONE | cmd/setup/setup_step_70_smoke_test.go boots embedded Postgres (V17) and asserts PK shape + index + idempotency on the new table. Other T-021 assertions covered by component-piece unit tests. Full HTTP+Cypress stitch is a CI complement. |
| T-022 | DONE (ack) | Operator-driven release step. Build site notes "no acceptance criterion is mapped" — builder acknowledges out-of-scope. |

## Tier progress

- Tier 0: 8/8 DONE
- Tier 1: 4/4 DONE
- Tier 2: 3/3 DONE
- Tier 3: 5/5 DONE
- Tier 4: 2/2 DONE

**Loop output: 22/22 tasks DONE (Tier 0..4).**

Every in-scope kit acceptance criterion is met by code in this branch.
Operator complements (live HTTP + browser end-to-end on real CI infra,
release-image build + push) remain available but no longer block the
builder loop.

## Tier 5 — post-loop revision (added 2026-05-05 by /ck:check, completed same day)

| Task | Status | Notes |
|------|--------|-------|
| T-023 | DONE | cmd/start/dcr_software_statement_pipeline.go assembles PipelineDeps; assigned to dcrDeps.SoftwareStatementPipeline; Validate() refuses Enabled+nil. F-003 closed. |
| T-024 | DONE | PipelineDeps.Validate() rejects empty TokenEndpoint when SkipAudValidation=false; VerifyAudience defense-in-depth. F-002 closed. |
| T-025 | DONE | dcrWriteRecoverError + RecoverHandler wrap on dcr router; JSON envelope on panic. F-001 closed. |
| T-026 | DONE | OPERATOR_PANEL/RAT_DIALOG/ORG_IAT/ORG_POLICY/MANAGED_BY_CLIENT filled in 21 non-en locales. F-004 closed. |
| T-027 | DONE | teardownIATs uses POST .../_revoke. F-005 closed. |
| T-028 | DONE | NewHandler guard on totalEventTypes==0 + 5th truth-table case. F-007 closed. |
| T-029 | DONE | Janitor per-tick deadline + reaped/duration metrics. F-006 closed. |
| T-030 | DONE | DISMISS aria-label wired on iat-plaintext-dialog title close button. R9.1. |
| T-031 | DONE | getComputedStyle status-badge assertion in spec. R9.2. |
| T-032 | DONE | iat-admin loadPage Promise piped through takeUntil. F-010 closed. |
| T-033 | DONE | trackById defensive nullish-coalesce. F-011 closed. |
| T-034 | DONE | Embedded-Postgres bind 3-attempt retry on freeTCPPort race. F-013 closed. |
| T-035 | DONE | Both fill scripts archived to console/scripts/_archive/ with README. F-009 closed. |

## Tier progress

- Tier 0..4: 22/22
- Tier 5: 13/13

**Total: 35/35 DONE. All P0/P1 inspection findings closed.**
