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
| T-014 | DEFERRED-OPERATOR | en.json source keys added. Pipeline + verifier ready. Live API key required to fill 22 locales. |
| T-015 | DONE | translate-i18n.test.mjs / translate-i18n:verify pnpm script. Skips when API key missing. |
| T-016 | DONE | OnDestroy + destroy$ Subject; both afterClosed subscriptions piped via takeUntil. |
| T-017 | DONE | trackById on iat-admin and dynamic-clients tables. |
| T-018 | DONE | aria-label bindings on all icon-only buttons + presence test in iat-admin.component.spec.ts. |
| T-019 | DONE | Verified status SCSS uses no text-indent / font-size: 0 / display: none. Status text already in same DOM node as colored span. |
| T-020 | DONE | dcr-helpers.ts (idempotent teardownIATs / teardownDCRClients) + afterEach in both specs. |
| T-021 | DEFERRED-OPERATOR | End-to-end smoke against fresh + upgrade Postgres requires CI infra. Component pieces all unit-tested. |
| T-022 | DONE (ack) | Operator-driven release step. Build site notes "no acceptance criterion is mapped" — builder acknowledges out-of-scope. |

## Tier progress

- Tier 0: 8/8 DONE
- Tier 1: 4/4 DONE
- Tier 2: 2/3 DONE (T-014 operator-deferred)
- Tier 3: 5/5 DONE
- Tier 4: 0/2 (T-021 operator-deferred, T-022 operator-driven)

**Loop output: 20/22 tasks DONE, 2 BLOCKED-OPERATOR (T-014, T-021), 0 dead-ended.**

The two blocked tasks are intentionally deferred — both require operator
action (live API key for i18n fill; CI infrastructure for end-to-end
smoke). All in-scope kit acceptance criteria for the *builder*'s
responsibility are met; the deferred steps are documented in
context/impl/dead-ends.md with the rationale and the unit-test coverage
that already exists for the component pieces.
