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
| T-009 | PENDING | Framework guard at NewHandler (~line 174). |
| T-010 | PENDING | Truth-table tests for guard. |
| T-011 | PENDING | Janitor wiring in cmd/start/start.go + Reaper config. |
| T-012 | PENDING | Translation-correctness contract (glossary, placeholders, JSON-only) on translate-i18n.mjs. |
| T-013 | PENDING | Boot-smoke back-stop verification of guard. |
| T-014 | PENDING | Run pipeline against 22 locales to populate DCR keys. |
| T-015 | PENDING | CI reproducibility verification (translate-i18n.test.mjs). |
| T-016 | PENDING | Subscription-cleanup hygiene (takeUntil) in iat-admin. |
| T-017 | PENDING | trackBy hygiene on iat-admin + dynamic-clients tables. |
| T-018 | PENDING | ARIA-label hygiene on icon-only buttons. |
| T-019 | PENDING | Status-text-accompanies-color hygiene. |
| T-020 | PENDING | Cypress teardown helpers + per-spec afterEach. |
| T-021 | PENDING | E2E smoke (fresh + upgrade Postgres). |
| T-022 | PENDING | Operator-driven image build (NOT a builder task). |

## Tier progress

- Tier 0: 8/8 DONE
- Tier 1: 0/4
- Tier 2: 0/3
- Tier 3: 0/5
- Tier 4: 0/2 (T-022 is operator-driven)
