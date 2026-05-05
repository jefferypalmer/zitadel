---
created: "2026-05-05T00:00:00Z"
last_edited: "2026-05-05T18:00:00Z"
complexity: medium
---

# Cavekit: Console i18n Translation Pipeline (Anthropic-API bootstrap)

## Scope
Defines a reproducible Anthropic-API-driven translation pipeline that: (a) reads the source-of-truth English locale `console/src/assets/i18n/en.json`, (b) for each target locale file under `console/src/assets/i18n/*.json`, identifies any keys present in `en.json` but missing in the target, (c) dispatches one Anthropic API call per locale (Claude Haiku is sufficient — translations are bounded-creativity, low-reasoning), (d) merges returned translations into the target file preserving existing keys, JSON structure, and key order, (e) produces deterministic output across re-runs given the same source. The pipeline never overwrites existing values in target locales — human translators replace machine output later via separate locale-PRs and those are left alone on subsequent pipeline runs. Out of scope: human translation review workflow; `crowdin`/`weblate`/external-TMS integration; runtime translation-quality scoring; any locale that does not already have a `console/src/assets/i18n/*.json` file (adding a new locale is out of scope — operator creates the empty file first).

## Source
- Audit finding (BLOCKER): all locale files except `en.json` and `de.json` lack the `DESCRIPTIONS.DCR.CLIENTS` and `DESCRIPTIONS.DCR.IAT` subtrees.
- Existing console toolchain: pnpm + Nx (`apps/console/project.json`); a `scripts/` directory exists or can be created at `console/scripts/`.
- Anthropic SDK: `@anthropic-ai/sdk` (Node), already familiar to the project ecosystem (no other Anthropic dep currently in console).
- Model selection: Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) — translations are low-reasoning, latency-sensitive, and cheap; Opus would be wasteful.

## Requirements

### R1: Pipeline script — structure, invocation, env-var config
**Description:** A Node.js ESM script `console/scripts/translate-i18n.mjs` reads source and target locale files, identifies missing keys per target, dispatches one Anthropic API call per target locale, and merges returned translations back into each target file. The script is invoked via a pnpm/Nx task to integrate with the existing console toolchain. All runtime configuration (model, source/target paths, target-locale allow-list) is overridable via env vars; the defaults match the current console layout.

**Acceptance Criteria:**
- [ ] Script lives at `console/scripts/translate-i18n.mjs` and is a valid Node ESM module.
- [ ] Script is registered as an npm/pnpm script in `console/package.json`: `"translate-i18n": "node scripts/translate-i18n.mjs"`. Optional Nx target wrapper if appropriate to the existing project conventions.
- [ ] Environment variables (with documented defaults): `ANTHROPIC_API_KEY` (required; script exits non-zero if missing), `ANTHROPIC_MODEL` (default `claude-haiku-4-5-20251001`), `I18N_SOURCE` (default `console/src/assets/i18n/en.json`), `I18N_TARGET_DIR` (default `console/src/assets/i18n/`), `I18N_LOCALES` (comma-separated; default = all `*.json` files in `I18N_TARGET_DIR` minus `en.json`), `I18N_DRY_RUN` (boolean, default `false`).
- [ ] Script exits zero on success, non-zero on any error (missing API key, API failure, file-write failure, malformed source JSON). Stderr carries diagnostic detail.
- [ ] Script logs progress per locale: `translating <locale> (<N missing keys>)` → `wrote <locale> (<N keys added>)` or `skipped <locale> (no missing keys)`.
- [ ] Script produces no output to stdout other than progress lines.

**Dependencies:** None — pure Node tooling.

### R2: Translation correctness — placeholder preservation, glossary, determinism
**Description:** The translation prompt and merge logic preserve technical correctness across all target locales. Three contracts: (a) ICU/printf placeholders (`{0}`, `{count}`, `{userName}`, `%s`, `%d`) MUST appear verbatim in translated output — no localization, no reordering of token names; (b) a small protected-terms glossary (brand names, protocol acronyms, HTTP methods) MUST appear verbatim — never translated, never transliterated; (c) the same source + same model + same prompt MUST produce byte-identical output across runs (deterministic generation via `temperature=0`).

**Acceptance Criteria:**
- [ ] System prompt to Claude Haiku includes explicit instructions for placeholder preservation, glossary preservation (`Zitadel`, `OAuth`, `OIDC`, `JWT`, `JWKS`, `DCR`, `IAT`, `RAT`, `RFC 7591`, `RFC 7592`, `RFC 8707`, `PKCE`, `MCP`, `URL`, `URI`, `HTTP`, `HTTPS`, `JSON`; plus any all-uppercase initialism of length 2-6 in the source), JSON-only output, and structure preservation.
- [ ] API call uses `temperature: 0`, `max_tokens` sized to comfortably cover the largest locale-batch (e.g. 8192).
- [ ] Output validation: parsed as JSON; if parse fails, the run exits non-zero for that locale (do not write a malformed target file). The error includes the model's raw response truncated to 500 chars for diagnosis.
- [ ] Placeholder check: for each translated value, the set of `{...}` and `%s`/`%d` tokens MUST equal the source set. Any divergence is a per-key failure logged with the source / translated pair; the run exits non-zero (do not write partially-incorrect output).
- [ ] Glossary check: for each translated value, every protected term that appears in the source MUST appear verbatim in the translation. Violations follow the same fail-and-exit pattern as placeholder violations.
- [ ] Determinism smoke test (run as part of R3): two consecutive runs against the same source with `I18N_DRY_RUN=false` followed by `I18N_DRY_RUN=true` produce identical "would-write" payloads.

**Dependencies:** R1.

### R3: CI reproducibility verification
**Description:** A CI smoke test confirms the pipeline is reproducible (same input → same output) so future re-runs don't introduce unwanted churn in locale files. Skipped when `ANTHROPIC_API_KEY` is unavailable in the CI environment (e.g. PRs from forks).

**Acceptance Criteria:**
- [ ] A test target — e.g. `console/scripts/translate-i18n.test.mjs` or an Nx target `nx run @zitadel/console:translate-i18n-verify` — runs the pipeline twice with identical inputs and asserts the second run produces zero new writes.
- [ ] When `ANTHROPIC_API_KEY` is unset, the test logs `skipped — ANTHROPIC_API_KEY not configured` and exits zero.
- [ ] On main-branch CI where the key IS available, the test runs and a regression (any new diff) fails the build with a message instructing the operator to commit the regenerated locale files.
- [ ] The test accepts a `--dry-run` flag (passed to the underlying pipeline) so it never modifies the working tree even on failure — diff inspection is via the dry-run output only.

**Dependencies:** R1, R2.

### R4: Idempotent merge — never overwrite existing target values
**Description:** The merge logic that writes translations back into target files MUST treat the existing target file as authoritative for any key it already contains. Only keys present in the source AND missing from the target are added. This guarantees that human translations (which replace machine output via separate locale-PRs) survive future pipeline re-runs unchanged.

**Acceptance Criteria:**
- [ ] Pre-API-call diff phase: for each target locale, compute the set of keys present in source but missing in target (recursively, by JSON path).
- [ ] If the diff is empty, the locale is skipped entirely (no API call, no file write).
- [ ] If the diff is non-empty, only those missing keys are sent to the API for translation; existing target keys are NOT included in the request payload.
- [ ] The merge writes the translated keys back into the target file at their correct nested paths, leaving every other key bit-identical to its prior value.
- [ ] Final file output preserves the source's key order at each nesting level.
- [ ] Unit test (no API call): given a synthetic source `{a:1, b:2, c:3}` and target `{a:'X'}`, the merge function called with translations `{b:'Y', c:'Z'}` produces `{a:'X', b:'Y', c:'Z'}` — preserves `a:'X'`, adds `b` and `c` from translations, never invents keys.
- [ ] Unit test for nested case: source `{x:{y:1, z:2}}`, target `{x:{y:'A'}}`, translations `{x:{z:'B'}}` → result `{x:{y:'A', z:'B'}}`.

**Dependencies:** R1.

### R5: Pipeline coverage MUST include ALL locale-eligible subtrees, not a hand-picked subset (post-loop revision F-004)
**Description:** The first T-014 fill of 22 locales used a one-shot script (`console/scripts/dcr-i18n-fill.mjs`) that hard-coded translations for `DESCRIPTIONS.DCR.CLIENTS.*` and `DESCRIPTIONS.DCR.IAT.*` (49 keys) but skipped `DESCRIPTIONS.DCR.OPERATOR_PANEL.*`, `DESCRIPTIONS.DCR.RAT_DIALOG.*`, `DESCRIPTIONS.DCR.ORG_IAT.*`, and `DESCRIPTIONS.DCR.MANAGED_BY_CLIENT`. Console admins on non-English locales see English fragments mid-page in the DCR operator panel + RAT dialog. R5 makes the rule explicit: any subtree that EN populates must be filled in every shipped locale (modulo the locale-neutral exception clause that already lives in R3 of cavekit-console-ui-docs-and-observability.md).

**Acceptance Criteria:**
- [ ] Validation test (or shell loop) iterates every leaf path under any subtree EN defines and asserts each non-en locale either contains a translated value OR explicitly opts that path out (mechanism TBD — currently no opt-out marker exists, so the strict rule is: no path may be missing).
- [ ] CI reproducibility verifier (R3) extends to fail when ANY EN-leaf path is missing in any locale, not just when the pipeline produces a diff.
- [ ] One-shot bootstrap scripts (`dcr-i18n-fill.mjs` or successors) MUST cover every EN-defined DCR subtree; partial fills are forbidden going forward.
- [ ] Operator runbook documents the "rerun the pipeline against every locale" step; first-class operator action when EN gains new subtrees.

**Dependencies:** R3 (the verifier this strengthens), R4 (the merge logic that fills the gap).

## Out of Scope
- Human translation review workflow (locale-PRs replace machine output ad-hoc; no formal queue or assignment system).
- External Translation Memory System integration (Crowdin, Weblate, etc.).
- Runtime translation-quality scoring or LLM-judge evaluation of generated translations.
- Adding a new locale (the script only fills in keys for `*.json` files that already exist; creating a new locale file is operator-driven).
- Re-translating existing keys when EN values change (the pipeline's "missing-key only" rule means EN edits to existing keys do NOT propagate; addressed in a future iteration with content-hash markers if needed).
- Translating any keys outside `console/src/assets/i18n/` — the Login UI's locales (`apps/login/locales/`) are a separate domain.

## Cross-References
- See `cavekit-console-ui-docs-and-observability.md` R3 (strengthened — every enumerated key must resolve in every locale; this kit defines the bootstrap mechanism R3 depends on).
- See `cavekit-overview.md`: this kit is added to the Domain Index under a "Build Tooling" section (or whatever heading reflects cross-cutting infrastructure in the existing overview).

## Source Traceability (brownfield)
- `console/src/assets/i18n/en.json` — source-of-truth locale; baseline for the diff phase.
- `console/src/assets/i18n/de.json` — second-fully-populated locale (German); useful as a sanity reference during pipeline development.
- The other 20 locale files under the same directory — targets.
- `console/package.json` — host for the new pnpm script.
- `apps/login/locales/*.json` — different domain (Login UI), explicitly out of scope here.

## Changelog
- 2026-05-05: Created — v3 audit cleanup. Initial draft adds four Rs: R1 pipeline script structure, R2 translation correctness, R3 CI reproducibility, R4 idempotent merge.
- 2026-05-05 (post-loop revision): Added R5 — pipeline must cover every EN-defined DCR subtree, not a hand-picked subset. T-014 fill missed OPERATOR_PANEL/RAT_DIALOG/ORG_IAT in every non-en locale (F-004).
