# Archived one-shot DCR i18n fill scripts

These scripts produced the initial DCR locale fill when no live
`ANTHROPIC_API_KEY` was available during Phase 3 build:

- `dcr-i18n-fill.mjs` — first pass; populated
  `DESCRIPTIONS.DCR.{CLIENTS,IAT}.*` (49 keys × 21 non-en locales).
  Cavekit reference: cavekit-console-ui-docs-and-observability.md R3,
  cavekit-i18n-pipeline.md R4. Implemented as part of T-014.

- `dcr-i18n-fill-extended.mjs` — second pass (T-026); covered the
  subtrees the first pass missed:
  `DESCRIPTIONS.DCR.{OPERATOR_PANEL,RAT_DIALOG,ORG_IAT,ORG_POLICY,MANAGED_BY_CLIENT}`
  (35 additional keys × 21 non-en locales). Cavekit reference:
  cavekit-i18n-pipeline.md R5.

**Do NOT run these directly.** The canonical translation entry point is
`pnpm translate-i18n` (which dispatches `console/scripts/translate-i18n.mjs`).
The merge logic in `translate-i18n.merge.mjs` is idempotent: future
operators with `ANTHROPIC_API_KEY` set can safely re-run the live
pipeline; it only fills genuinely-missing keys without overwriting
existing translations.

These archives are kept for traceability — the values committed across
the 22 locale files originated here. If a translator replaces an entry,
that translator's value supersedes the archived one and the live
pipeline preserves the human edit on subsequent runs.
