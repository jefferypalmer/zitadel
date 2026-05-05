#!/usr/bin/env node
//
// translate-i18n.mjs — fills missing keys in console/src/assets/i18n/<locale>.json
// from the English source via Anthropic Claude, with idempotent merge.
//
// cavekit-i18n-pipeline.md R1 (T-004 — script structure / env config).
// cavekit-i18n-pipeline.md R4 (T-005 — idempotent merge: never overwrites
//   existing target values; preserves source key order at each level).
//
// The translation-correctness contract (T-012, R2) — protected glossary,
// placeholder preservation, JSON-only response, temperature: 0,
// per-key validation — is layered on top by extending callClaude() and
// validateTranslations() below.
//
// Env vars:
//   ANTHROPIC_API_KEY     required; missing → exit 1
//   ANTHROPIC_MODEL       default "claude-haiku-4-5-20251001"
//   I18N_SOURCE           default "src/assets/i18n/en.json" (relative to cwd, which is console/)
//   I18N_TARGET_DIR       default "src/assets/i18n/"
//   I18N_LOCALES          comma-separated (default = every *.json in the target dir minus en.json)
//   I18N_DRY_RUN          "true" / "1" → skip writes; report what would change
//
// Stdout is silent. Progress lines go to stderr:
//   translating <locale> (<N missing keys>)
//   wrote <locale> (<N keys added>)
//   skipped <locale> (no missing keys)
//
// Exit codes: 0 success; 1 any error.

import { readFile, writeFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, basename, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  diffMissingPaths,
  getPath,
  mergeTranslations,
} from './translate-i18n.merge.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONSOLE_DIR = resolve(__dirname, '..');

const DEFAULTS = {
  ANTHROPIC_MODEL: 'claude-haiku-4-5-20251001',
  I18N_SOURCE: 'src/assets/i18n/en.json',
  I18N_TARGET_DIR: 'src/assets/i18n/',
};

function readEnv() {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    process.stderr.write('translate-i18n: ANTHROPIC_API_KEY is required\n');
    process.exit(1);
  }
  return {
    apiKey,
    model: process.env.ANTHROPIC_MODEL || DEFAULTS.ANTHROPIC_MODEL,
    source: resolve(CONSOLE_DIR, process.env.I18N_SOURCE || DEFAULTS.I18N_SOURCE),
    targetDir: resolve(CONSOLE_DIR, process.env.I18N_TARGET_DIR || DEFAULTS.I18N_TARGET_DIR),
    explicitLocales: (process.env.I18N_LOCALES || '').trim(),
    dryRun: ['1', 'true', 'yes'].includes((process.env.I18N_DRY_RUN || '').toLowerCase()),
  };
}

async function discoverLocales(env) {
  if (env.explicitLocales) {
    return env.explicitLocales.split(',').map(s => s.trim()).filter(Boolean);
  }
  const sourceBase = basename(env.source).replace(/\.json$/, '');
  const entries = await readdir(env.targetDir);
  return entries
    .filter(n => n.endsWith('.json'))
    .map(n => n.replace(/\.json$/, ''))
    .filter(loc => loc !== sourceBase)
    .sort();
}

async function readJSON(path) {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw);
}

async function writeJSON(path, value) {
  // Mirror existing locale files: 2-space indent, trailing newline.
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

// PROTECTED_GLOSSARY — domain terms that MUST appear verbatim in the
// translation if they appear in the source. Matched case-sensitively.
// Plus any all-uppercase initialism of length 2-6 detected dynamically
// in source values (cavekit-i18n-pipeline.md R2).
export const PROTECTED_GLOSSARY = [
  'Zitadel', 'OAuth', 'OIDC', 'JWT', 'JWKS', 'DCR', 'IAT', 'RAT',
  'RFC 7591', 'RFC 7592', 'RFC 8707', 'PKCE', 'MCP',
  'URL', 'URI', 'HTTP', 'HTTPS', 'JSON',
];

// PLACEHOLDER_RE matches every ICU `{...}` placeholder and every
// printf-style `%s`/`%d`/`%v` token. The set is compared between
// source and translation per-key; any divergence is fatal.
//
// `{...}` matches greedy-but-not-cross-newline so multi-line JSON
// values still segment correctly.
const PLACEHOLDER_RE = /\{[^}\n]*\}|%[sdv]/g;

export function extractPlaceholders(value) {
  if (typeof value !== 'string') return [];
  const matches = value.match(PLACEHOLDER_RE);
  return matches ? [...matches].sort() : [];
}

export function detectInitialisms(value) {
  if (typeof value !== 'string') return [];
  const matches = value.match(/\b[A-Z]{2,6}\b/g);
  return matches ? [...new Set(matches)] : [];
}

// validateLeafTranslation runs cavekit-i18n-pipeline.md R2 per-key
// invariants on a single (source, translated) pair. Returns null on
// pass; an error message string on fail.
export function validateLeafTranslation(srcValue, transValue, key) {
  if (typeof srcValue !== 'string' || typeof transValue !== 'string') {
    return null; // non-string leaves bypass — we still wrote them through
  }
  const srcPlaceholders = extractPlaceholders(srcValue);
  const transPlaceholders = extractPlaceholders(transValue);
  if (JSON.stringify(srcPlaceholders) !== JSON.stringify(transPlaceholders)) {
    return `placeholder-set divergence at ${key}: source ${JSON.stringify(srcPlaceholders)}, translated ${JSON.stringify(transPlaceholders)}\n  src: ${srcValue}\n  trans: ${transValue}`;
  }
  const protectedTerms = [
    ...PROTECTED_GLOSSARY,
    ...detectInitialisms(srcValue),
  ];
  for (const term of protectedTerms) {
    if (srcValue.includes(term) && !transValue.includes(term)) {
      return `protected-glossary divergence at ${key}: term ${JSON.stringify(term)} missing from translation\n  src: ${srcValue}\n  trans: ${transValue}`;
    }
  }
  return null;
}

// validateTranslations walks the source + translations objects in
// lockstep, applying validateLeafTranslation at each leaf. Throws on
// the first divergence (the kit mandates fail-and-exit; partial writes
// would corrupt the locale file).
export function validateTranslations(source, translations, prefix = '') {
  if (translations === null || typeof translations !== 'object' || Array.isArray(translations)) {
    return;
  }
  for (const key of Object.keys(translations)) {
    const path = prefix === '' ? key : `${prefix}.${key}`;
    const srcVal = source?.[key];
    const transVal = translations[key];
    if (transVal !== null && typeof transVal === 'object' && !Array.isArray(transVal)) {
      validateTranslations(srcVal, transVal, path);
      continue;
    }
    const err = validateLeafTranslation(srcVal, transVal, path);
    if (err) throw new Error(err);
  }
}

const SYSTEM_PROMPT = [
  'You are a professional software localizer. Translate JSON values from English into the target locale.',
  '',
  'PROTECTED GLOSSARY — these terms MUST appear verbatim (same casing, same spacing) in the translation when they appear in the source:',
  ...PROTECTED_GLOSSARY.map(t => `  - ${t}`),
  'Plus any all-uppercase initialism of length 2-6 in the source MUST appear verbatim in the translation.',
  '',
  'PLACEHOLDER PRESERVATION — every {placeholder}, {0}, {count}, {userName}, %s, %d token MUST appear verbatim in the translation. Do NOT reorder, localize, or translate placeholders.',
  '',
  'OUTPUT FORMAT — respond with a SINGLE JSON object that has EXACTLY the same nested shape as the input. No prose. No markdown fences. No commentary. JSON ONLY.',
].join('\n');

// callClaude calls the Anthropic Messages API and validates the
// response per cavekit-i18n-pipeline.md R2: temperature 0, max_tokens
// >=8192, JSON-only output, per-key glossary + placeholder check.
// On any validation failure the caller exits non-zero per-locale (the
// kit mandates fail-and-exit; partial writes would corrupt the file).
async function callClaude(env, sourceMissingPayload, locale) {
  const userPrompt = [
    `Target locale: ${locale}`,
    '',
    'Translate every value in the JSON below into the target locale.',
    'Apply the protected-glossary and placeholder-preservation rules verbatim.',
    'Respond with JSON only.',
    '',
    JSON.stringify(sourceMissingPayload, null, 2),
  ].join('\n');

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': env.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: env.model,
      max_tokens: 8192,
      temperature: 0,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Anthropic API ${response.status}: ${detail.slice(0, 500)}`);
  }
  const body = await response.json();
  const text = body?.content?.[0]?.text;
  if (typeof text !== 'string') {
    throw new Error('Anthropic API: missing content[0].text');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error('Anthropic API returned non-JSON: ' + text.slice(0, 500));
  }
  validateTranslations(sourceMissingPayload, parsed);
  return parsed;
}

// extractMissingShape — given a source object and an array of missing
// dot-paths, build a nested object containing ONLY the missing leaves
// (with English source values). This is the payload sent to the API.
function extractMissingShape(source, missingPaths) {
  const out = {};
  for (const path of missingPaths) {
    const value = getPath(source, path);
    if (value === undefined) continue;
    setPath(out, path, value);
  }
  return out;
}

function setPath(obj, path, value) {
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (typeof cur[key] !== 'object' || cur[key] === null || Array.isArray(cur[key])) {
      cur[key] = {};
    }
    cur = cur[key];
  }
  cur[parts.at(-1)] = value;
}

// countLeaves — depth-first leaf count of a nested object (used for
// progress-line "(N keys added)" reporting).
function countLeaves(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return 1;
  let n = 0;
  for (const k of Object.keys(obj)) n += countLeaves(obj[k]);
  return n;
}

async function processLocale(env, source, locale) {
  const targetPath = join(env.targetDir, locale + '.json');
  if (!existsSync(targetPath)) {
    process.stderr.write(`skipped ${locale} (target file missing: ${targetPath})\n`);
    return;
  }
  const target = await readJSON(targetPath);
  const missing = diffMissingPaths(source, target);
  if (missing.length === 0) {
    process.stderr.write(`skipped ${locale} (no missing keys)\n`);
    return;
  }

  process.stderr.write(`translating ${locale} (${missing.length} missing keys)\n`);
  const sourcePayload = extractMissingShape(source, missing);
  const translations = await callClaude(env, sourcePayload, locale);

  const merged = mergeTranslations(source, target, translations);
  if (env.dryRun) {
    process.stderr.write(`would write ${locale} (${countLeaves(translations)} keys added) [dry-run]\n`);
    return;
  }
  await writeJSON(targetPath, merged);
  process.stderr.write(`wrote ${locale} (${countLeaves(translations)} keys added)\n`);
}

async function main() {
  const env = readEnv();
  const source = await readJSON(env.source);
  const locales = await discoverLocales(env);
  if (locales.length === 0) {
    process.stderr.write('no locales discovered — set I18N_LOCALES or check I18N_TARGET_DIR\n');
    return;
  }
  for (const locale of locales) {
    try {
      await processLocale(env, source, locale);
    } catch (err) {
      process.stderr.write(`failed ${locale}: ${err.message}\n`);
      process.exit(1);
    }
  }
}

// Only run main() when this file is invoked as the script entrypoint —
// importing it from a test for the exported validators must not fire
// the pipeline.
if (import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith('translate-i18n.mjs')) {
  main().catch(err => {
    process.stderr.write(`translate-i18n: fatal: ${err.message}\n`);
    process.exit(1);
  });
}
