// Unit tests for translation-correctness validators in translate-i18n.mjs.
// cavekit-i18n-pipeline.md R2 (T-012) — placeholder preservation, glossary
// preservation, all-caps initialism detection.
//
// Run with: node --test console/scripts/translate-i18n.validate.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  PROTECTED_GLOSSARY,
  extractPlaceholders,
  detectInitialisms,
  validateLeafTranslation,
  validateTranslations,
} from './translate-i18n.mjs';

test('extractPlaceholders: ICU and printf tokens are extracted', () => {
  assert.deepEqual(extractPlaceholders('hi {name}, you have %d items'),
    ['%d', '{name}'].sort());
  assert.deepEqual(extractPlaceholders('plain string'), []);
  assert.deepEqual(extractPlaceholders('mixed: {0} {count} %s %d'),
    ['%d', '%s', '{0}', '{count}'].sort());
});

test('detectInitialisms: 2-6 char all-caps tokens', () => {
  assert.deepEqual(detectInitialisms('Use OAuth and OIDC for SSO').sort(),
    ['OAuth', 'OIDC', 'SSO'].sort().filter(t => /^[A-Z]+$/.test(t)));
  assert.deepEqual(detectInitialisms('LONGERTHANSIX is too long'), []);
});

test('PROTECTED_GLOSSARY contains the kit-mandated terms', () => {
  for (const t of ['Zitadel', 'OAuth', 'OIDC', 'JWT', 'JWKS', 'DCR',
                   'IAT', 'RAT', 'RFC 7591', 'RFC 7592', 'RFC 8707',
                   'PKCE', 'MCP', 'URL', 'URI', 'HTTP', 'HTTPS', 'JSON']) {
    assert.ok(PROTECTED_GLOSSARY.includes(t), `glossary missing ${t}`);
  }
});

test('validateLeafTranslation: matching placeholders + glossary passes', () => {
  const err = validateLeafTranslation(
    'OAuth client {name} has %d errors',
    'Cliente OAuth {name} tiene %d errores',
    'k.test',
  );
  assert.equal(err, null);
});

test('validateLeafTranslation: placeholder set divergence is fatal', () => {
  const err = validateLeafTranslation(
    'hi {name}',
    'hola {nombre}',
    'k.greeting',
  );
  assert.match(err, /placeholder-set divergence at k\.greeting/);
});

test('validateLeafTranslation: missing protected term is fatal', () => {
  const err = validateLeafTranslation(
    'OAuth flow failed',
    'Flujo de autenticación fallido',
    'k.flow',
  );
  assert.match(err, /protected-glossary divergence at k\.flow.*OAuth/s);
});

test('validateLeafTranslation: detected initialism (in source) preserved required', () => {
  const err = validateLeafTranslation(
    'Use the SSO endpoint',
    'Use el endpoint de inicio único',
    'k.sso',
  );
  // SSO is detected as an initialism and required to appear verbatim.
  assert.match(err, /SSO/);
});

test('validateLeafTranslation: non-string leaves bypass', () => {
  assert.equal(validateLeafTranslation(42, 42, 'k.num'), null);
  assert.equal(validateLeafTranslation(null, 'foo', 'k.nul'), null);
});

test('validateTranslations: nested tree pass', () => {
  const source = { a: 'OAuth ok', b: { c: 'count {n}' } };
  const trans = { a: 'OAuth bien', b: { c: 'recuento {n}' } };
  assert.doesNotThrow(() => validateTranslations(source, trans));
});

test('validateTranslations: nested tree fails on first divergence', () => {
  const source = { a: 'ok', b: { c: 'count {n}' } };
  const trans = { a: 'ok', b: { c: 'recuento {m}' } };
  assert.throws(() => validateTranslations(source, trans), /b\.c/);
});

test('validateTranslations: multiple placeholders compared as a set, order-independent', () => {
  // Spanish often reorders {0} {1}; the kit forbids reordering across
  // languages where both tokens appear, but compares them as a sorted
  // set — a translation that drops a token still fails.
  const source = { x: '{0} of {1}' };
  const trans = { x: '{1} of {0}' };
  assert.doesNotThrow(() => validateTranslations(source, trans),
    'reordered placeholders are accepted (set equality, not order)');

  const dropped = { x: 'just {0}' };
  assert.throws(() => validateTranslations(source, dropped), /placeholder-set divergence/);
});
