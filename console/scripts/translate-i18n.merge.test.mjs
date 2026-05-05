// Unit tests for translate-i18n.merge.mjs.
// cavekit-i18n-pipeline.md R4 (T-005) — both flat and nested cases.
//
// Run with: node --test console/scripts/translate-i18n.merge.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  collectLeafPaths,
  diffMissingPaths,
  getPath,
  mergeTranslations,
} from './translate-i18n.merge.mjs';

test('collectLeafPaths: flat object', () => {
  assert.deepEqual(collectLeafPaths({ a: 1, b: 2, c: 3 }).sort(), ['a', 'b', 'c']);
});

test('collectLeafPaths: nested object', () => {
  const got = collectLeafPaths({ x: { y: 1, z: { w: 2 } }, a: 'hi' }).sort();
  assert.deepEqual(got, ['a', 'x.y', 'x.z.w']);
});

test('getPath: nested miss returns undefined', () => {
  assert.equal(getPath({ a: { b: 1 } }, 'a.b.c'), undefined);
  assert.equal(getPath({ a: { b: 1 } }, 'a.b'), 1);
  assert.equal(getPath({}, 'a'), undefined);
});

test('diffMissingPaths: target with subset returns the diff', () => {
  const source = { a: 1, b: 2, c: 3 };
  const target = { a: 'X' };
  assert.deepEqual(diffMissingPaths(source, target).sort(), ['b', 'c']);
});

test('diffMissingPaths: empty diff when target is full', () => {
  const source = { a: 1, b: 2 };
  const target = { a: 'X', b: 'Y' };
  assert.deepEqual(diffMissingPaths(source, target), []);
});

test('R4 flat case: {a:1,b:2,c:3} + {a:X} + {b:Y,c:Z} → {a:X,b:Y,c:Z}', () => {
  const source = { a: 1, b: 2, c: 3 };
  const target = { a: 'X' };
  const translations = { b: 'Y', c: 'Z' };

  const merged = mergeTranslations(source, target, translations);

  assert.deepEqual(merged, { a: 'X', b: 'Y', c: 'Z' });
  // Source key order at each level.
  assert.deepEqual(Object.keys(merged), ['a', 'b', 'c']);
});

test('R4 nested case: {x:{y:1,z:2}} + {x:{y:A}} + {x:{z:B}} → {x:{y:A,z:B}}', () => {
  const source = { x: { y: 1, z: 2 } };
  const target = { x: { y: 'A' } };
  const translations = { x: { z: 'B' } };

  const merged = mergeTranslations(source, target, translations);

  assert.deepEqual(merged, { x: { y: 'A', z: 'B' } });
  assert.deepEqual(Object.keys(merged), ['x']);
  assert.deepEqual(Object.keys(merged.x), ['y', 'z']);
});

test('mergeTranslations: existing target values are preserved bit-identical', () => {
  const source = { a: 1, b: 2 };
  const target = { a: 'manual translation' };
  const translations = { a: 'API SHOULD NOT WIN', b: 'API result' };

  const merged = mergeTranslations(source, target, translations);

  assert.equal(merged.a, 'manual translation');
  assert.equal(merged.b, 'API result');
});

test('mergeTranslations: source order preserved across nesting levels', () => {
  // Source declares b before a at top level, w before y at inner level.
  const source = { b: { w: 1, y: 2 }, a: 3 };
  const target = {};
  const translations = { b: { w: 'W', y: 'Y' }, a: 'A' };

  const merged = mergeTranslations(source, target, translations);

  assert.deepEqual(Object.keys(merged), ['b', 'a']);
  assert.deepEqual(Object.keys(merged.b), ['w', 'y']);
});

test('mergeTranslations: empty translations + full target = identity', () => {
  const source = { a: 1, b: 2 };
  const target = { a: 'X', b: 'Y' };
  const merged = mergeTranslations(source, target, {});
  assert.deepEqual(merged, { a: 'X', b: 'Y' });
});

test('mergeTranslations: target keys not in source are kept (manual override)', () => {
  const source = { a: 1 };
  const target = { a: 'X', legacy: 'Z' };
  const merged = mergeTranslations(source, target, {});
  assert.equal(merged.legacy, 'Z');
});
