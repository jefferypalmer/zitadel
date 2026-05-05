// Pure merge / diff logic for translate-i18n.mjs.
//
// Implements cavekit-i18n-pipeline.md R4: idempotent merge — never
// overwrite existing target values; preserve source key order at each
// nesting level; recursive diff against arbitrary nested object shapes.
//
// Exported as ES modules so the main pipeline (T-004) and the unit
// tests (T-005) can both import the same code path.

/**
 * Recursively collect "leaf" key paths from `obj`. A leaf is any value
 * that is not a plain object (so strings, numbers, arrays, null all
 * count as leaves). Returns an array of dot-joined paths.
 *
 * Example: {a: 1, b: {c: 2, d: {e: 3}}} → ["a", "b.c", "b.d.e"].
 */
export function collectLeafPaths(obj, prefix = '') {
  const paths = [];
  if (!isPlainObject(obj)) {
    if (prefix !== '') paths.push(prefix);
    return paths;
  }
  for (const key of Object.keys(obj)) {
    const childPath = prefix === '' ? key : `${prefix}.${key}`;
    const value = obj[key];
    if (isPlainObject(value)) {
      paths.push(...collectLeafPaths(value, childPath));
    } else {
      paths.push(childPath);
    }
  }
  return paths;
}

/**
 * Compute the set of leaf paths present in `source` but missing in
 * `target`. "Missing" means the path either doesn't resolve, resolves
 * to `undefined`, or resolves to `null` (Codex F-101 / P3 — explicit
 * nulls in the target file are treated as placeholders awaiting
 * translation rather than authoritative empty values, matching the
 * R4 idempotent-merge intent). Empty-string `""` values still count
 * as present so an operator can intentionally null-out a label.
 */
export function diffMissingPaths(source, target) {
  const sourcePaths = collectLeafPaths(source);
  const missing = [];
  for (const path of sourcePaths) {
    const v = getPath(target, path);
    if (v === undefined || v === null) {
      missing.push(path);
    }
  }
  return missing;
}

/**
 * Return the value at `path` in `obj` if every step is a defined
 * property (own or inherited via plain object). `undefined` otherwise.
 */
export function getPath(obj, path) {
  const parts = path.split('.');
  let cur = obj;
  for (const part of parts) {
    if (!isPlainObject(cur) || !(part in cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

function hasPath(obj, path) {
  return getPath(obj, path) !== undefined;
}

/**
 * Merge `translations` (a flat or nested object whose paths overlap
 * with `target`'s missing paths) into a new target. Existing target
 * keys are bit-identical in the result (object reference may change,
 * but every leaf value present in `target` survives unchanged).
 *
 * Final key order at each level mirrors `source`'s key order, so the
 * file diff stays stable run-to-run regardless of the order the API
 * returned the translations in. Keys present in `target` but not in
 * `source` are kept (and appended after the source-ordered keys at
 * each level) so a manual translation that's no longer in source
 * isn't silently dropped.
 */
export function mergeTranslations(source, target, translations) {
  const result = {};
  const sourceKeys = isPlainObject(source) ? Object.keys(source) : [];
  const targetKeys = isPlainObject(target) ? Object.keys(target) : [];
  const seen = new Set();

  for (const key of sourceKeys) {
    seen.add(key);
    const srcVal = source[key];
    const tgtVal = isPlainObject(target) ? target[key] : undefined;
    const transVal = isPlainObject(translations) ? translations[key] : undefined;
    result[key] = pick(srcVal, tgtVal, transVal);
  }
  for (const key of targetKeys) {
    if (seen.has(key)) continue;
    result[key] = isPlainObject(target) ? target[key] : undefined;
  }
  return result;
}

function pick(srcVal, tgtVal, transVal) {
  if (isPlainObject(srcVal)) {
    return mergeTranslations(srcVal, tgtVal ?? {}, transVal ?? {});
  }
  if (tgtVal !== undefined) return tgtVal;
  if (transVal !== undefined) return transVal;
  return srcVal;
}

export function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
