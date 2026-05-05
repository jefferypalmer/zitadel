#!/usr/bin/env node
//
// translate-i18n.test.mjs — CI reproducibility verifier.
// cavekit-i18n-pipeline.md R3 (T-015).
//
// Runs the pipeline twice with identical inputs and asserts the second
// run produces zero new writes. The pipeline already runs at temperature 0
// with the same prompt + model; the second run's `diffMissingPaths`
// should be empty for every locale (because the first run filled all
// missing keys), so the second run reports `skipped <locale> (no
// missing keys)` for every target.
//
// When ANTHROPIC_API_KEY is unset the verifier exits zero with a
// `skipped` log line — local developers can run the rest of the test
// suite without provisioning an API key.
//
// Always passes --dry-run to the underlying pipeline so the working
// tree is never modified — diff inspection is via stderr output only.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PIPELINE = resolve(__dirname, 'translate-i18n.mjs');

function runPipelineDryRun(env) {
  const result = spawnSync('node', [PIPELINE], {
    env: { ...process.env, ...env, I18N_DRY_RUN: 'true' },
    encoding: 'utf8',
  });
  return {
    stderr: result.stderr || '',
    status: result.status,
    error: result.error,
  };
}

function countWrites(stderr) {
  // First-run "would write" / second-run wrote / skipped — only count
  // "wrote" or "would write". Both forms imply a translation diff.
  const lines = stderr.split('\n').filter(Boolean);
  return lines.filter(l => /^(?:wrote|would write) /.test(l)).length;
}

function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    process.stderr.write('skipped — ANTHROPIC_API_KEY not configured\n');
    process.exit(0);
  }

  process.stderr.write('translate-i18n verify: first run ...\n');
  const first = runPipelineDryRun({});
  process.stderr.write(first.stderr);
  if (first.status !== 0 || first.error) {
    process.stderr.write(`first run failed: status=${first.status}, err=${first.error?.message}\n`);
    process.exit(1);
  }

  process.stderr.write('translate-i18n verify: second run ...\n');
  const second = runPipelineDryRun({});
  process.stderr.write(second.stderr);
  if (second.status !== 0 || second.error) {
    process.stderr.write(`second run failed: status=${second.status}, err=${second.error?.message}\n`);
    process.exit(1);
  }

  const writes = countWrites(second.stderr);
  if (writes === 0) {
    process.stderr.write('OK — pipeline is reproducible (zero new writes on second run)\n');
    process.exit(0);
  }

  process.stderr.write(
    `FAIL — second run produced ${writes} write(s); locales drifted from main.\n` +
    `Run \`pnpm translate-i18n\` locally and commit the regenerated files.\n`
  );
  process.exit(1);
}

main();
