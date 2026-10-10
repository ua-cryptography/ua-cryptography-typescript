/**
 * Compiles src/ modules for Node, so the tests exercise the very code the page runs, and a checker() with
 * check(name, actual, expected) and a "N passed, M failed" summary — no test framework.
 */
import { build } from 'esbuild';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = dirname(dirname(fileURLToPath(import.meta.url)));

export async function load(...modules) {
  const result = await build({
    stdin: {
      contents: modules.map((name) => `export * from './src/${name}';`).join('\n'),
      resolveDir: root,
      loader: 'ts',
    },
    bundle: true,
    format: 'cjs',
    platform: 'node',
    target: 'node22',
    write: false,
    logLevel: 'silent',
  });
  const dir = await mkdtemp(join(tmpdir(), 'ua-crypto-test-'));
  const file = join(dir, 'bundle.cjs');
  await writeFile(file, result.outputFiles[0].text);
  try {
    return createRequire(import.meta.url)(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export function checker() {
  let passed = 0;
  let failed = 0;
  const check = (name, actual, expected) => {
    const a = JSON.stringify(actual, (_, v) => (typeof v === 'bigint' ? v.toString(16) : v));
    const b = JSON.stringify(expected, (_, v) => (typeof v === 'bigint' ? v.toString(16) : v));
    if (a === b) passed += 1;
    else {
      failed += 1;
      console.error(`FAIL  ${name}\n  expected: ${b}\n  actual:   ${a}`);
    }
  };
  const done = (label) => {
    console.log(`${label}: ${passed} passed, ${failed} failed`);
    if (failed) process.exitCode = 1;
  };
  return { check, done };
}
