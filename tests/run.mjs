/** Runs every unit test file in turn (Node only; the page is tested by tests/app.mjs). */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { root } from '../tools/load.mjs';

const files = ['hash', 'dstu4145', 'certificates', 'c14n', 'verify', 'sign', 'revocation', 'online'];
let failed = false;
for (const name of files) {
  const run = spawnSync(process.execPath, [join(root, 'tests', `${name}.mjs`)], { stdio: 'inherit' });
  if (run.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
