// KBOX-6 amended (N1): an update must keep kb-join loadable. The installer asks the release's kb-join to load through the
// port method `joinCheck`, after `selfCheck` and with the same bound, before the release counts as healthy.
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { NODE_BIN, CADDY_BIN, installWorld, lockFor } from './support/install-world.ts';
import type { InstallWorld, Tree } from './support/install-world.ts';
import type { ReleaseUnits } from '../src/shell/installer.ts';
import { systemdUnits } from '../src/shell/systemd.ts';

const LOADING_INSTALL = "import { ok } from './part.ts';\nif (process.argv[2] === '--self-check') process.exitCode = ok;\n";
const LOADING_JOIN = "import { ok } from './join-part.ts';\nif (process.argv[2] === '--self-check') process.exitCode = ok;\n";
/** A release whose kb-install loads, so only the kb-join check can tell releases apart. */
const RELEASE: Tree = {
  'runtime.lock': lockFor(NODE_BIN, CADDY_BIN),
  'src/main-core.ts': 'new core\n',
  'src/cli/kb-install.ts': LOADING_INSTALL,
  'src/cli/part.ts': 'export const ok = 0;\n',
  'src/cli/kb-join.ts': LOADING_JOIN,
  'src/cli/join-part.ts': 'export const ok = 0;\n',
};

const real = (w: InstallWorld): ReleaseUnits =>
  systemdUnits({ systemctl: '/bin/false', units: [], healthSockets: [], clock: w.clock, wait: () => Promise.resolve(), nodeOf: () => process.execPath });

test('KBOX-6 a release whose kb-join, or a module it imports, fails to load is rolled back; one that loads is installed', async (t) => {
  const cases = [
    ['kb-join imports a module that throws', { ...RELEASE, 'src/cli/join-part.ts': "throw new Error('kb-join import fails');\n" }, 'rolled_back'],
    ['kb-join does not parse', { ...RELEASE, 'src/cli/kb-join.ts': 'import { ok from;\n' }, 'rolled_back'],
    ['control: a kb-join that loads', RELEASE, 'installed'],
  ] as const;
  for (const [name, tree, expected] of cases) {
    const w = await installWorld(t);
    w.units.checkSelf = real(w).selfCheck;
    w.units.checkJoin = real(w).joinCheck;
    const h = w.stage(tree);
    w.installRequest(h);
    await w.run();
    assert.equal(w.result(h), expected, name);
    assert.equal(w.current(), expected === 'installed' ? h : w.h0, name);
  }
});

// The test's own timeout is the oracle that the check did not wait for a process that never ends.
test('KBOX-6 the kb-join check is bounded: a kb-join that never exits is killed at the bound and fails', { timeout: 20_000 }, async (t) => {
  const w = await installWorld(t);
  const release = join(w.root, 'hangs');
  mkdirSync(join(release, 'src/cli'), { recursive: true });
  writeFileSync(join(release, 'src/cli/kb-join.ts'), 'setInterval(() => undefined, 1000);\n');
  assert.equal(await real(w).joinCheck(release, w.clock.now() + 300), false);
});

test('KBOX-6 the kb-join check runs with no environment', async (t) => {
  const w = await installWorld(t);
  const release = join(w.root, 'env');
  mkdirSync(join(release, 'src/cli'), { recursive: true });
  writeFileSync(join(release, 'src/cli/kb-join.ts'), "process.exitCode = Object.keys(process.env).some((k) => k.startsWith('KB_') || k === 'PATH') ? 1 : 0;\n");
  process.env['KB_PROBE'] = 'x';
  try {
    assert.equal(await real(w).joinCheck(release, w.clock.now() + 20_000), true);
  } finally {
    delete process.env['KB_PROBE'];
  }
});

test('KBOX-6 the installer checks the release with selfCheck then joinCheck under one bound, and a failing selfCheck rolls back', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed');
  const release = join(w.paths.releases, h);
  assert.deepEqual(w.units.selfChecks.map((c) => c.release), [release]);
  assert.deepEqual(w.units.joinChecks.map((c) => c.release), [release]);
  assert.equal(w.units.joinChecks[0]?.until, w.units.selfChecks[0]?.until, 'one bound for both');

  const w2 = await installWorld(t);
  w2.units.checkSelf = () => Promise.resolve(false);
  const h2 = w2.stage({ ...RELEASE, 'README.md': 'two\n' });
  w2.installRequest(h2);
  await w2.run();
  assert.equal(w2.result(h2), 'rolled_back');
  assert.equal(w2.current(), w2.h0);
  assert.equal(w2.units.selfChecks.length, 1);
});

test('KBOX-6 a failing joinCheck alone rolls back, and the order is selfCheck first', async (t) => {
  const w = await installWorld(t);
  const order: string[] = [];
  w.units.checkSelf = () => (order.push('self'), Promise.resolve(true));
  w.units.checkJoin = () => (order.push('join'), Promise.resolve(false));
  const h = w.stage(RELEASE);
  w.installRequest(h);
  await w.run();
  assert.deepEqual(order, ['self', 'join']);
  assert.equal(w.result(h), 'rolled_back');
  assert.equal(w.current(), w.h0);
});
