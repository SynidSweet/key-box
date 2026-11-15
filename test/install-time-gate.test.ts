// KBOX-6 (amended, install-time-gate): until the box has an authenticated time, kb-install refuses every request without
// reading the clock, undoes a half-done switch without a restart, and the update self-check refuses a release whose
// time-gate wiring disagrees with the host. Each test names the fault it catches.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import { installWorld, addActionOf } from './support/install-world.ts';
import type { InstallWorld, Tree } from './support/install-world.ts';
import { NODE_BIN, CADDY_BIN, lockFor } from './support/install-world.ts';
import { WORDLIST } from './support/approve-world.ts';
import { runInstaller } from '../src/shell/installer.ts';
import { systemdUnits } from '../src/shell/systemd.ts';
import { TIME_OK_FILE } from '../src/pure/time-gate.ts';

const CLI = new URL('../src/cli/kb-install.ts', import.meta.url).pathname;
const DEPLOY = new URL('../deploy/kb-install.service', import.meta.url).pathname;
const RELEASE_1: Tree = { 'runtime.lock': lockFor(NODE_BIN, CADDY_BIN), 'src/main-core.ts': 'new core\n', 'run.sh': { body: '#!/bin/sh\n', exec: true } };

const STALE_EARLY = Date.parse('2024-01-01T00:00:00Z');
const DEADLINE = Date.parse('2026-11-15T12:00:00Z');

/** A run of the real installer over the world, with the time gate given (the world's own run has none). */
const runWith = (w: InstallWorld, timeAuthenticated: (() => boolean) | undefined): Promise<unknown> =>
  runInstaller({ paths: w.paths, units: w.units, clock: w.clock, wordlist: WORDLIST, domain: 'box.example', ...(timeAuthenticated === undefined ? {} : { timeAuthenticated }) });

const trustAddRequest = (w: InstallWorld, name: string, deadline: number | null = DEADLINE): string => {
  const added = w.trusted('ap-second-0002', softApprover());
  w.request(name, { kind: 'trust', change: 'approver_add', approval: w.proof(addActionOf(added)), approver: added, ...(deadline === null ? {} : { deadline }) });
  return readFileSync(join(w.paths.staging, `${name}.request`), 'utf8');
};

test('KBOX-6 M-A: on a stale-early clock a trust request whose deadline passed in real time is refused late while the time is not authenticated, and applies with the same clock once it is', async (t) => {
  const w = await installWorld(t);
  w.clock.advance(STALE_EARLY - w.clock.now());
  const before = readFileSync(w.paths.trustFile, 'utf8');
  const body = trustAddRequest(w, 'add');
  await runWith(w, () => false);
  assert.equal(w.result('add'), 'refused:late');
  assert.equal(readFileSync(w.paths.trustFile, 'utf8'), before, 'trust.json is unchanged');
  // The same request again: had the refusal spent the approval, it would now be refused spent.
  writeFileSync(join(w.paths.staging, 'add.request'), body);
  await runWith(w, () => true);
  assert.equal(w.result('add'), 'applied', 'control: with the gate open and the same clock the request applies, so the gate refused it');
});

test('KBOX-6 an install request is refused timeout while the time is not authenticated, and leaves no release, no .tmp, no switching record and no unit call', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await runWith(w, () => false);
  assert.equal(w.result(h), 'refused:timeout');
  assert.deepEqual(w.releases(), [w.h0]);
  assert.equal(existsSync(join(w.paths.results, 'switching')), false);
  assert.deepEqual(w.units.restarts, []);
  assert.deepEqual(w.units.selfChecks, []);
  assert.equal(w.current(), w.h0);
});

test('KBOX-6 a switching record is undone without any restart while the time is not authenticated; authenticated, it restarts once (today)', async (t) => {
  for (const [authenticated, restarts] of [[false, 0], [true, 1]] as const) {
    const w = await installWorld(t);
    const h = w.stage(RELEASE_1);
    w.installRequest(h);
    assert.equal(w.runKilledAt('afterSwitch').signal, 'SIGKILL');
    assert.equal(w.current(), h);
    await runWith(w, () => authenticated);
    assert.equal(w.current(), w.h0, `authenticated=${authenticated}: current is back on the base`);
    assert.deepEqual(w.releases(), [w.h0]);
    assert.equal(w.result(h), 'failed:interrupted');
    assert.equal(w.units.restarts.length, restarts, `authenticated=${authenticated}: restart calls`);
  }
});

test('KBOX-6 a .settled marker still removes its result while the time is not authenticated', async (t) => {
  const w = await installWorld(t);
  writeFileSync(join(w.paths.results, 'old.result'), 'applied');
  writeFileSync(join(w.paths.staging, 'old.settled'), '');
  await runWith(w, () => false);
  assert.equal(existsSync(join(w.paths.results, 'old.result')), false);
  assert.equal(existsSync(join(w.paths.staging, 'old.settled')), false);
});

// --- the CLI -------------------------------------------------------------------------------------------------------

const cliEnv = (w: InstallWorld, extra: Record<string, string>): Record<string, string> => ({
  KB_STAGING_DIR: w.paths.staging,
  KB_RELEASES_DIR: w.paths.releases,
  KB_CURRENT: w.paths.current,
  KB_TRUST_FILE: w.paths.trustFile,
  KB_CODES_DIR: w.paths.codesDir,
  KB_INSTALL_RESULTS: w.paths.results,
  KB_BOOT_ID_FILE: w.paths.bootIdFile,
  KB_SYSTEMCTL: '/bin/false',
  ...extra,
});

test('KBOX-6 CLI: KB_TIME_OK_FILE naming a missing file refuses a trust request late; the file present, or the variable unset, gives today\'s result', async (t) => {
  const cases = [
    ['missing file', (w: InstallWorld) => ({ KB_TIME_OK_FILE: join(w.root, 'no-such-ok') }), 'refused:late'],
    ['file present', (w: InstallWorld) => { writeFileSync(join(w.root, 'ok'), ''); return { KB_TIME_OK_FILE: join(w.root, 'ok') }; }, 'applied'],
    ['variable unset', () => ({}), 'applied'],
  ] as const;
  for (const [name, extra, expected] of cases) {
    const w = await installWorld(t);
    trustAddRequest(w, 'add', null);
    const run = spawnSync(process.execPath, [CLI], { env: cliEnv(w, extra(w)), encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(w.result('add'), expected, name);
  }
});

test('KBOX-6 deploy: kb-install.service sets KB_TIME_OK_FILE to the constant of src/pure/time-gate.ts and keeps TimeoutStartSec=120s', () => {
  const unit = readFileSync(DEPLOY, 'utf8');
  assert.ok(unit.split('\n').includes(`Environment=KB_TIME_OK_FILE=${TIME_OK_FILE}`));
  assert.ok(unit.split('\n').includes('TimeoutStartSec=120s'));
});

test('KBOX-6 N-M3: kb-install --self-check --for-update fails unless KB_TIME_OK_FILE equals the constant; plain --self-check is unchanged', () => {
  const run = (args: string[], env: Record<string, string>): number | null => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' }).status;
  const forUpdate = ['--self-check', '--for-update'];
  assert.notEqual(run(forUpdate, {}), 0, 'variable unset: the gate would be off');
  assert.notEqual(run(forUpdate, { KB_TIME_OK_FILE: '/run/keybox-time/ok2' }), 0, 'path moved');
  assert.equal(run(forUpdate, { KB_TIME_OK_FILE: TIME_OK_FILE }), 0);
  assert.equal(run(['--self-check'], {}), 0, 'control: plain self-check with the variable unset');
});

test('KBOX-6 N-M3: the real selfCheck spawns the release kb-install with --self-check --for-update and exactly one variable, KB_TIME_OK_FILE; with no value, none', async (t) => {
  const w = await installWorld(t);
  const release = join(w.root, 'fake-release');
  mkdirSync(join(release, 'src/cli'), { recursive: true });
  const out = join(w.root, 'seen.json');
  writeFileSync(join(release, 'src/cli/kb-install.ts'), `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(out)}, JSON.stringify({ env: process.env, args: process.argv.slice(2) }));\n`);
  for (const value of ['/run/keybox-time/ok', undefined]) {
    const units = systemdUnits({ systemctl: '/bin/false', units: [], healthSockets: [], clock: w.clock, wait: () => Promise.resolve(), nodeOf: () => process.execPath, ...(value === undefined ? {} : { timeOkFile: value }) });
    assert.equal(await units.selfCheck(release, w.clock.now() + 20_000), true);
    const seen = JSON.parse(readFileSync(out, 'utf8')) as { env: Record<string, string>; args: string[] };
    assert.deepEqual(seen.args, ['--self-check', '--for-update']);
    assert.deepEqual(seen.env, value === undefined ? {} : { KB_TIME_OK_FILE: value });
  }
});
