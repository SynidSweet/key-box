// KBOX-6: kb-install, the root installer. It verifies the owner's approval itself against the root copy of the approvers,
// installs only bytes it read through descriptors it holds and hashed itself, over the base the approval names, rolls back
// a failed health check and changes trust.json only on an approved change or a code root checks. Temp dirs and fake units;
// the uid half (core cannot read root's files) is test/install-root.test.ts, run as root in a container by the gate.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, closeSync, constants, existsSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import { COMMIT, NODE_BIN, CADDY_BIN, RELEASE_0, addActionOf, hashOf, installWorld, lockFor, sha256Hex } from './support/install-world.ts';
import type { InstallWorld, Tree } from './support/install-world.ts';

const RELEASE_1: Tree = { 'runtime.lock': lockFor(NODE_BIN, CADDY_BIN), 'src/main-core.ts': 'new core\n', 'src/cli/kb-install.ts': 'installer\n', 'README.md': 'v1\n', 'run.sh': { body: '#!/bin/sh\n', exec: true } };

/** Every file under a directory, as path -> bytes. */
function filesUnder(dir: string, prefix = ''): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.isDirectory()) for (const [k, v] of filesUnder(join(dir, e.name), rel)) out.set(k, v);
    else if (e.isFile()) out.set(rel, readFileSync(join(dir, e.name))); // `current` is a link to a release walked anyway
  }
  return out;
}

const mkfifo = (path: string): void => {
  const made = spawnSync('mkfifo', [path]);
  assert.equal(made.status, 0, 'mkfifo is needed to plant a FIFO');
};

/** Nothing was copied: no releases/<H> or <H>.tmp, and current is still H0. */
function nothingCopied(w: InstallWorld, h: string): void {
  assert.deepEqual(w.releases(), [w.h0], 'only the running release is under releases/');
  assert.equal(w.current(), w.h0, 'current is unchanged');
  assert.equal(existsSync(join(w.paths.releases, `${h}.tmp`)), false);
  assert.deepEqual(w.units.restarts, [], 'no unit was restarted');
}

async function refusedProof(w: InstallWorld, h: string, code: 'no_proof' | 'bad_proof'): Promise<void> {
  await w.run();
  assert.equal(w.result(h), `refused:${code}`);
  nothingCopied(w, h);
}

// --- its own proof of approval ----------------------------------------------------------------------------------------

test('KBOX-6 a proof valid for H over the running base installs exactly the staged bytes and restarts the units', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed');
  assert.equal(w.current(), h);
  const installed = filesUnder(join(w.paths.releases, h));
  for (const [path, v] of Object.entries(RELEASE_1)) assert.deepEqual(installed.get(path), Buffer.from(typeof v === 'object' && 'body' in v ? v.body : v), path);
  assert.deepEqual(installed.get('bin/node'), NODE_BIN, 'the unchanged node binary is taken from the running release, checked');
  assert.deepEqual(w.units.restarts, [h]);
  assert.equal(existsSync(join(w.paths.staging, `${h}.request`)), false, 'the request works once');
});

test('KBOX-6 a request with no proof is refused no_proof with nothing copied', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h, 'none');
  await refusedProof(w, h, 'no_proof');
});

test('KBOX-6 a request keybox wrote itself with the right H and base and a proof of garbage is refused bad_proof', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const proof = w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 });
  w.installRequest(h, { ...proof, signature_b64: Buffer.from('not a signature').toString('base64url') });
  await refusedProof(w, h, 'bad_proof');
});

test('KBOX-6 a proof whose device-key signature is invalid is refused bad_proof', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const proof = w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 });
  w.installRequest(h, { ...proof, device_signature_b64: Buffer.from(w.owner.deviceSign(new Uint8Array(32))).toString('base64url') });
  await refusedProof(w, h, 'bad_proof');
});

test('KBOX-6 a valid passkey signature with the device key of another approver in trust.json is refused bad_proof', async (t) => {
  const w = await installWorld(t);
  const other = softApprover();
  w.writeTrust([{ id: w.ownerId, a: w.owner }, { id: 'ap-other-00002', a: other }]);
  const h = w.stage(RELEASE_1);
  w.installRequest(h, w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 }, { deviceOf: other }));
  await refusedProof(w, h, 'bad_proof');
});

for (const [what, action] of [
  ['another H', (h: string, h0: string) => ({ kind: 'install_update', install: 'f'.repeat(64), commit: COMMIT, base: h0 })],
  ['another commit', (h: string, h0: string) => ({ kind: 'install_update', install: h, commit: 'cd'.repeat(20), base: h0 })],
  ['another base', (h: string) => ({ kind: 'install_update', install: h, commit: COMMIT, base: 'e'.repeat(64) })],
  ['another kind', () => ({ kind: 'approver_add' })],
] as const) {
  test(`KBOX-6 a proof signed for ${what} is refused bad_proof with nothing copied`, async (t) => {
    const w = await installWorld(t);
    const h = w.stage(RELEASE_1);
    w.installRequest(h, w.proof(action(h, w.h0)));
    await refusedProof(w, h, 'bad_proof');
  });
}

test('KBOX-6 a proof by an approver not in trust.json (never copied, or removed from it) is refused bad_proof', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const stranger = softApprover();
  w.installRequest(h, w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 }, { approver: stranger, approverId: 'ap-stranger-01' }));
  await refusedProof(w, h, 'bad_proof');

  const w2 = await installWorld(t);
  const h2 = w2.stage(RELEASE_1);
  w2.writeTrust([{ id: 'ap-other-00002', a: softApprover() }]); // the owner was removed from the root copy
  w2.installRequest(h2);
  await refusedProof(w2, h2, 'bad_proof');
});

test('KBOX-6 an assertion with UV clear, the wrong origin, the wrong rpIdHash or another type is refused bad_proof', async (t) => {
  for (const quirks of [{ flags: 0x01 }, { origin: 'https://keys.evil.example' }, { rpIdHashOf: 'keys.evil.example' }, { type: 'webauthn.create' }]) {
    const w = await installWorld(t);
    const h = w.stage(RELEASE_1);
    w.installRequest(h, w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 }, { quirks }));
    await refusedProof(w, h, 'bad_proof');
  }
});

test('KBOX-6 with no trust.json no install proof can verify: refused bad_proof', async (t) => {
  const w = await installWorld(t, { trust: false });
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await refusedProof(w, h, 'bad_proof');
});

// --- the base and the hash --------------------------------------------------------------------------------------------

test('KBOX-6 a request over another base is refused base, and H equal to H0 is refused already_current', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const other = 'e'.repeat(64);
  w.installRequest(h, w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: other }), other);
  await w.run();
  assert.equal(w.result(h), 'refused:base');
  nothingCopied(w, h);
  w.installRequest(w.h0, w.proof({ kind: 'install_update', install: w.h0, commit: COMMIT, base: w.h0 }));
  await w.run();
  assert.equal(w.result(w.h0), 'refused:already_current');
});

test('KBOX-6 a request replayed after a success is refused base (current is no longer H0)', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const proof = w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 });
  w.installRequest(h, proof);
  await w.run();
  assert.equal(w.result(h), 'installed');
  w.installRequest(h, proof);
  await w.run();
  assert.equal(w.result(h), 'refused:base');
  assert.equal(w.current(), h);
});

test('KBOX-6 an install approval works once: replayed after a later approved revert to its base it is refused spent', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const forward = w.proof({ kind: 'install_update', install: h, commit: COMMIT, base: w.h0 });
  w.installRequest(h, forward);
  await w.run();
  assert.equal(w.result(h), 'installed');
  w.stage(RELEASE_0);
  w.installRequest(w.h0, w.proof({ kind: 'install_update', install: w.h0, commit: COMMIT, base: h }), h);
  await w.run();
  assert.equal(w.result(w.h0), 'installed', 'the owner approved going back');
  w.installRequest(h, forward);
  await w.run();
  assert.equal(w.result(h), 'refused:spent');
  assert.equal(w.current(), w.h0);
});

test('KBOX-6 an approval of H1 cannot install H2: staging that holds another tree under H1 is refused hash', async (t) => {
  const w = await installWorld(t);
  const h1 = hashOf(RELEASE_1);
  w.stage({ ...RELEASE_1, 'src/main-core.ts': 'a backdoor\n' }, h1);
  w.installRequest(h1);
  await w.run();
  assert.equal(w.result(h1), 'refused:hash');
  nothingCopied(w, h1);
});

test('KBOX-6 a staged tree changed after approval (a file added) is refused hash', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  writeFileSync(join(w.paths.staging, h, 'extra.ts'), 'added after the approval\n');
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'refused:hash');
  nothingCopied(w, h);
});

// --- the safe copy ----------------------------------------------------------------------------------------------------

test('KBOX-6 a staged file swapped for a symlink to a root-only canary between listing and open is refused not_regular, and the canary is copied nowhere', async (t) => {
  const w = await installWorld(t);
  const canary = `canary-${sha256Hex(String(Math.random()))}`;
  const secret = join(w.root, 'root-only-secret');
  writeFileSync(secret, canary, { mode: 0o600 });
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({
    afterList: (rel) => {
      if (rel !== 'README.md') return;
      rmSync(join(w.paths.staging, h, rel));
      symlinkSync(secret, join(w.paths.staging, h, rel));
    },
  });
  assert.equal(w.result(h), 'refused:not_regular');
  nothingCopied(w, h);
  for (const [path, bytes] of filesUnder(join(w.root, 'opt'))) assert.equal(bytes.includes(canary), false, path);
  for (const [path, bytes] of filesUnder(w.paths.results)) assert.equal(bytes.includes(canary), false, path);
});

test('KBOX-6 a staged directory swapped for a symlink between listing and open is refused not_regular', async (t) => {
  const w = await installWorld(t);
  const elsewhere = join(w.root, 'elsewhere');
  mkdirSync(elsewhere);
  writeFileSync(join(elsewhere, 'main-core.ts'), 'new core\n');
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({
    afterList: (rel) => {
      if (rel !== 'src') return;
      renameSync(join(w.paths.staging, h, 'src'), join(w.root, 'moved-src'));
      symlinkSync(join(w.root, 'moved-src'), join(w.paths.staging, h, 'src'));
    },
  });
  assert.equal(w.result(h), 'refused:not_regular');
  nothingCopied(w, h);
});

test('KBOX-6 a symlink, a hard link and a FIFO planted in staging are each refused not_regular, and the run does not hang', async (t) => {
  const plants: readonly [string, (dir: string, root: string) => void][] = [
    ['a symlink', (dir, root) => symlinkSync(join(root, 'boot_id'), join(dir, 'README.md'))],
    ['a hard link', (dir) => linkSync(join(dir, 'src/main-core.ts'), join(dir, 'README.md'))],
    ['a FIFO', (dir) => mkfifo(join(dir, 'README.md'))],
  ];
  for (const [what, plant] of plants) {
    const w = await installWorld(t);
    const h = w.stage(RELEASE_1);
    rmSync(join(w.paths.staging, h, 'README.md'));
    plant(join(w.paths.staging, h), w.root);
    w.installRequest(h);
    await w.run();
    assert.equal(w.result(h), 'refused:not_regular', what);
    nothingCopied(w, h);
  }
});

test('KBOX-6 a file that grows while it is read is refused size', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({ afterOpen: (rel) => void (rel === 'README.md' && appendFileSync(join(w.paths.staging, h, rel), 'grown\n')) });
  assert.equal(w.result(h), 'refused:size');
  nothingCopied(w, h);
});

test('KBOX-6 a staged file over the 20 MiB limit is refused size', async (t) => {
  const w = await installWorld(t);
  const big = { ...RELEASE_1, 'big.bin': new Uint8Array(20 * 1024 * 1024 + 1) };
  const h = w.stage(big);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'refused:size');
  nothingCopied(w, h);
});

test('KBOX-6 a staging file with a newline in its name is refused by the re-applied name rules', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  writeFileSync(join(w.paths.staging, h, 'a\nb'), 'x');
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'refused:not_regular');
  nothingCopied(w, h);
});

test('KBOX-6 the installed bytes are the bytes read: a staged file changed after it was read cannot reach releases/', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({ afterRead: (rel) => void (rel === 'src/main-core.ts' && writeFileSync(join(w.paths.staging, h, rel), 'swapped after read\n')) });
  assert.equal(w.result(h), 'installed');
  assert.equal(readFileSync(join(w.paths.releases, h, 'src/main-core.ts'), 'utf8'), 'new core\n');
});

test('KBOX-6 a staged file changed during the copy, before it is read, is caught by the hash over the bytes read', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({ afterList: (rel) => void (rel === 'README.md' && writeFileSync(join(w.paths.staging, h, rel), 'changed during the copy\n')) });
  assert.equal(w.result(h), 'refused:hash');
  nothingCopied(w, h);
});

test('KBOX-6 a copy past its 60 s deadline is refused timeout', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({ afterRead: () => w.clock.advance(61_000) });
  assert.equal(w.result(h), 'refused:timeout');
  nothingCopied(w, h);
});

test('KBOX-6 a pre-planted directory, symlink or FIFO named x.request is removed, a refused:not_regular result is written and the run ends', async (t) => {
  const w = await installWorld(t);
  const target = join(w.root, 'must-survive');
  mkdirSync(target);
  writeFileSync(join(target, 'keep'), 'keep');
  mkdirSync(join(w.paths.staging, 'd.request'));
  symlinkSync(target, join(w.paths.staging, 'd.request', 'inner-link'));
  symlinkSync(target, join(w.paths.staging, 's.request'));
  mkfifo(join(w.paths.staging, 'f.request'));
  await w.run();
  for (const name of ['d', 's', 'f']) {
    assert.equal(existsSync(join(w.paths.staging, `${name}.request`)), false, name);
    assert.equal(w.result(name), 'refused:not_regular', name);
  }
  assert.equal(readFileSync(join(target, 'keep'), 'utf8'), 'keep', 'nothing behind a link was removed');
});

/** Plants `name` in `dir` as `depth` nested directories, made through held descriptors: the path is far past PATH_MAX. */
function nestDirs(dir: string, name: string, depth: number): void {
  mkdirSync(join(dir, name));
  let fd = openSync(join(dir, name), constants.O_RDONLY | constants.O_DIRECTORY);
  for (let i = 1; i < depth; i += 1) {
    mkdirSync(`/proc/self/fd/${fd}/d`);
    const next = openSync(`/proc/self/fd/${fd}/d`, constants.O_RDONLY | constants.O_DIRECTORY);
    closeSync(fd);
    fd = next;
  }
  closeSync(fd);
}

test('KBOX-6 a pre-planted x.request of 20,000 nested directories is removed (removal is iterative, not bounded by the call stack) and the run ends', async (t) => {
  const w = await installWorld(t);
  nestDirs(w.paths.staging, 'deep.request', 20_000);
  await w.run();
  assert.equal(existsSync(join(w.paths.staging, 'deep.request')), false, 'the entry that keeps the path unit triggered is gone');
  assert.equal(w.result('deep'), 'refused:not_regular');
});

test('KBOX-6 a pre-planted <H>.result symlink in staging has no effect: results are written under the root-owned results directory', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  const victim = join(w.root, 'victim');
  writeFileSync(victim, 'untouched');
  symlinkSync(victim, join(w.paths.staging, `${h}.result`));
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed');
  assert.equal(readFileSync(victim, 'utf8'), 'untouched');
});

test('KBOX-6 a request file over 64 KiB is refused size and removed', async (t) => {
  const w = await installWorld(t);
  w.request('big', { kind: 'install', pad: 'x'.repeat(64 * 1024) });
  await w.run();
  assert.equal(w.result('big'), 'refused:size');
  assert.equal(existsSync(join(w.paths.staging, 'big.request')), false);
});

// --- binaries ---------------------------------------------------------------------------------------------------------

test('KBOX-6 a new binary in <H>.bin whose hash matches the copied lock is installed; one whose hash differs is refused lock', async (t) => {
  const newNode = Buffer.from('#!/bin/sh\necho fake node 24.12\n');
  const w = await installWorld(t);
  const tree = { ...RELEASE_1, 'runtime.lock': lockFor(newNode, CADDY_BIN) };
  const h = w.stage(tree);
  mkdirSync(join(w.paths.staging, `${h}.bin`));
  writeFileSync(join(w.paths.staging, `${h}.bin`, 'node'), newNode);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed');
  assert.deepEqual(readFileSync(join(w.paths.releases, h, 'bin/node')), newNode);

  const w2 = await installWorld(t);
  const h2 = w2.stage(tree);
  mkdirSync(join(w2.paths.staging, `${h2}.bin`));
  writeFileSync(join(w2.paths.staging, `${h2}.bin`, 'node'), Buffer.from('another binary\n'));
  w2.installRequest(h2);
  await w2.run();
  assert.equal(w2.result(h2), 'refused:lock');
  nothingCopied(w2, h2);
});

test('KBOX-6 an unchanged binary replaced on disk in current is refused lock at the next install', async (t) => {
  const w = await installWorld(t);
  writeFileSync(join(w.paths.releases, w.h0, 'bin/caddy'), 'replaced on disk\n');
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'refused:lock');
  nothingCopied(w, h);
});

test('KBOX-6 a bundle without a runtime.lock, or with a bin/ of its own, is refused lock', async (t) => {
  const w = await installWorld(t);
  const { 'runtime.lock': _lock, ...noLock } = RELEASE_1;
  const h = w.stage(noLock);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'refused:lock');
  const w2 = await installWorld(t);
  const h2 = w2.stage({ ...RELEASE_1, 'bin/node': { body: 'planted', exec: true } });
  w2.installRequest(h2);
  await w2.run();
  assert.equal(w2.result(h2), 'refused:lock');
});

// --- health, rollback, retry and crash leftovers ----------------------------------------------------------------------

test('KBOX-6 a failed health check rolls back: current is H0 again, releases/<H> is removed, the result is rolled_back', async (t) => {
  const w = await installWorld(t);
  w.units.healthy = false;
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'rolled_back');
  assert.equal(w.current(), w.h0);
  assert.deepEqual(w.releases(), [w.h0]);
  assert.deepEqual(w.units.restarts, [h, w.h0], 'restarted on H, then on H0 again');

  w.units.healthy = true;
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed', 'a retry of the same H after a rollback works');
  assert.equal(w.current(), h);
});

test('KBOX-6 crash leftovers (a releases/<H>.tmp and a releases/<H> that is not current) are removed before the copy', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  mkdirSync(join(w.paths.releases, `${h}.tmp`, 'src'), { recursive: true });
  writeFileSync(join(w.paths.releases, `${h}.tmp`, 'src', 'half.ts'), 'half');
  mkdirSync(join(w.paths.releases, h));
  writeFileSync(join(w.paths.releases, h, 'stale.ts'), 'stale');
  w.installRequest(h);
  await w.run();
  assert.equal(w.result(h), 'installed');
  assert.deepEqual(w.releases(), [h, w.h0].sort());
  assert.equal(existsSync(join(w.paths.releases, h, 'stale.ts')), false);
});

test('KBOX-6 a failure after the switch still rolls back: the hook after step 5 breaks every file of the new release', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  await w.run({
    afterSwitch: () => {
      for (const path of filesUnder(join(w.paths.releases, h)).keys()) writeFileSync(join(w.paths.releases, h, path), 'throw new Error("broken release");\n');
      w.units.healthy = false;
    },
  });
  assert.equal(w.result(h), 'rolled_back');
  assert.equal(w.current(), w.h0);
});

// --- time: every phase inside the unit's TimeoutStartSec, and a kill mid-install -------------------------------------

/** The unit's TimeoutStartSec as written in deploy/kb-install.service, in ms: the oracle for every bound below. */
const unitTimeoutMs = (): number => {
  const m = /^TimeoutStartSec=(\d+)s$/m.exec(readFileSync(new URL('../deploy/kb-install.service', import.meta.url), 'utf8'));
  assert.ok(m?.[1] !== undefined, 'kb-install.service names its TimeoutStartSec in seconds');
  return Number(m[1]) * 1000;
};
/** Health checks that use every millisecond they are given and fail. */
const healthUsesAllItIsGiven = (w: InstallWorld): void => {
  w.units.healthy = false;
  w.units.onHealth = (until) => {
    if (until !== undefined && until > w.clock.now()) w.clock.advance(until - w.clock.now());
  };
};

test('KBOX-6 every phase is bounded by the time left under TimeoutStartSec: after a slow copy and a health check that uses all it is given, the rollback restart still ends inside it', async (t) => {
  const w = await installWorld(t);
  healthUsesAllItIsGiven(w);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  const start = w.clock.now();
  let slowed = false;
  await w.run({
    afterRead: () => {
      if (!slowed) w.clock.advance(50_000);
      slowed = true;
    },
  });
  assert.equal(w.result(h), 'rolled_back');
  assert.deepEqual(w.units.restarts, [h, w.h0]);
  assert.deepEqual(
    w.units.bounds.map((b) => b.what),
    ['restart', 'health', 'restart'],
  );
  for (const b of w.units.bounds) assert.ok(b.until !== undefined && b.until <= start + unitTimeoutMs(), `${b.what} is bounded inside the unit's timeout`);
  const [, health, rollback] = w.units.bounds;
  assert.ok(health?.until !== undefined && rollback?.until !== undefined && rollback.until > health.until, 'the rollback restart has time of its own after the health check');
});

test('KBOX-6 a second install in a run whose time the first used up is refused timeout, with nothing copied', async (t) => {
  const w = await installWorld(t);
  healthUsesAllItIsGiven(w);
  const one = w.stage(RELEASE_1);
  const two = w.stage({ ...RELEASE_1, 'README.md': 'v2\n' });
  w.installRequest(one);
  w.installRequest(two);
  await w.run();
  assert.deepEqual([w.result(one), w.result(two)].sort(), ['refused:timeout', 'rolled_back']);
  assert.equal(w.current(), w.h0);
  assert.deepEqual(w.releases(), [w.h0]);
});

/** Every file root keeps in the results directory, as text. */
const resultsTexts = (w: InstallWorld): string[] => readdirSync(w.paths.results).map((f) => readFileSync(join(w.paths.results, f), 'utf8'));

test('KBOX-6 a kill after the switch is rolled back by the next run: current is the base again, restarted, releases/<H> removed, result failed:interrupted', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  const killed = w.runKilledAt('afterSwitch');
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  assert.equal(w.current(), h, 'the kill came after the switch');
  assert.ok(resultsTexts(w).some((text) => text.trim() === `switching ${h} from ${w.h0}`), 'the switching record names H and its base');
  await w.run();
  assert.equal(w.current(), w.h0);
  assert.deepEqual(w.units.restarts, [w.h0], 'the units were restarted on the base');
  assert.deepEqual(w.releases(), [w.h0]);
  assert.equal(w.result(h), 'failed:interrupted');
  assert.equal(resultsTexts(w).some((text) => text.startsWith('switching')), false, 'the record is gone once the base is back');
  await w.run();
  assert.deepEqual(w.units.restarts, [w.h0], 'a later run has nothing left to roll back');
});

test('KBOX-6 a kill between copy and switch leaves the base current and no releases/<H>; the next run removes the .tmp and answers failed:interrupted', async (t) => {
  const w = await installWorld(t);
  const h = w.stage(RELEASE_1);
  w.installRequest(h);
  const killed = w.runKilledAt('afterCopy');
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  assert.equal(w.current(), w.h0);
  assert.deepEqual(w.releases(), [`${h}.tmp`, w.h0].sort(), 'only the .tmp copy exists');
  await w.run();
  assert.deepEqual(w.releases(), [w.h0]);
  assert.equal(w.result(h), 'failed:interrupted');
  assert.deepEqual(w.units.restarts, [], 'current never moved, so nothing is restarted');
});

// --- trust.json -------------------------------------------------------------------------------------------------------

const newApprover = (w: InstallWorld, id: string) => w.trusted(id, softApprover());

test('KBOX-6 approver_add with a proof by an approver in trust.json adds the approver; the same proof again is refused', async (t) => {
  const w = await installWorld(t);
  const added = newApprover(w, 'ap-second-0002');
  // FORCED-FLIP: as of the spec revision 4 the signed approver_add names the new keys by hash, so the proof is over them.
  const proof = w.proof(addActionOf(added));
  w.request('trust-a', { kind: 'trust', change: 'approver_add', approval: proof, approver: added });
  await w.run();
  assert.equal(w.result('trust-a'), 'applied');
  assert.deepEqual(w.trust()?.approvers.map((a) => a.id), [w.ownerId, 'ap-second-0002']);
  w.request('trust-b', { kind: 'trust', change: 'approver_add', approval: proof, approver: newApprover(w, 'ap-attacker-03') });
  await w.run();
  assert.equal(w.result('trust-b'), 'refused:spent');
  assert.equal(w.trust()?.approvers.length, 2);
});

test('KBOX-53 a kept approved approver_add presented with other keys is refused by root: another passkey, another device key or both', async (t) => {
  const w = await installWorld(t);
  const approved = newApprover(w, 'ap-approved-01');
  const other = newApprover(w, 'ap-other-00001');
  const before = readFileSync(w.paths.trustFile, 'utf8');
  const presented = [
    ['other keys', { ...other, id: 'ap-swapped-001' }],
    ['another passkey', { ...approved, id: 'ap-swapped-002', cose_b64: other.cose_b64 }],
    ['another device key', { ...approved, id: 'ap-swapped-003', device_pub_b64: other.device_pub_b64 }],
  ] as const;
  for (const [what, approver] of presented) {
    w.request(`x-${approver.id}`, { kind: 'trust', change: 'approver_add', approval: w.proof(addActionOf(approved)), approver });
    await w.run();
    assert.equal(w.result(`x-${approver.id}`), 'refused:bad_proof', what);
  }
  assert.equal(readFileSync(w.paths.trustFile, 'utf8'), before, 'trust.json is unchanged');
  w.request('x-good', { kind: 'trust', change: 'approver_add', approval: w.proof(addActionOf(approved)), approver: approved });
  await w.run();
  assert.equal(w.result('x-good'), 'applied', 'control: the keys the owner approved are added');
  assert.deepEqual(w.trust()?.approvers.at(-1), approved);
});

test('KBOX-6 approver_add or approver_remove with a proof by an approver not in trust.json, or for another action, changes nothing', async (t) => {
  const w = await installWorld(t);
  const before = readFileSync(w.paths.trustFile, 'utf8');
  const stranger = softApprover();
  const fresh = newApprover(w, 'ap-new-000001');
  // FORCED-FLIP: as of the spec revision 4 the signed approver_add names the new keys by hash.
  w.request('t1', { kind: 'trust', change: 'approver_add', approval: w.proof(addActionOf(fresh), { approver: stranger, approverId: 'ap-stranger-01' }), approver: fresh });
  w.request('t2', { kind: 'trust', change: 'approver_remove', approval: w.proof({ kind: 'approver_remove', approver_id: 'ap-xxxxxxxx' }), approver_id: w.ownerId });
  w.request('t3', { kind: 'trust', change: 'approver_add', approver: newApprover(w, 'ap-new-000002') });
  await w.run();
  assert.equal(w.result('t1'), 'refused:bad_proof');
  assert.equal(w.result('t2'), 'refused:bad_proof');
  assert.equal(w.result('t3'), 'refused:no_proof');
  assert.equal(readFileSync(w.paths.trustFile, 'utf8'), before);
});

test('KBOX-6 approver_remove removes an approver with a valid proof, and the last approver is never removed', async (t) => {
  const w = await installWorld(t);
  const second = softApprover();
  w.writeTrust([{ id: w.ownerId, a: w.owner }, { id: 'ap-second-0002', a: second }]);
  w.request('r1', { kind: 'trust', change: 'approver_remove', approval: w.proof({ kind: 'approver_remove', approver_id: 'ap-second-0002' }), approver_id: 'ap-second-0002' });
  await w.run();
  assert.equal(w.result('r1'), 'applied');
  assert.deepEqual(w.trust()?.approvers.map((a) => a.id), [w.ownerId]);
  w.request('r2', { kind: 'trust', change: 'approver_remove', approval: w.proof({ kind: 'approver_remove', approver_id: w.ownerId }), approver_id: w.ownerId });
  await w.run();
  assert.equal(w.result('r2'), 'refused:last_approver');
  assert.equal(w.trust()?.approvers.length, 1);
});

const codeFrom = (lines: readonly string[]): string => /([a-z]+(?: [a-z]+){11})/.exec(lines.at(-1) ?? '')?.[1] ?? '';

test('KBOX-49 setup writes the first trust.json only with the code root made; a wrong code is refused and stays valid; a used code is refused', async (t) => {
  const w = await installWorld(t, { trust: false });
  w.codes.writeSetupCode(false);
  const code = codeFrom(w.console);
  const first = newApprover(w, 'ap-first-00001');
  w.request('s1', { kind: 'trust', change: 'setup', code: 'abandon '.repeat(12).trim(), domain: 'box.example', approvers: [first] });
  await w.run();
  assert.equal(w.result('s1'), 'refused:wrong_code');
  assert.equal(w.trust(), undefined);
  w.request('s2', { kind: 'trust', change: 'setup', code, domain: 'box.example', approvers: [first] });
  await w.run();
  assert.equal(w.result('s2'), 'applied');
  assert.deepEqual(w.trust(), { domain: 'box.example', approvers: [first] });
  w.request('s3', { kind: 'trust', change: 'setup', code, domain: 'box.example', approvers: [newApprover(w, 'ap-second-0002')] });
  await w.run();
  assert.equal(w.result('s3'), 'refused:trust_exists');
});

test('KBOX-6 setup is refused once trust.json exists, even with a code core says is valid', async (t) => {
  const w = await installWorld(t);
  w.codes.writeSetupCode(false);
  const before = readFileSync(w.paths.trustFile, 'utf8');
  w.request('s', { kind: 'trust', change: 'setup', code: codeFrom(w.console), domain: 'box.example', approvers: [newApprover(w, 'ap-first-00001')] });
  await w.run();
  assert.equal(w.result('s'), 'refused:trust_exists');
  assert.equal(readFileSync(w.paths.trustFile, 'utf8'), before);
});

test('KBOX-20 recovery replaces every approver with root checking the code: wrong code, used code, another boot and 30 min + 1 ms are refused', async (t) => {
  const w = await installWorld(t);
  const replacement = newApprover(w, 'ap-recovered-1');
  w.codes.writeRecoveryCode('b0070000-0000-4000-8000-000000000002');
  const code = codeFrom(w.console);
  w.request('c1', { kind: 'trust', change: 'recovery', code: 'zoo '.repeat(12).trim(), approvers: [replacement] });
  await w.run();
  assert.equal(w.result('c1'), 'refused:wrong_code');
  w.request('c2', { kind: 'trust', change: 'recovery', code, approvers: [replacement] });
  await w.run();
  assert.equal(w.result('c2'), 'applied');
  assert.deepEqual(w.trust()?.approvers, [replacement]);
  w.request('c3', { kind: 'trust', change: 'recovery', code, approvers: [newApprover(w, 'ap-again-00001')] });
  await w.run();
  assert.equal(w.result('c3'), 'refused:no_code', 'a code works once');

  w.codes.writeRecoveryCode('b0070000-0000-4000-8000-0000000000ff'); // a code of another boot
  w.request('c4', { kind: 'trust', change: 'recovery', code: codeFrom(w.console), approvers: [newApprover(w, 'ap-again-00002')] });
  await w.run();
  assert.equal(w.result('c4'), 'refused:stale_boot');

  w.codes.consume('recovery');
  w.codes.writeRecoveryCode('b0070000-0000-4000-8000-000000000002');
  w.clock.advance(30 * 60_000 + 1);
  w.request('c5', { kind: 'trust', change: 'recovery', code: codeFrom(w.console), approvers: [newApprover(w, 'ap-again-00003')] });
  await w.run();
  assert.equal(w.result('c5'), 'refused:expired');
  assert.deepEqual(w.trust()?.approvers, [replacement]);
});

test('KBOX-6 a trust request with keys that do not decode is refused bad_request and changes nothing', async (t) => {
  const w = await installWorld(t);
  const before = readFileSync(w.paths.trustFile, 'utf8');
  const broken = { id: 'ap-broken-0001', cose_b64: 'AAAA', device_pub_b64: 'AAAA' };
  // FORCED-FLIP: as of the spec revision 4 the signed approver_add names the new keys by hash.
  w.request('k', { kind: 'trust', change: 'approver_add', approval: w.proof(addActionOf(broken)), approver: broken });
  await w.run();
  assert.equal(w.result('k'), 'refused:bad_request');
  assert.equal(readFileSync(w.paths.trustFile, 'utf8'), before);
});
