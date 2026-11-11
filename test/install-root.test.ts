// KBOX-6 (the uid half): the real kb-install entry run as root over a tree with the real owners and modes, and a throwaway
// `kbt-kbcore` user standing in for core (its own name: process-split runs beside it and makes and removes `kbt-keybox`). Core's uid cannot read or list root's code directory, cannot write under the
// installed release, and a request it writes without a valid proof is refused while the run exits 0.
// This file needs root: it fails, never skips, when it cannot make its user. loop/gate.sh runs it as root in a container.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, chownSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { after, before, test } from 'node:test';
import { ensureSystemUsers } from './kit/index.ts';
import type { SystemUser, SystemUsers } from './kit/index.ts';
import { softApprover } from './kit/approver.ts';
import { WORDLIST } from './support/approve-world.ts';
import { COMMIT, NODE_BIN, CADDY_BIN, RELEASE_0, hashOf, keptProof, lockFor } from './support/install-world.ts';
import type { Tree } from './support/install-world.ts';
import { createCodeRoot } from '../src/shell/console.ts';

const CLI = new URL('../src/cli/kb-install.ts', import.meta.url).pathname;
const RELEASE_1: Tree = { 'runtime.lock': lockFor(NODE_BIN, CADDY_BIN), 'src/main-core.ts': 'new core\n', 'run.sh': { body: '#!/bin/sh\n', exec: true } };

interface World {
  readonly root: string;
  readonly users: SystemUsers;
  readonly keybox: SystemUser;
  readonly env: Readonly<Record<string, string>>;
  readonly servers: readonly Server[];
  readonly h0: string;
}
let world: World | undefined;
const w = (): World => {
  if (world === undefined) throw new Error('the world was not set up');
  return world;
};

const p = (...parts: string[]): string => join(w().root, ...parts);

function writeTree(dir: string, tree: Tree): void {
  for (const [path, v] of Object.entries(tree)) {
    const file = join(dir, path);
    mkdirSync(join(file, '..'), { recursive: true, mode: 0o755 });
    const exec = typeof v === 'object' && 'exec' in v;
    writeFileSync(file, typeof v === 'object' && 'body' in v ? v.body : v, { mode: exec ? 0o755 : 0o644 });
  }
}

/** Runs a short script as core's stand-in user; its stdout is the outcome code. */
function asKeybox(script: string): string {
  const k = w().keybox;
  const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], { uid: k.uid, gid: k.gid, encoding: 'utf8', cwd: '/' });
  assert.equal(run.status, 0, run.stderr);
  return run.stdout.trim();
}

const tryWrite = (path: string): string =>
  asKeybox(`import { writeFileSync } from 'node:fs'; try { writeFileSync(${JSON.stringify(path)}, 'x'); console.log('written'); } catch (e) { console.log(e.code); }`);

/** Runs the real kb-install. Asynchronously: the stand-in core and relay in this process must answer its health check. */
function runCli(): Promise<{ status: number | null; stdout: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI], { env: { ...process.env, ...w().env }, stdio: ['ignore', 'pipe', 'inherit'] });
    let stdout = '';
    child.stdout.on('data', (c: Buffer) => void (stdout += c.toString('utf8')));
    child.on('close', (status) => resolve({ status, stdout }));
  });
}

before(async () => {
  const users = ensureSystemUsers(['kbt-kbcore']);
  const keybox = users.users['kbt-kbcore'] as SystemUser;
  const root = mkdtempSync(join(tmpdir(), 'kbt-install-'));
  chmodSync(root, 0o755);
  world = { root, users, keybox, env: {}, servers: [], h0: hashOf(RELEASE_0) };
  for (const dir of ['opt/keybox/releases', 'etc/keybox', 'var/lib/keybox-install', 'run']) mkdirSync(p(dir), { recursive: true, mode: 0o755 });
  mkdirSync(p('var/lib/keybox/staging'), { recursive: true, mode: 0o750 });
  chownSync(p('var/lib/keybox'), keybox.uid, keybox.gid);
  chownSync(p('var/lib/keybox/staging'), keybox.uid, keybox.gid);
  chmodSync(p('var/lib/keybox'), 0o755); // walkable here so the test can stage as keybox; the box makes it 0700
  const r0 = p('opt/keybox/releases', world.h0);
  writeTree(r0, RELEASE_0);
  writeTree(r0, { 'bin/node': { body: NODE_BIN, exec: true }, 'bin/caddy': { body: CADDY_BIN, exec: true } });
  spawnSync('ln', ['-s', r0, p('opt/keybox/current')]);
  writeFileSync(p('boot_id'), 'b0070000-0000-4000-8000-000000000003\n');
  const codes = createCodeRoot({ dir: p('etc/keybox/codes'), sink: () => undefined, random: { bytes: (n) => new Uint8Array(n).fill(7) }, clock: { now: () => Date.UTC(2026, 0, 1) }, wordlist: WORDLIST });
  codes.writeSetupCode(false);
  // Stand-ins for core and relay that answer /healthz with whatever `current` points at, as restarted processes would.
  const servers = ['core.sock', 'relay.sock'].map((name) => {
    const server = createServer((_req, res) => void res.writeHead(200).end(JSON.stringify({ release: basename(realpathSync(p('opt/keybox/current'))) })));
    server.listen(p('run', name));
    return server;
  });
  await Promise.all(servers.map((s) => new Promise((r) => s.once('listening', r))));
  world = {
    ...world,
    servers,
    env: {
      KB_STAGING_DIR: p('var/lib/keybox/staging'),
      KB_RELEASES_DIR: p('opt/keybox/releases'),
      KB_CURRENT: p('opt/keybox/current'),
      KB_TRUST_FILE: p('etc/keybox/trust.json'),
      KB_CODES_DIR: p('etc/keybox/codes'),
      KB_INSTALL_RESULTS: p('var/lib/keybox-install'),
      KB_BOOT_ID_FILE: p('boot_id'),
      KB_SYSTEMCTL: '/bin/true',
      KB_CORE_SOCKET: p('run', 'core.sock'),
      KB_RELAY_SOCKET: p('run', 'relay.sock'),
    },
  };
});

after(() => {
  if (world === undefined) return;
  for (const s of world.servers) s.close();
  rmSync(world.root, { recursive: true, force: true });
  world.users.remove();
});

test('KBOX-6 core\'s uid cannot read or list root\'s code directory, and the hash file is root 0600 in a 0700 directory', () => {
  assert.equal(statSync(p('etc/keybox/codes')).mode & 0o777, 0o700);
  assert.equal(statSync(p('etc/keybox/codes/setup.hash')).mode & 0o777, 0o600);
  assert.equal(asKeybox(`import { readdirSync } from 'node:fs'; try { readdirSync(${JSON.stringify(p('etc/keybox/codes'))}); console.log('listed'); } catch (e) { console.log(e.code); }`), 'EACCES');
  assert.equal(asKeybox(`import { readFileSync } from 'node:fs'; try { readFileSync(${JSON.stringify(p('etc/keybox/codes/setup.hash'))}); console.log('read'); } catch (e) { console.log(e.code); }`), 'EACCES');
});

test('KBOX-6 a request core\'s uid wrote with the right H and base and no proof is refused no_proof by the real kb-install, which exits 0', async () => {
  const h = hashOf(RELEASE_1);
  const request = JSON.stringify({ kind: 'install', install: h, commit: COMMIT, base: w().h0 });
  assert.equal(asKeybox(`import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(p('var/lib/keybox/staging', `${h}.request`))}, ${JSON.stringify(request)}); console.log('ok');`), 'ok');
  const run = await runCli();
  assert.equal(run.status, 0);
  assert.equal(readFileSync(p('var/lib/keybox-install', `${h}.result`), 'utf8'), 'refused:no_proof');
  assert.deepEqual(readdirSync(p('opt/keybox/releases')), [w().h0]);
});

test('KBOX-6 an approved install by the real kb-install as root: a root-owned release with fixed modes that core\'s uid cannot write, and a hard link to a root-only canary is refused', async () => {
  const owner = softApprover();
  writeFileSync(p('etc/keybox/trust.json'), JSON.stringify({ domain: 'box.example', approvers: [{ id: 'ap-owner-00001', cose_b64: Buffer.from(owner.coseKey).toString('base64url'), device_pub_b64: Buffer.from(owner.devicePublicKey).toString('base64url') }] }));
  const h = hashOf(RELEASE_1);
  const staged = p('var/lib/keybox/staging', h);
  writeTree(staged, RELEASE_1);
  // A hard link to a root-only file in place of a staged file (root makes it here; protected_hardlinks would stop keybox).
  const canary = `canary-${Date.now().toString(36)}-root-only`;
  writeFileSync(p('etc/keybox/secret'), canary, { mode: 0o600 });
  rmSync(join(staged, 'src/main-core.ts'));
  linkSync(p('etc/keybox/secret'), join(staged, 'src/main-core.ts'));
  const write = (body: object): void => writeFileSync(p('var/lib/keybox/staging', `${h}.request`), JSON.stringify(body));
  write({ kind: 'install', install: h, commit: COMMIT, base: w().h0, approval: keptProof(owner, 'ap-owner-00001', { kind: 'install_update', install: h, commit: COMMIT, base: w().h0 }) });
  assert.equal((await runCli()).status, 0);
  assert.equal(readFileSync(p('var/lib/keybox-install', `${h}.result`), 'utf8'), 'refused:not_regular');
  for (const dir of ['opt', 'var/lib/keybox-install']) assert.equal(spawnSync('grep', ['-r', '-l', canary, p(dir)]).status, 1, `the canary is nowhere under ${dir}`);

  rmSync(join(staged, 'src/main-core.ts'));
  writeTree(staged, { 'src/main-core.ts': 'new core\n' });
  spawnSync('chown', ['-R', `${w().keybox.uid}:${w().keybox.gid}`, p('var/lib/keybox/staging')]);
  write({ kind: 'install', install: h, commit: COMMIT, base: w().h0, approval: keptProof(owner, 'ap-owner-00001', { kind: 'install_update', install: h, commit: COMMIT, base: w().h0 }) });
  const run = await runCli();
  assert.equal(run.status, 0);
  assert.equal(readFileSync(p('var/lib/keybox-install', `${h}.result`), 'utf8'), 'installed');
  assert.equal(readlinkSync(p('opt/keybox/current')), p('opt/keybox/releases', h));
  const release = p('opt/keybox/releases', h);
  for (const [path, mode] of [['', 0o755], ['src', 0o755], ['src/main-core.ts', 0o644], ['run.sh', 0o755], ['bin/node', 0o755]] as const) {
    const st = statSync(join(release, path));
    assert.deepEqual([st.uid, st.mode & 0o777], [0, mode], path);
  }
  assert.equal(tryWrite(join(release, 'src/main-core.ts')), 'EACCES', 'core cannot change an installed file');
  assert.equal(tryWrite(join(release, 'planted.ts')), 'EACCES', 'core cannot add a file to a release');
  assert.equal(tryWrite(p('opt/keybox/releases/planted')), 'EACCES', 'core cannot add a release');
  assert.equal(tryWrite(p('etc/keybox/trust.json')), 'EACCES', 'core cannot write the root copy of the approvers');
  assert.equal(tryWrite(p('var/lib/keybox-install/planted.result')), 'EACCES', 'core cannot plant a result');
});
