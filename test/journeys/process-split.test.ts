// KBOX-45 (the started-process half): with the real modes of deploy/keybox-tmpfiles.conf and real users, the relay user cannot
// reach core's http.sock, the caddy user cannot reach the lend socket, and the relay cannot open a vault file.
// This file needs root: it fails, never skips, when it cannot switch uid. loop/gate.sh runs it as root in a throwaway container.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, chownSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { createFileVault } from '../../src/shell/vault-fs.ts';
import { ensureSystemUsers, parseTmpfiles, startNode } from '../kit/index.ts';
import type { SystemUser, SystemUsers } from '../kit/index.ts';

const here = new URL('./', import.meta.url).pathname;
const repoDeploy = new URL('../../deploy/', import.meta.url).pathname;

/** The spec's user and group names, as the throwaway users of this test. */
const NAMES = { caddy: 'kbt-caddy', keybox: 'kbt-keybox', keyrelay: 'kbt-keyrelay' } as const;
type Role = keyof typeof NAMES;

interface World {
  readonly root: string;
  readonly users: SystemUsers;
  readonly uid: Readonly<Record<Role, SystemUser>>;
  /** The directories as the tmpfiles file makes them, under `root` instead of `/`. */
  readonly dirs: Readonly<Record<'/run/keybox' | '/run/keyrelay' | '/run/keybox-lend' | '/etc/keybox' | '/var/lib/keybox-install' | '/var/lib/keybox', string>>;
}

let world: World | undefined;
const w = (): World => {
  if (world === undefined) throw new Error('the world was not set up');
  return world;
};

function owner(name: string, users: Readonly<Record<string, SystemUser>>): { uid: number; gid: number } {
  if (name === 'root') return { uid: 0, gid: 0 };
  const user = users[`kbt-${name}`];
  if (user === undefined) throw new Error(`the tmpfiles file names an owner this test has no user for: ${name}`);
  return { uid: user.uid, gid: user.gid };
}

function chownTree(path: string, uid: number, gid: number): void {
  chownSync(path, uid, gid);
  if (statSync(path).isDirectory()) for (const entry of readdirSync(path)) chownTree(join(path, entry), uid, gid);
}

before(() => {
  const users = ensureSystemUsers(Object.values(NAMES));
  const root = mkdtempSync(join(tmpdir(), 'kbt-split-'));
  chmodSync(root, 0o755);
  writeFileSync(join(root, 'package.json'), '{"type":"module"}\n');
  for (const script of ['stand-in-listener.ts', 'uid-probe.ts']) copyFileSync(join(here, script), join(root, script));
  const tmpfiles = parseTmpfiles(readFileSync(join(repoDeploy, 'keybox-tmpfiles.conf'), 'utf8'));
  const dirs: Record<string, string> = {};
  for (const line of tmpfiles) {
    const path = join(root, line.path);
    mkdirSync(path, { recursive: true, mode: 0o755 });
    const ids = { user: owner(line.user, users.users), group: owner(line.group, users.users) };
    chownSync(path, ids.user.uid, ids.group.gid);
    chmodSync(path, parseInt(line.mode, 8));
    dirs[line.path] = path;
  }
  // Parents made on the way (root/run, root/etc, root/var/lib) must be walkable by everyone.
  for (const parent of ['run', 'etc', 'var', join('var', 'lib')]) chmodSync(join(root, parent), 0o755);
  const state = dirs['/var/lib/keybox'] ?? '';
  createFileVault(join(state, 'vault')).put('openai/master', 1, Buffer.from('a vault value that must stay unreadable'));
  chownTree(state, users.users[NAMES.keybox]?.uid ?? 0, users.users[NAMES.keybox]?.gid ?? 0);
  world = {
    root,
    users,
    uid: { caddy: users.users[NAMES.caddy] as SystemUser, keybox: users.users[NAMES.keybox] as SystemUser, keyrelay: users.users[NAMES.keyrelay] as SystemUser },
    dirs: dirs as World['dirs'],
  };
});

after(() => {
  if (world === undefined) return;
  rmSync(world.root, { recursive: true, force: true });
  world.users.remove();
});

const modeOf = (path: string): number => statSync(path).mode & 0o7777;

/** Runs the probe as `role` and returns what the operating system said. */
function probe(role: Role, action: 'connect' | 'list' | 'open' | 'write', target: string): Record<string, unknown> {
  const user = w().uid[role];
  const run = spawnSync(process.execPath, [join(w().root, 'uid-probe.ts'), action, target], { cwd: w().root, uid: user.uid, gid: user.gid, encoding: 'utf8', timeout: 20_000 });
  if (run.error !== undefined) throw run.error;
  assert.equal(run.status, 0, `the probe as ${role} failed: ${run.stderr}`);
  return JSON.parse(run.stdout) as Record<string, unknown>;
}

const sockets = () => ({
  core: join(w().dirs['/run/keybox'], 'http.sock'),
  relay: join(w().dirs['/run/keyrelay'], 'http.sock'),
  lend: join(w().dirs['/run/keybox-lend'], 'lend.sock'),
});

test('KBOX-45 the real directory modes, owners and groups are in place under the throwaway users', () => {
  const { dirs, uid } = w();
  for (const [path, mode, user, group] of [
    ['/run/keybox', 0o2750, 'keybox', 'caddy'],
    ['/run/keyrelay', 0o2750, 'keyrelay', 'caddy'],
    ['/run/keybox-lend', 0o2750, 'keybox', 'keyrelay'],
  ] as const) {
    const stat = statSync(dirs[path]);
    assert.equal(modeOf(dirs[path]), mode, path);
    assert.equal(stat.uid, uid[user].uid, `${path} owner`);
    assert.equal(stat.gid, uid[group].gid, `${path} group`);
  }
  for (const path of ['/etc/keybox', '/var/lib/keybox-install'] as const) assert.deepEqual([statSync(dirs[path]).uid, modeOf(dirs[path])], [0, 0o755], path);
});

test('KBOX-45 the lend socket exists only after core starts, and each socket made takes its directory\'s group with mode 0660', async (t) => {
  const { dirs, uid, root } = w();
  const s = sockets();
  assert.equal(existsSync(s.lend), false, 'no lend socket before core starts');
  const relay = startNode(t, [join(root, 'stand-in-listener.ts'), 'relay', s.relay], root, {}, uid.keyrelay);
  await relay.ready('listening');
  assert.equal(existsSync(s.lend), false, 'the relay stand-in does not make the lend socket');
  const core = startNode(t, [join(root, 'stand-in-listener.ts'), 'core', s.core, s.lend], root, {}, uid.keybox);
  await core.ready('listening');
  assert.equal(existsSync(s.lend), true, 'the lend socket exists once core runs');
  for (const [socket, dir, owner] of [
    [s.core, '/run/keybox', 'keybox'],
    [s.relay, '/run/keyrelay', 'keyrelay'],
    [s.lend, '/run/keybox-lend', 'keybox'],
  ] as const) {
    const stat = statSync(socket);
    assert.equal(stat.gid, statSync(dirs[dir]).gid, `${socket} takes the directory's group`);
    assert.equal(stat.uid, uid[owner].uid, `${socket} owner`);
    assert.equal(stat.mode & 0o007, 0, `${socket} gives others nothing`);
    assert.equal(stat.mode & 0o060, 0o060, `${socket} gives its group read and write`);
  }
});

test('KBOX-45 the socket-group table: who can connect to which socket, who can list which directory, who can open a vault file', async (t) => {
  const { dirs, uid, root } = w();
  const s = sockets();
  const relay = startNode(t, [join(root, 'stand-in-listener.ts'), 'relay', s.relay], root, {}, uid.keyrelay);
  const core = startNode(t, [join(root, 'stand-in-listener.ts'), 'core', s.core, s.lend], root, {}, uid.keybox);
  await Promise.all([relay.ready('listening'), core.ready('listening')]);
  const vaultFile = join(dirs['/var/lib/keybox'], 'vault', 'openai', 'master', '1');
  const says = { ok: true, said: 'hello' };
  const refused = { ok: false, code: 'EACCES' };
  const table: [Role, 'connect' | 'list' | 'open', string, (r: Record<string, unknown>) => void, string][] = [
    ['keyrelay', 'connect', s.core, (r) => assert.deepEqual(r, refused), 'the relay user is refused on core\'s http.sock'],
    ['keyrelay', 'list', dirs['/run/keybox'], (r) => assert.deepEqual(r, refused), 'the relay user cannot even list /run/keybox'],
    ['caddy', 'connect', s.core, (r) => assert.deepEqual(r, says), 'caddy reaches core\'s http.sock'],
    ['caddy', 'connect', s.relay, (r) => assert.deepEqual(r, says), 'caddy reaches the relay\'s http.sock'],
    ['caddy', 'connect', s.lend, (r) => assert.deepEqual(r, refused), 'caddy is refused on the lend socket'],
    ['keyrelay', 'connect', s.lend, (r) => assert.deepEqual(r, says), 'the relay user reaches the lend socket'],
    ['keybox', 'connect', s.relay, (r) => assert.deepEqual(r, refused), 'core\'s user is not given the relay\'s socket'],
    ['caddy', 'list', dirs['/run/keybox'], (r) => assert.deepEqual(r, { ok: true, entries: ['http.sock'] }), 'caddy can list core\'s directory'],
    ['caddy', 'list', dirs['/run/keybox-lend'], (r) => assert.deepEqual(r, refused), 'caddy cannot list the lend directory'],
    ['keyrelay', 'open', vaultFile, (r) => assert.deepEqual(r, refused), 'the relay cannot open a vault file'],
    ['caddy', 'open', vaultFile, (r) => assert.deepEqual(r, refused), 'caddy cannot open a vault file'],
    ['keyrelay', 'list', join(dirs['/var/lib/keybox'], 'vault'), (r) => assert.deepEqual(r, refused), 'the relay cannot list the vault'],
    ['keybox', 'open', vaultFile, (r) => assert.deepEqual(r, { ok: true }), 'core\'s user can open its own vault file'],
  ];
  for (const [role, action, target, check, what] of table) {
    try {
      check(probe(role, action, target));
    } catch (cause) {
      throw new Error(`${what}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    }
  }
});

test('KBOX-45 keybox can read /etc/keybox and /var/lib/keybox-install and write neither', () => {
  const { dirs } = w();
  for (const path of ['/etc/keybox', '/var/lib/keybox-install'] as const) {
    assert.deepEqual(probe('keybox', 'list', dirs[path]), { ok: true, entries: [] }, `${path} can be read`);
    assert.deepEqual(probe('keybox', 'write', dirs[path]), { ok: false, code: 'EACCES' }, `${path} cannot be written`);
  }
});

test('KBOX-45 the throwaway users: one that was already there is used and kept, one that is missing is made and removed, a failed create fails', () => {
  const exists = (name: string): boolean => spawnSync('id', ['-u', name]).status === 0;
  const pre = ensureSystemUsers(['kbt-pre']);
  assert.deepEqual(pre.made, ['kbt-pre']);
  const both = ensureSystemUsers(['kbt-pre', 'kbt-new']);
  assert.deepEqual(both.made, ['kbt-new']);
  assert.equal(exists('kbt-new'), true);
  both.remove();
  assert.equal(exists('kbt-new'), false);
  assert.equal(exists('kbt-pre'), true, 'a user this call did not make is not deleted');
  pre.remove();
  assert.equal(exists('kbt-pre'), false);
  assert.throws(() => ensureSystemUsers(['bad name!']), /useradd bad name! failed/);
});
