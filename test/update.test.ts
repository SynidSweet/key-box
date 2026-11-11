// KBOX-6 (intake and approval): the tar the box takes, the content hash H it computes itself, POST /api/updates, the
// install_update executor and the trust requests core sends to root. kb-install itself is tested in install-helper.test.ts.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { parseTar } from '../src/pure/tar.ts';
import { releaseHash, releaseText } from '../src/pure/release-hash.ts';
import { createTrustInstaller } from '../src/shell/trust-installer.ts';
import { createUpdater } from '../src/shell/updater.ts';
import { systemdUnits } from '../src/shell/systemd.ts';
import { softApprover } from './kit/approver.ts';
import { FakeClock, drive, seededRandom, tempDir } from './kit/index.ts';
import { approveWorld } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';
import { CADDY_BIN, NODE_BIN, addActionOf, installWorld, lockFor } from './support/install-world.ts';
import { gitGlobalHeader, tarOf } from './support/tar.ts';
import type { TarEntrySpec } from './support/tar.ts';

const C = 'c0ffee'.padEnd(40, '0');
const sha = (s: string | Uint8Array): string => createHash('sha256').update(s).digest('hex');

const refusesTar = (entries: readonly TarEntrySpec[], code: string, why: string): void => {
  const parsed = parseTar(tarOf(entries));
  assert.deepEqual(parsed, { ok: false, code }, why);
};

// --- the tar refusal table --------------------------------------------------------------------------------------------

test('KBOX-6 a git-archive style tar (one global pax header first, directories, files) parses to its files and modes', () => {
  const parsed = parseTar(tarOf([gitGlobalHeader(C), { name: 'src/', type: '5', mode: 0o775 }, { name: 'src/a.ts', body: 'one\n', mode: 0o664 }, { name: 'run.sh', body: '#!/bin/sh\n', mode: 0o775 }]));
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.deepEqual(
    parsed.entries.map((e) => (e.kind === 'dir' ? ['dir', e.path] : ['file', e.path, e.executable, Buffer.from(e.bytes).toString()])),
    [['dir', 'src'], ['file', 'src/a.ts', false, 'one\n'], ['file', 'run.sh', true, '#!/bin/sh\n']],
  );
});

for (const [flag, why] of [['1', 'a hard link'], ['2', 'a symlink'], ['3', 'a character device'], ['4', 'a block device'], ['6', 'a FIFO'], ['7', 'a contiguous file'], ['S', 'an unknown type']] as const) {
  test(`KBOX-6 ${why} in the tar is refused entry_type`, () => refusesTar([{ name: 'x', type: flag, linkname: flag === '1' || flag === '2' ? '/etc/shadow' : '' }], 'entry_type', why));
}

test('KBOX-6 a pax x header, a GNU long name or long link header and a second g header are refused extended_header', () => {
  refusesTar([{ name: 'PaxHeader/x', type: 'x', body: '11 path=a\n' }, { name: 'a', body: 'a' }], 'extended_header', 'pax x');
  refusesTar([{ name: '././@LongLink', type: 'L', body: 'long' }, { name: 'a', body: 'a' }], 'extended_header', 'GNU L');
  refusesTar([{ name: '././@LongLink', type: 'K', body: 'long' }, { name: 'a', body: 'a' }], 'extended_header', 'GNU K');
  refusesTar([gitGlobalHeader(C), gitGlobalHeader(C), { name: 'a', body: 'a' }], 'extended_header', 'a second g header');
  refusesTar([{ name: 'a', body: 'a' }, gitGlobalHeader(C)], 'extended_header', 'a g header that is not the first entry');
});

const badNames: readonly (readonly [string | Uint8Array, string])[] = [
  ['/etc/passwd', 'an absolute path'],
  ['../up', 'a path with ..'],
  ['a/../../up', 'a path with .. inside'],
  ['a/./b', 'a path with a . segment'],
  ['a//b', 'an empty segment'],
  ['a\nb', 'a newline'],
  ['a\tb', 'a tab (another control byte)'],
  ['a\u007fb', 'DEL'],
  ['a\\b', 'a backslash'],
  [Uint8Array.from([0x61, 0xff, 0x62]), 'invalid UTF-8'],
  [Uint8Array.from([0x61, 0xc0, 0xaf]), 'an overlong UTF-8 slash'],
];
for (const [name, why] of badNames) test(`KBOX-6 a tar path with ${why} is refused name`, () => refusesTar([{ name, body: 'x' }], 'name', why));

test('KBOX-6 a NUL inside a tar name field is refused name (the name does not end at the first NUL with more bytes after it)', () => {
  refusesTar([{ name: Uint8Array.from([0x61, 0x00, 0x62]), body: 'x' }], 'name', 'a NUL then more name bytes');
});

test('KBOX-6 a duplicate path, a directory listed twice and a file under a file are refused duplicate', () => {
  refusesTar([{ name: 'a', body: '1' }, { name: 'a', body: '2' }], 'duplicate', 'a file twice');
  refusesTar([{ name: 'd/', type: '5' }, { name: 'd/', type: '5' }], 'duplicate', 'a directory twice');
  refusesTar([{ name: 'a', body: '1' }, { name: 'a/b', body: '2' }], 'duplicate', 'a file under a file');
  refusesTar([{ name: 'a/b', body: '2' }, { name: 'a', body: '1' }], 'duplicate', 'a file over an implied directory');
});

test('KBOX-6 a 255-byte path is accepted and a 256-byte path is refused name', () => {
  const at = (n: number): TarEntrySpec => ({ prefix: 'p'.repeat(n - 101), name: 'n'.repeat(100), body: 'x' });
  assert.equal(parseTar(tarOf([at(255)])).ok, true);
  refusesTar([at(256)], 'name', '256 bytes');
});

test('KBOX-6 5,000 entries are accepted and 5,001 are refused too_many', () => {
  const many = (n: number): TarEntrySpec[] => Array.from({ length: n }, (_, i) => ({ name: `d${i}/`, type: '5' }));
  assert.equal(parseTar(tarOf(many(5000))).ok, true);
  refusesTar(many(5001), 'too_many', '5,001 entries');
});

test('KBOX-6 20 MiB of file bytes are accepted and 20 MiB + 1 is refused too_large', () => {
  const mib = 1024 * 1024;
  assert.equal(parseTar(tarOf([{ name: 'a', body: new Uint8Array(20 * mib - 1) }, { name: 'b', body: 'x' }])).ok, true);
  refusesTar([{ name: 'a', body: new Uint8Array(20 * mib) }, { name: 'b', body: 'x' }], 'too_large', '20 MiB + 1');
});

test('KBOX-6 a truncated tar is refused truncated: a cut body, a cut header, no end block', () => {
  const whole = tarOf([{ name: 'a', body: 'x'.repeat(600) }]);
  assert.deepEqual(parseTar(whole.subarray(0, 700)), { ok: false, code: 'truncated' }, 'cut body');
  assert.deepEqual(parseTar(whole.subarray(0, 300)), { ok: false, code: 'truncated' }, 'cut header');
  assert.deepEqual(parseTar(tarOf([{ name: 'a', body: 'x' }], { end: false })), { ok: false, code: 'truncated' }, 'no end block');
  assert.deepEqual(parseTar(new Uint8Array(0)), { ok: false, code: 'truncated' }, 'empty input');
});

test('KBOX-6 a wrong checksum, a base-256 size, a missing ustar magic and bytes after the end are refused bad_header', () => {
  refusesTar([{ name: 'a', body: 'x', badChecksum: true }], 'bad_header', 'checksum');
  refusesTar([{ name: 'a', body: 'x', base256Size: true }], 'bad_header', 'base-256 size');
  const noMagic = tarOf([{ name: 'a', body: 'x' }]);
  noMagic.fill(0, 257, 263);
  assert.deepEqual(parseTar(noMagic), { ok: false, code: 'bad_header' }, 'no magic');
  const trailing = tarOf([{ name: 'a', body: 'x' }]);
  trailing[trailing.length - 1] = 1;
  assert.deepEqual(parseTar(trailing), { ok: false, code: 'bad_header' }, 'a non-zero byte after the end block');
  refusesTar([{ name: 'd/', type: '5', body: 'data' }], 'bad_header', 'a directory with a body');
});

// --- the content hash -------------------------------------------------------------------------------------------------

test('KBOX-6 the content hash matches a vector computed here from the spec text: sorted bytewise, <mode> <sha256> <path>, 0755 only with the owner-execute bit', () => {
  const files = [
    { path: 'src/z.ts', executable: false, sha256: sha('z') },
    { path: 'run.sh', executable: true, sha256: sha('#!/bin/sh\n') },
    { path: 'src/a.ts', executable: false, sha256: sha('a') },
    { path: 'Src.md', executable: false, sha256: sha('S') },
    { path: 'é.txt', executable: false, sha256: sha('e') },
  ];
  // Bytewise: 'S' (0x53) < 'r' (0x72) < 's' (0x73) < 0xc3 (the first byte of é).
  const text = `0644 ${sha('S')} Src.md\n0755 ${sha('#!/bin/sh\n')} run.sh\n0644 ${sha('a')} src/a.ts\n0644 ${sha('z')} src/z.ts\n0644 ${sha('e')} é.txt\n`;
  assert.equal(releaseText(files), text);
  assert.equal(releaseHash(files), sha(text));
});

test('KBOX-6 a file with group or other execute bits only is 0644 in the hash text', () => {
  const parsed = parseTar(tarOf([{ name: 'g', body: 'x', mode: 0o654 }, { name: 'o', body: 'x', mode: 0o645 }, { name: 'u', body: 'x', mode: 0o744 }]));
  assert.ok(parsed.ok);
  assert.deepEqual(parsed.entries.map((e) => (e.kind === 'file' ? e.executable : 'dir')), [false, false, true]);
});

// --- core: POST /api/updates, the executor, the trust port ------------------------------------------------------------

async function updateWorld(t: TestContext) {
  const iw = await installWorld(t);
  let world: World | undefined;
  const must = (): World => {
    if (world === undefined) throw new Error('the approve world is not up yet');
    return world;
  };
  const updater = createUpdater({
    stagingDir: iw.paths.staging,
    resultsDir: iw.paths.results,
    currentLink: iw.paths.current,
    propose: (input) => must().core.approvals.propose(input),
    approvals: () => must().core.approvals,
    events: { append: (kind, data) => must().parts.events.append(kind, data) },
  });
  world = await approveWorld(t, { routes: updater.routes, executors: { install_update: updater.executor } });
  const w = world;
  iw.writeTrust([{ id: w.ownerId, a: w.owner }]);
  const control = w.token('ctl-1', 'control');
  const driver = drive(join(w.stateDir, '..', 'http.sock'));
  const post = (tar: Uint8Array, query = `?commit=${C}`, type = 'application/x-tar', token = control) =>
    driver.request({ method: 'POST', path: `/api/updates${query}`, headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}`, 'content-type': type }, body: tar });
  const events = (kind: string) => w.parts.events.after(0).filter((e) => e.kind === kind).map((e) => e.data);
  return { iw, w, updater, post, events };
}

const BUNDLE: readonly TarEntrySpec[] = [
  gitGlobalHeader(C),
  { name: 'runtime.lock', body: lockFor(NODE_BIN, CADDY_BIN) },
  { name: 'src/', type: '5' },
  { name: 'src/main-core.ts', body: 'new core\n' },
  { name: 'run.sh', body: '#!/bin/sh\n', mode: 0o775 },
];
// Bytewise, "run.sh" sorts before "runtime.lock" ('.' is 0x2e, 't' is 0x74).
const BUNDLE_H = sha(`0755 ${sha('#!/bin/sh\n')} run.sh\n0644 ${sha(lockFor(NODE_BIN, CADDY_BIN))} runtime.lock\n0644 ${sha('new core\n')} src/main-core.ts\n`);

test('KBOX-6 POST /api/updates answers 201 with the hash it computed and the running base, stages the tree, and the page carries the fixed sentence byte for byte', async (t) => {
  const { iw, w, post } = await updateWorld(t);
  const reply = await post(tarOf(BUNDLE));
  assert.equal(reply.status, 201, reply.body);
  const body = reply.json() as { approval_id: string; hash: string; base: string };
  assert.deepEqual({ hash: body.hash, base: body.base }, { hash: BUNDLE_H, base: iw.h0 });
  assert.equal(readFileSync(join(iw.paths.staging, BUNDLE_H, 'src/main-core.ts'), 'utf8'), 'new core\n');
  const item = (await w.queue()).find((q) => q.approval_id === body.approval_id);
  assert.ok(item);
  assert.ok(item.lines.includes('Agents wrote this version and only agents checked it. Any change can take every key, and this page cannot tell whether it is safe.'));
  assert.ok(item.lines.includes(`Install key box version ${BUNDLE_H.slice(0, 12)} (commit ${C.slice(0, 12)}) over version ${iw.h0.slice(0, 12)}`));
});

test('KBOX-6 the intake refuses a truncated tar with a fixed code, another media type, a bad commit and a relay token', async (t) => {
  const { w, post } = await updateWorld(t);
  const cut = await post(tarOf(BUNDLE).subarray(0, 700));
  assert.equal(cut.status, 400);
  assert.equal((cut.json() as { error: { detail?: { code: string } } }).error.detail?.code, 'truncated');
  assert.equal((await post(tarOf(BUNDLE), `?commit=${C}`, 'application/json')).status, 415);
  assert.equal((await post(tarOf(BUNDLE), '?commit=xyz')).status, 400);
  assert.equal((await post(tarOf(BUNDLE), `?commit=${C}&extra=1`)).status, 400);
  assert.equal((await post(tarOf(BUNDLE), `?commit=${C}`, 'application/x-tar', w.token('m1', 'relay'))).status, 403);
});

test('KBOX-6 on approval core writes <H>.request with the kept proof; root installs it; settle emits update.state installed', async (t) => {
  const { iw, w, post, updater, events } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  assert.equal((await w.decide(approval_id, 'approve', w.proofFor(item))).status, 200);
  const request = JSON.parse(readFileSync(join(iw.paths.staging, `${BUNDLE_H}.request`), 'utf8')) as { install: string; base: string; approval: { approval_id: string } };
  assert.deepEqual([request.install, request.base, request.approval.approval_id], [BUNDLE_H, iw.h0, approval_id]);
  assert.deepEqual(events('update.state'), [{ approval_id, state: 'pending' }]);
  await iw.run();
  assert.equal(iw.result(BUNDLE_H), 'installed', 'root verified the proof the phone made, against its own copy');
  updater.settle();
  assert.deepEqual(events('update.state').at(-1), { approval_id, state: 'installed' });
  assert.equal(updater.release(), BUNDLE_H);
});

test('KBOX-6 an approval after current moved off H0 writes no request: a new proposal is needed', async (t) => {
  const { iw, w, post, events } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  const moved = join(iw.paths.releases, 'f'.repeat(64));
  mkdirSync(moved);
  rmSync(iw.paths.current);
  symlinkSync(moved, iw.paths.current);
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  const decided = await w.decide(approval_id, 'approve', w.proofFor(item));
  assert.equal((decided.json() as { result: string }).result, 'failed');
  assert.deepEqual(events('approval.executed').at(-1), { approval_id, result: 'failed', reason_code: 'base_moved' });
  assert.equal(existsSync(join(iw.paths.staging, `${BUNDLE_H}.request`)), false);
});

test('KBOX-6 settle ignores a result older than the approval (an earlier try of the same H)', async (t) => {
  const { iw, w, post, updater, events } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  await w.decide(approval_id, 'approve', w.proofFor(item));
  writeFileSync(join(iw.paths.results, `${BUNDLE_H}.result`), 'rolled_back');
  utimesSync(join(iw.paths.results, `${BUNDLE_H}.result`), new Date(0), new Date(0));
  updater.settle();
  assert.deepEqual(events('update.state'), [{ approval_id, state: 'pending' }]);
});

test('KBOX-6 the real TrustPort writes a trust request root answers: applied changes trust.json, a refusal comes back with its code, no answer is timeout', async (t) => {
  const iw = await installWorld(t);
  const clock = new FakeClock(1_700_000_000_000);
  const port = createTrustInstaller({ stagingDir: iw.paths.staging, resultsDir: iw.paths.results, random: seededRandom(3), clock, wait: () => iw.run() });
  const added = iw.trusted('ap-second-0002', softApprover());
  // FORCED-FLIP: as of the spec revision 4 the signed approver_add names the new keys by hash, so the proof is over them.
  assert.deepEqual(await port.apply({ kind: 'trust', change: 'approver_add', approval: iw.proof(addActionOf(added)), approver: added }), { result: 'applied' });
  assert.deepEqual(iw.trust()?.approvers.map((a) => a.id), [iw.ownerId, 'ap-second-0002']);
  const stranger = softApprover();
  const refused = await port.apply({ kind: 'trust', change: 'approver_remove', approval: iw.proof({ kind: 'approver_remove', approver_id: iw.ownerId }, { approver: stranger }), approver_id: iw.ownerId });
  assert.deepEqual(refused, { result: 'refused', code: 'bad_proof' });
  const silent = createTrustInstaller({ stagingDir: iw.paths.staging, resultsDir: iw.paths.results, random: seededRandom(4), clock, wait: (ms) => Promise.resolve(clock.advance(ms)), timeoutMs: 2_000 });
  assert.deepEqual(await silent.apply({ kind: 'trust', change: 'approver_add', approval: iw.proof({ kind: 'approver_add' }), approver: iw.trusted('ap-third-00003', softApprover()) }), { result: 'refused', code: 'timeout' });
});

test('KBOX-6 core records the running release, and /healthz answers it; a value that is not a content hash is refused', async (t) => {
  const { iw, w, updater } = await updateWorld(t);
  w.parts.meta.setRelease(updater.release());
  const reply = await w.call('/healthz');
  assert.deepEqual(reply.json(), { release: iw.h0 });
  assert.throws(() => w.parts.meta.setRelease('unreleased'), RangeError);
});

test('KBOX-6 with no results directory (no kb-install on this machine) the real TrustPort refuses at once and writes no request', async (t) => {
  const iw = await installWorld(t);
  const port = createTrustInstaller({ stagingDir: iw.paths.staging, resultsDir: join(iw.root, 'absent'), random: seededRandom(5), clock: new FakeClock(0), wait: () => Promise.reject(new Error('must not wait')) });
  assert.deepEqual(await port.apply({ kind: 'trust', change: 'approver_add', approval: iw.proof({ kind: 'approver_add' }), approver: iw.trusted('ap-third-00003', softApprover()) }), { result: 'refused', code: 'no_installer' });
  assert.deepEqual(readdirSync(iw.paths.staging), []);
});

test('KBOX-6 the health check passes only when core and relay both answer /healthz with the new release, and gives up after 60 s', async (t) => {
  const dir = await tempDir(t);
  const answer = { core: 'a'.repeat(64), relay: 'b'.repeat(64) };
  const servers = (['core', 'relay'] as const).map((name) => {
    const server = createServer((_req, res) => void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ release: answer[name] })));
    server.listen(join(dir, `${name}.sock`));
    return server;
  });
  t.after(() => servers.forEach((s) => s.close()));
  await Promise.all(servers.map((s) => new Promise((r) => (s.listening ? r(undefined) : s.once('listening', r)))));
  const clock = new FakeClock(0);
  const units = systemdUnits({ systemctl: '/bin/true', units: [], healthSockets: [join(dir, 'core.sock'), join(dir, 'relay.sock')], clock, wait: (ms) => Promise.resolve(clock.advance(ms)) });
  assert.equal(await units.healthCheck('a'.repeat(64)), false, 'the relay still answers another release');
  assert.equal(clock.now() >= 60_000, true, 'it asked until the 60 s were up');
  answer.relay = 'a'.repeat(64);
  assert.equal(await units.healthCheck('a'.repeat(64)), true);
  const gone = systemdUnits({ systemctl: '/bin/true', units: [], healthSockets: [join(dir, 'none.sock')], clock, wait: (ms) => Promise.resolve(clock.advance(ms)) });
  assert.equal(await gone.healthCheck('a'.repeat(64)), false, 'no socket is no answer');
});

test('KBOX-6 a restart is bounded by the time kb-install gives it: a systemctl that hangs is killed and the restart fails', async (t) => {
  const dir = await tempDir(t);
  const hangs = join(dir, 'systemctl');
  writeFileSync(hangs, '#!/bin/sh\nexec sleep 20\n', { mode: 0o755 });
  const clock = new FakeClock(0);
  const units = systemdUnits({ systemctl: hangs, units: ['keybox.service'], healthSockets: [], clock, wait: (ms) => Promise.resolve(clock.advance(ms)) });
  await assert.rejects(units.restart(300));
});

test('KBOX-6 a health check gives up at the bound kb-install gives it when that comes before its own 60 s', async (t) => {
  const dir = await tempDir(t);
  const clock = new FakeClock(0);
  const units = systemdUnits({ systemctl: '/bin/true', units: [], healthSockets: [join(dir, 'none.sock')], clock, wait: (ms) => Promise.resolve(clock.advance(ms)) });
  assert.equal(await units.healthCheck('a'.repeat(64), 5_000), false);
  assert.ok(clock.now() >= 5_000 && clock.now() < 60_000, `it stopped asking at its bound (${clock.now()} ms)`);
});

test('KBOX-6 settle ends an install root answered failed:interrupted (a kill mid-install, rolled back by the next run) as failed interrupted', async (t) => {
  const { iw, w, post, updater, events } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  await w.decide(approval_id, 'approve', w.proofFor(item));
  writeFileSync(join(iw.paths.results, `${BUNDLE_H}.result`), 'failed:interrupted');
  updater.settle();
  assert.deepEqual(events('approval.executed').at(-1), { approval_id, result: 'failed', reason_code: 'interrupted' });
});

test('KBOX-6 a stale .<H>.tmp left in staging by a write that crashed does not block the request: on approval core still writes <H>.request', async (t) => {
  const { iw, w, post } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  writeFileSync(join(iw.paths.staging, `.${BUNDLE_H}.tmp`), '{"half":');
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  assert.equal((await w.decide(approval_id, 'approve', w.proofFor(item))).status, 200);
  const request = JSON.parse(readFileSync(join(iw.paths.staging, `${BUNDLE_H}.request`), 'utf8')) as { install: string };
  assert.equal(request.install, BUNDLE_H);
  assert.equal(existsSync(join(iw.paths.staging, `.${BUNDLE_H}.tmp`)), false);
});

test('KBOX-6 a trust request carries the deadline after which root refuses it, and core still takes an answer root gives just after that deadline', async (t) => {
  const iw = await installWorld(t);
  const clock = new FakeClock(1_700_000_000_000);
  const start = clock.now();
  let request: { deadline?: unknown } | undefined;
  const answerLate = (ms: number): Promise<void> => {
    clock.advance(ms);
    const name = readdirSync(iw.paths.staging).find((f) => f.endsWith('.request'));
    if (name !== undefined) request = JSON.parse(readFileSync(join(iw.paths.staging, name), 'utf8')) as { deadline?: unknown };
    // Root checked the deadline just before it and writes its answer a second after it.
    if (name !== undefined && typeof request?.deadline === 'number' && clock.now() >= request.deadline + 1_000) writeFileSync(join(iw.paths.results, `${name.slice(0, -'.request'.length)}.result`), 'applied');
    return Promise.resolve();
  };
  const port = createTrustInstaller({ stagingDir: iw.paths.staging, resultsDir: iw.paths.results, random: seededRandom(6), clock, wait: answerLate, timeoutMs: 2_000 });
  const added = iw.trusted('ap-late-000004', softApprover());
  assert.deepEqual(await port.apply({ kind: 'trust', change: 'approver_add', approval: iw.proof(addActionOf(added)), approver: added }), { result: 'applied' });
  assert.equal(request?.deadline, start + 2_000);
});

// --- pruning: nothing core staged or root answered outlives its approval ------------------------------------------------

const stagingNames = (iw: { readonly paths: { readonly staging: string } }): string[] => readdirSync(iw.paths.staging).sort();

test('KBOX-6 once an install is settled core removes staging/<H> and <H>.bin, and root then removes <H>.result at its next run', async (t) => {
  const { iw, w, post, updater } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  mkdirSync(join(iw.paths.staging, `${BUNDLE_H}.bin`));
  writeFileSync(join(iw.paths.staging, `${BUNDLE_H}.bin`, 'node'), 'a binary');
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  await w.decide(approval_id, 'approve', w.proofFor(item));
  updater.settle();
  assert.ok(stagingNames(iw).includes(BUNDLE_H), 'kept while root has not answered');
  await iw.run();
  assert.equal(iw.result(BUNDLE_H), 'installed');
  updater.settle();
  assert.deepEqual(stagingNames(iw).filter((n) => n.startsWith(BUNDLE_H)), [`${BUNDLE_H}.settled`]);
  await iw.run();
  assert.equal(iw.result(BUNDLE_H), undefined, 'root removed the answer core has read');
  assert.deepEqual(stagingNames(iw), []);
});

test('KBOX-6 a denied install proposal leaves nothing staged once settle runs, while a pending one keeps its tree', async (t) => {
  const { iw, w, post, updater } = await updateWorld(t);
  const { approval_id } = (await post(tarOf(BUNDLE))).json() as { approval_id: string };
  updater.settle();
  assert.deepEqual(stagingNames(iw), [BUNDLE_H], 'pending: kept');
  const item = (await w.queue()).find((q) => q.approval_id === approval_id);
  assert.ok(item);
  assert.equal((await w.decide(approval_id, 'deny', w.proofFor(item, undefined, undefined, 'deny'))).status, 200);
  updater.settle();
  assert.deepEqual(stagingNames(iw), []);
});

test('KBOX-6 a trust answer core has read is removed by root at its next run', async (t) => {
  const iw = await installWorld(t);
  const clock = new FakeClock(1_700_000_000_000);
  const port = createTrustInstaller({ stagingDir: iw.paths.staging, resultsDir: iw.paths.results, random: seededRandom(7), clock, wait: () => iw.run() });
  const added = iw.trusted('ap-second-0002', softApprover());
  assert.deepEqual(await port.apply({ kind: 'trust', change: 'approver_add', approval: iw.proof(addActionOf(added)), approver: added }), { result: 'applied' });
  assert.ok(readdirSync(iw.paths.results).some((f) => f.startsWith('trust-')));
  await iw.run();
  assert.deepEqual(readdirSync(iw.paths.results).filter((f) => f.startsWith('trust-') && f !== 'trust-spent'), []);
  assert.deepEqual(stagingNames(iw), []);
});
