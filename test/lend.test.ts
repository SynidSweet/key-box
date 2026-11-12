// KBOX-3: master keys never reach the relay. Core lends a value over the lend socket only for an admin key granted to the
// pass's machine whose profile has the asked rule; the class check is in the lend handler. These tests talk to core's lend
// socket the way kb-relay does, and through the running relay where the relay's answer is the point.
import assert from 'node:assert/strict';
import { chmodSync, statSync } from 'node:fs';
import { connect } from 'node:net';
import { test } from 'node:test';
import { FRAME_JSON, parseGrantsAnswer } from '../src/pure/lend-protocol.ts';
import { relayErrorBody } from '../src/pure/relay-errors.ts';
import { hashToken } from '../src/pure/tokens.ts';
import { FrameDecoder, LendUnavailable, createLendClient, encodeFrame } from '../src/shell/lend-socket.ts';
import { bytesOf, canary, waitUntil } from './kit/index.ts';
import { lendWorld } from './support/lend-world.ts';
import type { LendWorld } from './support/lend-world.ts';
import { relayWorld } from './support/relay-world.ts';
import { PROJECT_REGISTRY } from './fixtures/profiles.ts';

const NETWORK = '203.0.113.0/24';
const textValue = (bytes: Uint8Array): Uint8Array => Buffer.from(Buffer.from(bytes).toString('hex'));

async function granted(t: Parameters<typeof lendWorld>[0]): Promise<{ readonly w: LendWorld; readonly pass: string; readonly value: Uint8Array; readonly c: ReturnType<typeof canary> }> {
  const w = await lendWorld(t);
  const c = canary();
  const value = textValue(c.bytes);
  const pass = w.enrol('laptop');
  w.addKey({ keyref: 'adminkey1', value, grants: ['laptop'] });
  return { w, pass, value, c };
}

const lendOf = (w: LendWorld, pass: string, keyref: string, rule = 'models-list') => w.client.lend({ op: 'lend', token_hash: hashToken(pass), keyref, rule_id: rule });

test('KBOX-3 an admin key granted to the pass machine, with a rule of its profile, is lent for that one call', async (t) => {
  const { w, pass, value } = await granted(t);
  const answer = await lendOf(w, pass, 'adminkey1');
  assert.ok(answer.ok);
  assert.deepEqual(Buffer.from(await bytesOf(answer.value)), Buffer.from(value));
  assert.equal(String(answer.value).includes(Buffer.from(value).toString()), false);
});

test('KBOX-3 a master keyref is refused with no value sent, even when granted and the rule matches', async (t) => {
  const { w, pass, c } = await granted(t);
  w.addKey({ keyref: 'masterkey1', value: textValue(c.bytes), cls: 'master', grants: ['laptop'] });
  assert.deepEqual(await lendOf(w, pass, 'masterkey1'), { ok: false, code: 'forbidden' });
  const raw = await rawExchange(w.socket, { op: 'lend', token_hash: hashToken(pass), keyref: 'masterkey1', rule_id: 'models-list' });
  c.assertAbsent({ answer: raw });
});

test('KBOX-3 an ordinary keyref is refused', async (t) => {
  const { w, pass, c } = await granted(t);
  w.addKey({ keyref: 'ordinary01', value: textValue(c.bytes), cls: 'ordinary', grants: ['laptop'] });
  assert.deepEqual(await lendOf(w, pass, 'ordinary01'), { ok: false, code: 'forbidden' });
});

test('KBOX-3 a keyref without a grant for the pass machine, or unknown, is refused', async (t) => {
  const { w, pass } = await granted(t);
  const other = w.enrol('desktop');
  w.addKey({ keyref: 'adminkey2', value: Buffer.from('another value'), grants: ['desktop'] });
  assert.deepEqual(await lendOf(w, pass, 'adminkey2'), { ok: false, code: 'forbidden' });
  assert.deepEqual(await lendOf(w, pass, 'nosuchkey'), { ok: false, code: 'forbidden' });
  assert.equal((await lendOf(w, other, 'adminkey2')).ok, true);
});

test('KBOX-3 a revoked pass, an unknown pass and a control token are refused as bad_token', async (t) => {
  const { w, pass } = await granted(t);
  const control = w.enrol('desk', 'control');
  w.core.meta.putGrant('adminkey1', 'desk');
  assert.deepEqual(await lendOf(w, control, 'adminkey1'), { ok: false, code: 'bad_token' });
  assert.deepEqual(await lendOf(w, `kbt_${'A'.repeat(43)}`, 'adminkey1'), { ok: false, code: 'bad_token' });
  w.core.meta.revokeMachine('laptop');
  assert.deepEqual(await lendOf(w, pass, 'adminkey1'), { ok: false, code: 'bad_token' });
});

test('KBOX-3 a rule id not in the key profile, or a key whose platform has no relay profile, is refused', async (t) => {
  const { w, pass } = await granted(t);
  assert.deepEqual(await lendOf(w, pass, 'adminkey1', 'accounts-list'), { ok: false, code: 'forbidden' });
  assert.deepEqual(await lendOf(w, pass, 'adminkey1', 'no-such-rule'), { ok: false, code: 'forbidden' });
  w.addKey({ keyref: 'plainkey1', value: Buffer.from('plain value'), platform: 'plain', grants: ['laptop'] });
  assert.deepEqual(await lendOf(w, pass, 'plainkey1'), { ok: false, code: 'forbidden' });
});

/** Sends one JSON frame on a fresh connection and returns everything core sent before it closed. */
async function rawExchange(socket: string, request: unknown, second?: unknown): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const conn = connect(socket);
    const got: Buffer[] = [];
    conn.on('data', (d: Buffer) => {
      got.push(d);
      if (second !== undefined) conn.write(encodeFrame(FRAME_JSON, Buffer.from(JSON.stringify(second))));
    });
    conn.on('error', reject);
    conn.on('close', () => resolve(Buffer.concat(got)));
    conn.write(encodeFrame(FRAME_JSON, Buffer.from(JSON.stringify(request))));
  });
}

test('KBOX-3 a lend answer is one-shot: a second request on the same connection gets nothing', async (t) => {
  const { w, pass, value } = await granted(t);
  const request = { op: 'lend', token_hash: hashToken(pass), keyref: 'adminkey1', rule_id: 'models-list' };
  const raw = await rawExchange(w.socket, request, request);
  const frames = new FrameDecoder().push(raw);
  assert.equal(frames.length, 1, 'one answer frame, then the connection closed');
  assert.deepEqual(Buffer.from(frames[0]?.body ?? []), Buffer.from(value));
});

test('KBOX-3 a malformed request, an unknown op or an oversized frame is refused and lends nothing', async (t) => {
  const { w, pass, c } = await granted(t);
  for (const request of [{ op: 'lend', token_hash: hashToken(pass), keyref: 'adminkey1' }, { op: 'give', token_hash: hashToken(pass), keyref: 'adminkey1', rule_id: 'models-list' }, 'lend', { op: 'lend', token_hash: hashToken(pass), keyref: 'adminkey1', rule_id: 'models-list', extra: 1 }]) {
    const raw = await rawExchange(w.socket, request);
    c.assertAbsent({ answer: raw });
    const frames = new FrameDecoder().push(raw);
    assert.equal(frames[0]?.kind, FRAME_JSON);
    assert.deepEqual(JSON.parse(Buffer.from(frames[0]?.body ?? []).toString()), { ok: 'false', code: 'bad_request' });
  }
  const oversized = await new Promise<Buffer>((resolve, reject) => {
    const conn = connect(w.socket);
    const got: Buffer[] = [];
    conn.on('data', (d: Buffer) => got.push(d));
    conn.on('error', reject);
    conn.on('close', () => resolve(Buffer.concat(got)));
    const header = Buffer.alloc(4);
    header.writeUInt32BE(64 * 1024 * 1024);
    conn.write(header);
  });
  c.assertAbsent({ answer: oversized });
});

test('KBOX-3 the lend socket is made 0660 whatever the umask, and a process the socket mode refuses gets no lend (relay answer: unavailable)', async (t) => {
  const before = process.umask(0o000);
  let world: Awaited<ReturnType<typeof granted>>;
  try {
    world = await granted(t);
  } finally {
    process.umask(before);
  }
  const { w, pass } = world;
  assert.equal(statSync(w.socket).mode & 0o777, 0o660);
  chmodSync(w.socket, 0o440);
  try {
    await assert.rejects(lendOf(w, pass, 'adminkey1'), (e: unknown) => e instanceof LendUnavailable);
  } finally {
    chmodSync(w.socket, 0o660);
  }
});

test('KBOX-3 core down: a lend client on a socket nobody listens on fails as unavailable', async (t) => {
  const w = await lendWorld(t);
  await w.server.stop();
  await assert.rejects(createLendClient(w.socket).resolve({ op: 'resolve', token_hash: '0'.repeat(64), keyref: 'adminkey1', network: NETWORK }), (e: unknown) => e instanceof LendUnavailable);
});

test('KBOX-3 resolve names the pass label and the key platform for a granted key and records the pass network once', async (t) => {
  const { w, pass } = await granted(t);
  const resolve = (network: string) => w.client.resolve({ op: 'resolve', token_hash: hashToken(pass), keyref: 'adminkey1', network });
  assert.deepEqual(await resolve(NETWORK), { ok: true, label: 'laptop', platform: 'pathplat' });
  await resolve(NETWORK);
  const networks = w.core.events.after(0).filter((e) => e.kind === 'token.new_network');
  assert.deepEqual(networks.map((e) => e.data), [{ label: 'laptop', network: NETWORK }]);
  assert.deepEqual(await w.client.resolve({ op: 'resolve', token_hash: hashToken(pass), keyref: 'nosuchkey', network: NETWORK }), { ok: false, code: 'forbidden' });
});

test('KBOX-32 grants lists the admin keys granted to the pass machine with a relay profile, never another machine key and never a value', async (t) => {
  const { w, pass, c } = await granted(t);
  w.enrol('desktop');
  w.addKey({ keyref: 'desktopkey', value: textValue(c.bytes), grants: ['desktop'] });
  w.addKey({ keyref: 'masterkey1', value: textValue(c.bytes), cls: 'master', grants: ['laptop'] });
  w.addKey({ keyref: 'hostkey001', value: textValue(c.bytes), platform: 'hostplat', grants: ['laptop'] });
  const answer = await w.client.grants({ op: 'grants', token_hash: hashToken(pass), network: NETWORK });
  assert.deepEqual(answer, {
    ok: true,
    machine: 'laptop',
    grants: [
      { keyref: 'adminkey1', platform: 'pathplat', name: 'KEY_ADMINKEY1', projects: ['shop'] },
      { keyref: 'hostkey001', platform: 'hostplat', name: 'KEY_HOSTKEY001', projects: ['shop'] },
    ],
  });
  c.assertAbsent({ answer: JSON.stringify(answer) });
});

test('KBOX-14 a scan session in core catches a copy of any value the box holds, a master value included, which never reaches the relay', async (t) => {
  const { w, pass, c } = await granted(t);
  const master = Buffer.from('MasterValueOnlyCoreHolds0123456789abcdef');
  w.addKey({ keyref: 'masterkey1', value: master, cls: 'master' });
  const opened = await w.client.scan({ op: 'scan', token_hash: hashToken(pass), keyref: 'adminkey1' });
  assert.ok(opened.ok);
  const first = await opened.session.feed(Buffer.from('{"data":"'));
  assert.equal(first.kind, 'progress');
  const hit = await opened.session.feed(Buffer.from(`${master.toString('base64')}"}`));
  assert.deepEqual(hit, { kind: 'hit', reason: 'value' });
  opened.session.close();
  c.assertAbsent({ step: JSON.stringify(hit) });
});

test('KBOX-14 a scan session releases a clean stream whole at its end, and refuses a pass with no grant', async (t) => {
  const { w, pass } = await granted(t);
  const opened = await w.client.scan({ op: 'scan', token_hash: hashToken(pass), keyref: 'adminkey1' });
  assert.ok(opened.ok);
  await opened.session.feed(Buffer.from('{"ok":true,"items":[1,2,3]}'));
  assert.deepEqual(await opened.session.end(), { kind: 'progress', releasable: 27 });
  const stranger = w.enrol('stranger');
  assert.deepEqual(await w.client.scan({ op: 'scan', token_hash: hashToken(stranger), keyref: 'adminkey1' }), { ok: false, code: 'forbidden' });
});

test('KBOX-50 a relay audit row is written closed (rule id, status, bytes, source, no query) and a withheld response raises the owner notice', async (t) => {
  const { w } = await granted(t);
  await w.client.audit({ label: 'laptop', source: '203.0.113.9', agent: 'claude', project: 'shop', keyref: 'adminkey1', route: 'relay', method: 'GET', rule_id: 'models-list', status: 200, bytes: 12 });
  await w.client.audit({ label: 'laptop', source: '203.0.113.9', keyref: 'adminkey1', route: 'relay', method: 'GET', rule_id: 'models-list', status: 502, bytes: 0, code: 'withheld', reason: 'credential' });
  const rows = w.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
  assert.deepEqual(
    rows.map((r) => [r.actor, r.ref, r.detail]),
    [
      ['laptop', 'adminkey1', { route: 'relay', method: 'GET', status: 200, bytes: 12, source: '203.0.113.9', agent: 'claude', project: 'shop', rule_id: 'models-list' }],
      ['laptop', 'adminkey1', { route: 'relay', method: 'GET', status: 502, bytes: 0, source: '203.0.113.9', rule_id: 'models-list', code: 'withheld', reason: 'credential' }],
    ],
  );
  await waitUntil(() => w.core.events.after(0).some((e) => e.kind === 'box.notice'), 'the withheld notice');
  assert.deepEqual(w.core.events.after(0).filter((e) => e.kind === 'box.notice').map((e) => e.data), [{ code: 'credential_withheld', text: 'credential withheld' }]);
});

test('KBOX-3 the relay with core down answers 503 unavailable and journals fixed codes only, never the value', async (t) => {
  const w = await relayWorld(t);
  await w.lend.server.stop();
  const reply = await w.call('/r/adminkey1/v1/models');
  assert.deepEqual([reply.status, reply.body.toString()], [503, relayErrorBody('unavailable')]);
  assert.equal(w.upstream.requests.length, 0);
  assert.deepEqual([...w.journal], ['lend_unavailable', 'audit_unavailable']);
  w.canary.assertAbsent({ 'relay journal': w.journal.join('\n'), reply: reply.body });
});

// ---------------------------------------------------------------- the key's own allow set (KBOX-3, KBOX-25)

/** An admin key of the path profile whose own allow set is the one rule `model-get`. */
function addNarrowKey(w: LendWorld): void {
  w.addKey({ keyref: 'narrowkey1', value: Buffer.from('NarrowKeyValue0123456789abcdefgh'), grants: ['laptop'] });
  w.core.meta.putAllowRule('narrowkey1', 'model-get');
}

/** A key the meta store lists whose current generation is not in the vault (yet). */
function addUnstoredKey(w: LendWorld, keyref: string): void {
  w.core.meta.putKey({
    keyref,
    platform: 'pathplat',
    name: `KEY_${keyref.toUpperCase()}`,
    projects: ['shop'],
    class: 'admin',
    status: 'works',
    gen_current: 1,
    schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
    coverage: null,
    last_use_at: null,
  });
}

test('KBOX-3 a key with its own allow set is lent only for a rule in that set; with none set it gets the profile list', async (t) => {
  const { w, pass } = await granted(t);
  addNarrowKey(w);
  assert.equal((await lendOf(w, pass, 'narrowkey1', 'model-get')).ok, true, 'a rule in the key set');
  assert.deepEqual(await lendOf(w, pass, 'narrowkey1', 'models-list'), { ok: false, code: 'forbidden' }, 'a profile rule outside the key set');
  assert.deepEqual(await lendOf(w, pass, 'narrowkey1', 'no-such-rule'), { ok: false, code: 'forbidden' });
  assert.equal((await lendOf(w, pass, 'adminkey1', 'models-list')).ok, true, 'a key with no set of its own gets the profile list');
  assert.equal((await lendOf(w, pass, 'adminkey1', 'model-get')).ok, true);
});

test('KBOX-3 through the relay: a request matching a profile rule outside the key set is 403 with no upstream call; one inside the set passes', async (t) => {
  const w = await relayWorld(t);
  addNarrowKey(w.lend);
  const outside = await w.call('/r/narrowkey1/v1/models');
  assert.deepEqual([outside.status, outside.body.toString()], [403, relayErrorBody('forbidden')]);
  assert.equal(w.upstream.requests.length, 0);
  const inside = await w.call('/r/narrowkey1/v1/models/gpt-4');
  assert.equal(inside.status, 200);
  assert.equal(w.upstream.requests.length, 1);
});

// ---------------------------------------------------------------- minted values (KBOX-14, KBOX-41)

/** Whether a scan session over `text` cuts it. A clean stream is released whole at its end. */
async function cutsStream(w: LendWorld, pass: string, text: string): Promise<boolean> {
  const opened = await w.client.scan({ op: 'scan', token_hash: hashToken(pass), keyref: 'adminkey1' });
  assert.ok(opened.ok);
  try {
    const step = await opened.session.feed(Buffer.from(text));
    return step.kind === 'hit' || (await opened.session.end()).kind === 'hit';
  } finally {
    opened.session.close();
  }
}

const MINTED = 'Zm9vYmFy/cXV4+QmF6eHl6MDEyMzQ1Njc4OQ9aB';
/** The minted value as an upstream echo might carry it: the forms the scanner knows. */
const MINTED_FORMS: Readonly<Record<string, string>> = {
  raw: MINTED,
  'JSON-escaped': MINTED.replaceAll('/', '\\/'),
  base64: Buffer.from(MINTED).toString('base64'),
  'base64 shifted by one byte': Buffer.from(`x${MINTED}`).toString('base64'),
  percent: encodeURIComponent(MINTED),
  '\\u-escaped': [...MINTED].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
};

test('KBOX-14 a minted value is cut in every form the scanner knows while it lives, and is no longer held after it expires', async (t) => {
  const { w, pass } = await granted(t);
  const expiresAt = w.clock.now() + 60_000;
  for (const [name, form] of Object.entries(MINTED_FORMS)) assert.equal(await cutsStream(w, pass, `{"echo":"${form}"}`), false, `${name}: not held before it is registered`);
  w.minted.add('adminkey1', Buffer.from(MINTED), expiresAt);
  for (const [name, form] of Object.entries(MINTED_FORMS)) assert.equal(await cutsStream(w, pass, `{"echo":"${form}"}`), true, `${name}: held while it lives`);
  w.clock.advance(59_999);
  assert.equal(await cutsStream(w, pass, `{"echo":"${MINTED}"}`), true, 'still held one millisecond before expiry');
  w.clock.advance(1);
  for (const [name, form] of Object.entries(MINTED_FORMS)) assert.equal(await cutsStream(w, pass, `{"echo":"${form}"}`), false, `${name}: dropped at expiry`);
});

test('KBOX-14 a minted value the scanner cannot build forms of (empty, a NUL byte, one byte) is refused when it is added, so it is never injected unscanned', async (t) => {
  const { w } = await granted(t);
  for (const value of [Buffer.alloc(0), Buffer.from('ab\0cd'), Buffer.from('a')]) {
    assert.throws(() => w.minted.add('adminkey1', value, w.clock.now() + 1000), RangeError);
  }
});

// ---------------------------------------------------------------- forms that cannot be built (KBOX-14, fail closed)

test('KBOX-14 a generation that is not in the vault yet is scanned from the moment it is stored: an empty result is never cached', async (t) => {
  const { w, pass } = await granted(t);
  addUnstoredKey(w, 'latekey001');
  assert.equal(await cutsStream(w, pass, '{"echo":"LateValue0123456789abcdefghijklmn"}'), false, 'nothing to match yet');
  w.core.vault.put('latekey001', 1, Buffer.from('LateValue0123456789abcdefghijklmn'));
  assert.equal(await cutsStream(w, pass, '{"echo":"LateValue0123456789abcdefghijklmn"}'), true);
});

test('KBOX-14 a key whose forms cannot be built is refused for lend and scan, with a fixed journal code; other keys are still scanned', async (t) => {
  const { w, pass, value } = await granted(t);
  w.addKey({ keyref: 'nulkey0001', value: Buffer.from('ab\0cd'), grants: ['laptop'] });
  assert.deepEqual(await lendOf(w, pass, 'nulkey0001'), { ok: false, code: 'forbidden' });
  assert.deepEqual(await w.client.scan({ op: 'scan', token_hash: hashToken(pass), keyref: 'nulkey0001' }), { ok: false, code: 'forbidden' });
  assert.deepEqual([...new Set(w.journal)], ['forms_unbuildable']);
  const other = await lendOf(w, pass, 'adminkey1');
  assert.equal(other.ok, true, 'another key is lent as before');
  assert.equal(await cutsStream(w, pass, `{"echo":"${Buffer.from(value).toString()}"}`), true, 'and its value is still held by the scan');
});

// ---------------------------------------------------------------- KBOX-57: a project-host key is lent only for its stored project

const STORED = 'abcdefgh';
/** A valid-looking ref the key's `projects` name: never placement (the negative control). */
const OTHER = 'zyxwvuts';

/** `at` null stores no rotation record for the key. */
async function projectKey(t: Parameters<typeof lendWorld>[0], at: { readonly project?: string } | null = { project: STORED }) {
  const w = await lendWorld(t, PROJECT_REGISTRY);
  const c = canary();
  const pass = w.enrol('laptop');
  w.addKey({ keyref: 'projkey01', value: textValue(c.bytes), platform: 'projplat', grants: ['laptop'], projects: [OTHER], ...(at === null ? {} : { at }) });
  return { w, pass, c };
}

const resolveProject = (w: LendWorld, pass: string, keyref = 'projkey01') => w.client.resolve({ op: 'resolve', token_hash: hashToken(pass), keyref, network: NETWORK });
const projectLend = (keyref: string, pass: string, project: string | undefined, rule = 'rows-list') => ({ op: 'lend' as const, token_hash: hashToken(pass), keyref, rule_id: rule, ...(project === undefined ? {} : { project }) });
const mismatchRows = (w: LendWorld) => w.core.audit.read(0).entries.filter((r) => r.action === 'lend.refused').map((r) => [r.actor, r.ref, r.detail['op'], r.detail['code']]);

test('KBOX-57 negative control: resolve answers a project-host key with its stored project, never the ref its projects name', async (t) => {
  const { w, pass } = await projectKey(t);
  assert.deepEqual(await resolveProject(w, pass), { ok: true, label: 'laptop', platform: 'projplat', project: STORED });
  w.addKey({ keyref: 'pathkey01', value: Buffer.from('a path value'), grants: ['laptop'], at: { project: STORED } });
  assert.deepEqual(await resolveProject(w, pass, 'pathkey01'), { ok: true, label: 'laptop', platform: 'pathplat' }, 'a fixed-origin key names no project, stored or not');
  assert.deepEqual(mismatchRows(w), []);
});

test('KBOX-3 a project-host lend naming the stored project is lent; another project or none is forbidden, audited location_mismatch, and sends no value frame', async (t) => {
  const { w, pass, c } = await projectKey(t);
  const lent = await w.client.lend(projectLend('projkey01', pass, STORED));
  assert.ok(lent.ok, 'control: the stored project is lent');
  assert.deepEqual(await w.client.lend(projectLend('projkey01', pass, OTHER)), { ok: false, code: 'forbidden' });
  assert.deepEqual(await w.client.lend(projectLend('projkey01', pass, undefined)), { ok: false, code: 'forbidden' });
  c.assertAbsent({ answer: await rawExchange(w.socket, projectLend('projkey01', pass, OTHER)) });
  assert.deepEqual(mismatchRows(w), [
    ['laptop', 'projkey01', 'lend', 'location_mismatch'],
    ['laptop', 'projkey01', 'lend', 'location_mismatch'],
    ['laptop', 'projkey01', 'lend', 'location_mismatch'],
  ]);
});

test('KBOX-57 a project-host key with no stored project (no record, or a record naming none): resolve and every lend are forbidden, audited location_mismatch, no value frame', async (t) => {
  for (const at of [null, {}]) {
    const { w, pass, c } = await projectKey(t, at);
    assert.deepEqual(await resolveProject(w, pass), { ok: false, code: 'forbidden' });
    assert.deepEqual(await w.client.lend(projectLend('projkey01', pass, undefined)), { ok: false, code: 'forbidden' });
    c.assertAbsent({ answer: await rawExchange(w.socket, projectLend('projkey01', pass, OTHER)) });
    assert.deepEqual(mismatchRows(w), [
      ['laptop', 'projkey01', 'resolve', 'location_mismatch'],
      ['laptop', 'projkey01', 'lend', 'location_mismatch'],
      ['laptop', 'projkey01', 'lend', 'location_mismatch'],
    ], JSON.stringify(at));
  }
});

test('KBOX-57 a key deleted and re-added at another project between resolve and lend: the earlier lend is refused, a lend for the new place is not', async (t) => {
  const { w, pass } = await projectKey(t);
  const resolved = await resolveProject(w, pass);
  assert.deepEqual(resolved, { ok: true, label: 'laptop', platform: 'projplat', project: STORED });
  w.readdAt('projkey01', { project: OTHER });
  assert.deepEqual(await w.client.lend(projectLend('projkey01', pass, STORED)), { ok: false, code: 'forbidden' });
  assert.deepEqual(mismatchRows(w), [['laptop', 'projkey01', 'lend', 'location_mismatch']]);
  assert.equal((await w.client.lend(projectLend('projkey01', pass, OTHER))).ok, true, 'control: the stored place now is lent');
});

test('KBOX-3 a lend naming a project for a key whose profile is not project-host is forbidden, audited location_mismatch, even when it equals the stored project', async (t) => {
  const { w, pass } = await granted(t);
  w.addKey({ keyref: 'pathkey01', value: Buffer.from('a path value'), grants: ['laptop'], at: { project: STORED } });
  assert.deepEqual(await w.client.lend(projectLend('pathkey01', pass, STORED, 'models-list')), { ok: false, code: 'forbidden' });
  assert.deepEqual(mismatchRows(w), [['laptop', 'pathkey01', 'lend', 'location_mismatch']]);
  assert.equal((await w.client.lend(projectLend('pathkey01', pass, undefined, 'models-list'))).ok, true, 'control: without a project it is lent');
});

// ---------------------------------------------------------------- KBOX-3: every keyref on the lend socket has the stored shape

const REAL_KEYREF = 'openai/shop/OPENAI_KEY';

test('KBOX-3 resolve, lend, scan, audit and grants all accept a real keyref (a stored keyref has "/" and upper case)', async (t) => {
  const w = await lendWorld(t);
  const pass = w.enrol('laptop');
  w.addKey({ keyref: REAL_KEYREF, value: textValue(canary().bytes), platform: 'pathplat', grants: ['laptop'] });
  const token_hash = hashToken(pass);
  assert.equal((await w.client.resolve({ op: 'resolve', token_hash, keyref: REAL_KEYREF, network: NETWORK })).ok, true);
  const lent = await w.client.lend({ op: 'lend', token_hash, keyref: REAL_KEYREF, rule_id: 'models-list' });
  assert.equal(lent.ok, true);
  assert.equal((await w.client.scan({ op: 'scan', token_hash, keyref: REAL_KEYREF })).ok, true);
  await w.client.audit({ label: 'laptop', source: '203.0.113.9', keyref: REAL_KEYREF, route: 'relay', method: 'GET', rule_id: 'models-list', status: 200, bytes: 1 });
  assert.deepEqual(w.core.audit.read(0).entries.filter((r) => r.action === 'relay.request').map((r) => r.ref), [REAL_KEYREF]);
  const grants = await w.client.grants({ op: 'grants', token_hash, network: NETWORK });
  assert.deepEqual(grants.ok ? grants.grants.map((g) => g.keyref) : 'refused', [REAL_KEYREF]);
});

test('KBOX-3 resolve, lend and scan refuse a keyref that is not a stored shape ("~", "%2F", 129 characters) as bad_request', async (t) => {
  const { w, pass } = await granted(t);
  const token_hash = hashToken(pass);
  for (const keyref of ['a~b', 'a%2Fb', 'a'.repeat(129)]) {
    for (const request of [{ op: 'resolve', token_hash, keyref, network: NETWORK }, { op: 'lend', token_hash, keyref, rule_id: 'models-list' }, { op: 'scan', token_hash, keyref }]) {
      const frames = new FrameDecoder().push(await rawExchange(w.socket, request));
      assert.deepEqual(JSON.parse(Buffer.from(frames[0]?.body ?? []).toString()), { ok: 'false', code: 'bad_request' }, `${request.op} ${keyref.slice(0, 8)}`);
    }
  }
});

test('KBOX-3 parseGrantsAnswer accepts a grant whose keyref holds "/" and refuses one holding "~"', () => {
  const answer = (keyref: string) => ({ ok: 'true', machine: 'laptop', grants: [{ keyref, platform: 'pathplat', name: 'OPENAI_KEY', projects: ['shop'] }] });
  assert.equal(parseGrantsAnswer(answer(REAL_KEYREF)).ok, true);
  assert.equal(parseGrantsAnswer(answer('a~b')).ok, false);
});
