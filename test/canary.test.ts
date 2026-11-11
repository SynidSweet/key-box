// KBOX-2: a value leaves the box only to an approved destination or a relayed upstream. The canary suite is extended by every
// unit that adds a response, log line or event. Here: vault, adapter errors, requests, the frame, and the running process.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { ApiError, wrapAdapterCall } from '../src/pure/errors.ts';
import { text, NAME, oneOf } from '../src/pure/schemas.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { createMetaStore } from '../src/shell/meta.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { createEventHub } from '../src/shell/events.ts';
import { route } from '../src/shell/http.ts';
import { findDerived } from './kit/derived-forms.ts';
import { FakeClock, bytesOf, canary, drive, fakePlatform, seededRandom, startCore, startNode, tempDir } from './kit/index.ts';
import type { Surface } from './kit/index.ts';

const MODES = ['quote', 'adapter', 'platform-echo', 'plain'] as const;
const REF = 'openai/master';

test('KBOX-2 a value put in the vault, quoted by a failing handler and echoed by a failing platform, reaches no surface but the vault file', async (t) => {
  const platform = await fakePlatform(t);
  await platform.setMode('401-echo');
  let box: Awaited<ReturnType<typeof startCore>> | undefined;
  const c = canary(40);
  const quoting = (value: Uint8Array): string => `${Buffer.from(value).toString('latin1')} ${Buffer.from(value).toString('base64')} ${Buffer.from(value).toString('hex')}`;
  const routes = [
    route({
      method: 'GET',
      path: '/api/test/leak',
      surface: 'api',
      scope: 'control',
      query: { mode: oneOf(...MODES), ref: text(NAME) },
      handle: async ({ query }) => {
        if (box === undefined) throw new Error('not started');
        const lent = box.vault.lend(query.ref, 1);
        switch (query.mode) {
          case 'quote':
            return lent.use((bytes) => Promise.reject(new Error(quoting(bytes), { cause: new Error(quoting(bytes)) })));
          case 'adapter':
            return wrapAdapterCall(() => lent.use((bytes) => Promise.reject(Object.assign(new Error(quoting(bytes)), { status: 502 }))));
          case 'platform-echo':
            return wrapAdapterCall(() =>
              lent.use(async (bytes) => {
                const res = await fetch(`${platform.url}/v1/keys`, { method: 'POST', headers: { authorization: `Bearer ${Buffer.from(bytes).toString('base64url')}` } });
                throw Object.assign(new Error(await res.text()), { status: res.status });
              }),
            );
          case 'plain':
            return { json: { shown: String(lent), inspected: inspect(lent), json: JSON.stringify(lent) } };
        }
      },
    }),
  ];
  box = await startCore(t, { extraRoutes: routes });
  const token = box.enrol('ctl-1', 'control');
  box.vault.put(REF, 1, c.bytes);
  const raw = Buffer.from(c.bytes).toString('base64url');
  const bodies: string[] = [];
  const take = async (path: string, call: Parameters<typeof box.call>[1] = {}): Promise<void> => {
    const reply = await box.call(path, { token, ...call });
    bodies.push(reply.body, JSON.stringify(reply.headers));
  };
  for (const mode of MODES) await take(`/api/test/leak?mode=${mode}&ref=${REF}`);
  await take(`/api/test/leak?mode=quote&ref=${REF}`, { headers: { 'x-forwarded-for': raw } });
  await take(`/api/test/leak?mode=${raw}&ref=${raw}`);
  await take(`/api/${raw}`);
  await take('/api/meta', { token: `kbt_${raw}`.slice(0, 47) });
  await take('/api/meta', { headers: { authorization: `Bearer ${raw}` } });
  for (const path of ['/api/meta', '/api/audit', '/api/events?since=0']) await take(path);
  assert.equal(platform.requests.length >= 1, true, 'the platform really was called with the value');

  box.db.exec('PRAGMA wal_checkpoint(PASSIVE)');
  const surfaces: Record<string, Surface> = {
    database: readFileSync(join(box.stateDir, 'meta.db')),
    wal: readFileSync(join(box.stateDir, 'meta.db-wal')),
    audit: JSON.stringify(box.audit.read(0).entries),
    journal: box.journal.join('\n'),
    events: JSON.stringify(box.events.after(0)),
    responses: bodies.join('\n'),
  };
  c.assertAbsent(surfaces);
  assert.deepEqual(findDerived(c.bytes, REF, surfaces), [], 'a prefix, suffix, length beside the name, or digest of the vault value is in a surface');
  assert.ok(bodies.some((b) => b.includes('"internal"')), 'the failing handlers did answer internal');
  assert.deepEqual(
    box.audit.read(0).entries.filter((r) => r.detail['status'] === 500).map((r) => r.detail['cause']),
    ['unhandled', 'adapter_failed', 'adapter_failed', 'unhandled'],
  );

  const vaultFiles = readdirSync(join(box.stateDir, 'vault', 'openai', 'master'));
  assert.deepEqual(vaultFiles, ['1']);
  assert.ok(c.findIn({ vault: readFileSync(join(box.stateDir, 'vault', 'openai', 'master', '1')) }).length > 0, 'positive control: the value is in the vault file');
  assert.equal(Buffer.from(await bytesOf(box.vault.lend(REF, 1))).equals(Buffer.from(c.bytes)), true);
});

test('KBOX-2 the frame never shows a length, a prefix, a suffix or a digest of a request value', async (t) => {
  const box = await startCore(t);
  const token = box.enrol('ctl-1', 'control');
  const c = canary(48);
  const raw = Buffer.from(c.bytes).toString('base64url');
  const forms = [raw.slice(0, 8), raw.slice(-8), raw.slice(8, 24), Buffer.from(c.bytes).toString('hex').slice(0, 16)];
  const replies = [
    await box.call(`/api/events?since=${raw}`, { token }),
    await box.call(`/api/audit?limit=${raw}`, { token }),
    await box.call(`/api/${raw}`, { token }),
  ];
  const everything = [...replies.map((r) => r.body), JSON.stringify(box.audit.read(0).entries), JSON.stringify(box.events.after(0))].join('\n');
  for (const piece of forms) assert.equal(everything.includes(piece), false, `a piece of the request value (${piece.length} characters) is in a surface`);
  for (const length of [String(c.bytes.length), String(raw.length)]) assert.equal(replies.some((r) => r.body.includes(length)), false);
  assert.equal(everything.includes(hashToken(raw)), false);
  assert.equal(everything.includes(hashToken(`kbt_${raw}`)), false);
});

test('KBOX-2 the running core process: a canary in the token, the body, the query and every header is in no response, no journal line and no database file', async (t) => {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const socket = join(dir, 'http.sock');
  const rng = seededRandom(5);
  const token = newToken(rng);
  mkdirSync(stateDir, { recursive: true });
  const db = openMetaDatabase(join(stateDir, 'meta.db'), rng);
  createMetaStore(db, new FakeClock(1), createEventHub()).addMachine({ label: 'ctl-1', scope: 'control', tokenSha256: hashToken(token), enrolledAt: 1 });
  db.close();

  const core = startNode(t, [new URL('../src/main-core.ts', import.meta.url).pathname], dir, { KB_STATE_DIR: stateDir, KB_SOCKET: socket });
  await core.ready('keybox core listening');
  const c = canary(36);
  const raw = Buffer.from(c.bytes).toString('base64url');
  const hex = Buffer.from(c.bytes).toString('hex');
  const driver = drive(socket);
  const bodies: string[] = [];
  const call = async (path: string, headers: Record<string, string>, body?: string): Promise<void> => {
    const reply = await driver.request({ path, method: body === undefined ? 'GET' : 'POST', headers: { 'x-kb-client-ip': '203.0.113.9', ...headers }, ...(body === undefined ? {} : { body }) });
    bodies.push(reply.body, JSON.stringify(reply.headers));
  };
  await call('/api/meta', { authorization: `Bearer ${token}` });
  await call(`/api/events?since=${raw}`, { authorization: `Bearer ${token}`, 'x-note': hex });
  await call(`/api/${raw}?x=${hex}`, { authorization: `Bearer ${token}` });
  await call('/api/meta', { authorization: `Bearer kbt_${raw}`.slice(0, 54) });
  await call('/api/meta', { authorization: `Bearer ${raw}`, origin: raw, cookie: hex });
  await call('/api/meta', { authorization: `Bearer ${token}`, 'x-forwarded-for': raw, forwarded: `for=${hex}` });
  await call('/api/meta', { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, JSON.stringify({ key: raw }));
  await call(`/${raw}`, { 'x-kb-client-ip': `${raw.slice(0, 20)}` });
  await call('/api/audit', { authorization: `Bearer ${token}` });
  const exit = await core.stop();
  assert.equal(exit.status, 0, exit.stderr);
  assert.equal(readdirSync(dir).includes('http.sock'), false, 'the socket file is removed when the core stops');

  const files = readdirSync(stateDir).filter((f) => f.startsWith('meta.db') || f.startsWith('private.db'));
  assert.ok(files.includes('private.db') && files.includes('meta.db'));
  const surfaces: Record<string, Surface> = { journal: `${exit.stdout}\n${exit.stderr}`, responses: bodies.join('\n') };
  for (const file of files) surfaces[file] = readFileSync(join(stateDir, file));
  c.assertAbsent(surfaces);
  assert.match(exit.stdout, /keybox core listening/);
  assert.equal(token.length, 47);
  assert.equal(bodies.join('').includes(token), false, 'the real token is in no response');
});

test('KBOX-2 a route that throws an ApiError carrying a detail shows only the closed code and detail', async (t) => {
  const box = await startCore(t, {
    extraRoutes: [route({ method: 'GET', path: '/api/test/detail', surface: 'api', scope: 'control', handle: () => { throw new ApiError('rejected', 'too_short'); } })],
  });
  const token = box.enrol('ctl-1', 'control');
  const reply = await box.call('/api/test/detail', { token });
  assert.deepEqual(reply.json(), { error: { code: 'rejected', message: 'The value did not pass its checks.', detail: { code: 'too_short' } } });
});

test('KBOX-2 the derived-form scan of a vault value finds a prefix, a suffix, a length beside the name and a digest in an audit row, an event, a database row and a WAL', async (t) => {
  const box = await startCore(t);
  const c = canary(40);
  const raw = Buffer.from(c.bytes);
  const digest = createHash('sha256').update(raw).digest();
  const planted: [string, string][] = [
    ['prefix', raw.subarray(0, 8).toString('hex')],
    ['prefix', raw.subarray(0, 8).toString('base64url')],
    ['suffix', raw.subarray(-8).toString('hex')],
    ['length', `${REF} 40`],
    ['length', `40 ${REF}`],
    ['sha256', digest.toString('hex')],
    ['sha256', digest.toString('base64')],
  ];
  const clean = findDerived(c.bytes, REF, { audit: JSON.stringify(box.audit.read(0).entries), events: JSON.stringify(box.events.after(0)) });
  assert.deepEqual(clean, [], 'nothing planted yet');
  for (const [form, text] of planted) {
    for (const where of ['audit', 'events', 'database', 'wal']) {
      const surface: Surface = where === 'database' || where === 'wal' ? Buffer.from(`\0\0${text}\0`) : `{"detail":{"note":"${text}"}}`;
      const hits = findDerived(c.bytes, REF, { [where]: surface });
      assert.ok(hits.some((h) => h.form.includes(form)), `${form} planted in ${where} (${text.length} characters) is found`);
    }
  }
  assert.deepEqual(findDerived(c.bytes, REF, { near: `${REF} 401 and 4040 ${'x'.repeat(40)} 40` }), [], 'a length that is not beside the name, or only part of a number, is no hit');
});
