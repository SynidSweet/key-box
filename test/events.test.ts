// KBOX-31: events are append-only rows in meta.db, and a long poll holds a request for 25 seconds.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { DatabaseSync } from 'node:sqlite';
import { ApiError, WriteRefused } from '../src/pure/errors.ts';
import { EVENT_KINDS, EVENT_SCHEMAS } from '../src/pure/schemas.ts';
import type { EventRow } from '../src/ports/events.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { createEventHub, createEventLog, createEventPoller } from '../src/shell/events.ts';
import { FakeClock, canary, checkProperty, seedFor, seededRandom, settle, tempDir } from './kit/index.ts';

const seed = seedFor(process.env);

async function world(t: import('node:test').TestContext): Promise<{ db: DatabaseSync; path: string; clock: FakeClock; log: ReturnType<typeof createEventLog>; poller: ReturnType<typeof createEventPoller> }> {
  const path = join(await tempDir(t), 'meta.db');
  const db = openMetaDatabase(path, seededRandom(seed));
  t.after(() => db.close());
  const clock = new FakeClock(5000);
  const hub = createEventHub();
  const log = createEventLog(db, clock, hub);
  return { db, path, clock, log, poller: createEventPoller(log, hub, clock, 25_000) };
}

const key = (n: number) => ({ keyref: `openai/key-${n}` });
const track = <T>(p: Promise<T>): { settled: () => boolean; result: () => Promise<T> } => {
  let done = false;
  void p.then(
    () => (done = true),
    () => (done = true),
  );
  return { settled: () => done, result: () => p };
};

test('KBOX-31 sequence numbers are strictly increasing from 1 and continue after the database is opened again', async (t) => {
  const { path, log } = await world(t);
  assert.equal(log.head(), 0);
  assert.deepEqual([log.append('key.changed', key(1)), log.append('key.changed', key(2)), log.append('share.version', { version: 4 })], [1, 2, 3]);
  assert.deepEqual(log.after(1).map((e) => [e.seq, e.at, e.kind, e.data]), [[2, 5000, 'key.changed', key(2)], [3, 5000, 'share.version', { version: 4 }]]);
  assert.deepEqual(log.after(3), []);
  const again = openMetaDatabase(path, seededRandom(seed));
  t.after(() => again.close());
  const log2 = createEventLog(again, new FakeClock(6000), createEventHub());
  assert.equal(log2.head(), 3);
  assert.equal(log2.append('key.changed', key(3)), 4);
});

test('KBOX-31 the long poll answers at once when events are already there', async (t) => {
  const { log, poller } = await world(t);
  log.append('key.changed', key(1));
  log.append('key.changed', key(2));
  const answer = await poller.wait(0, new AbortController().signal);
  assert.deepEqual(answer.events.map((e) => e.seq), [1, 2]);
  assert.equal(answer.cursor, 2);
  assert.deepEqual((await poller.wait(1, new AbortController().signal)).events.map((e) => e.seq), [2]);
});

test('KBOX-31 the long poll returns on the first event', async (t) => {
  const { log, poller, clock } = await world(t);
  log.append('key.changed', key(1));
  const waiting = track(poller.wait(1, new AbortController().signal));
  await settle();
  assert.equal(waiting.settled(), false);
  log.append('key.changed', key(2));
  const answer = await waiting.result();
  assert.deepEqual(answer.events.map((e) => e.seq), [2]);
  assert.equal(answer.cursor, 2);
  assert.equal(clock.pendingTimers, 0, 'the 25 second timer is cancelled once the poll has answered');
});

test('KBOX-31 the long poll returns an empty batch with the same cursor at 25 s of fake time, not before', async (t) => {
  const { log, poller, clock } = await world(t);
  log.append('key.changed', key(1));
  const waiting = track(poller.wait(1, new AbortController().signal));
  clock.advance(24_999);
  await settle();
  assert.equal(waiting.settled(), false);
  clock.advance(1);
  assert.deepEqual(await waiting.result(), { events: [], cursor: 1 });
});

test('KBOX-31 a missing since means the current head: nothing is replayed, only what comes next', async (t) => {
  const { log, poller, clock } = await world(t);
  log.append('key.changed', key(1));
  log.append('key.changed', key(2));
  const waiting = track(poller.wait(undefined, new AbortController().signal));
  await settle();
  assert.equal(waiting.settled(), false);
  log.append('key.changed', key(3));
  assert.deepEqual((await waiting.result()).events.map((e) => e.seq), [3]);
  const quiet = track(poller.wait(undefined, new AbortController().signal));
  clock.advance(25_000);
  assert.deepEqual(await quiet.result(), { events: [], cursor: 3 });
});

test('KBOX-31 two concurrent pollers both see every event, in order', async (t) => {
  const { log, poller } = await world(t);
  const follow = async (): Promise<number[]> => {
    const seen: number[] = [];
    let cursor = 0;
    while (seen.length < 5) {
      const answer = await poller.wait(cursor, new AbortController().signal);
      seen.push(...answer.events.map((e) => e.seq));
      cursor = answer.cursor;
    }
    return seen;
  };
  const both = Promise.all([follow(), follow()]);
  for (let i = 1; i <= 5; i += 1) {
    await settle();
    log.append('key.changed', key(i));
  }
  assert.deepEqual(await both, [[1, 2, 3, 4, 5], [1, 2, 3, 4, 5]]);
});

test('KBOX-31 a poll interrupted by a stop rejects with unavailable, not an empty batch, and leaves no timer', async (t) => {
  const { poller, clock } = await world(t);
  const stop = new AbortController();
  const waiting = poller.wait(0, stop.signal);
  stop.abort();
  await assert.rejects(waiting, (error: unknown) => error instanceof ApiError && error.code === 'unavailable');
  assert.equal(clock.pendingTimers, 0);
  const already = new AbortController();
  already.abort();
  await assert.rejects(poller.wait(0, already.signal), (error: unknown) => error instanceof ApiError && error.code === 'unavailable');
  assert.equal(clock.pendingTimers, 0);
});

test('KBOX-31 an event outside the closed list, or with data outside its shape, cannot be written and wakes no poller', async (t) => {
  const { log, poller } = await world(t);
  const loose = log.append as (kind: string, data: unknown) => number;
  const waiting = track(poller.wait(0, new AbortController().signal));
  const refusals: [string, unknown][] = [
    ['key.stolen', { keyref: 'a' }],
    ['', {}],
    ['key.changed', {}],
    ['key.changed', { keyref: 'a', extra: 'x' }],
    ['key.changed', { keyref: 7 }],
    ['key.changed', { keyref: 'has space' }],
    ['key.changed', null],
    ['rotation.failed', { run_id: 'r', keyref: 'k', step: 's', reason_code: 'c', old_key_works: false }],
    ['box.notice', { code: 'idle_near', text: 'any other sentence' }],
    ['approval.decided', { approval_id: 'a', decision: 'maybe' }],
    ['share.version', { version: -1 }],
    ['share.version', { version: 1.5 }],
  ];
  for (const [kind, data] of refusals) assert.throws(() => loose.call(log, kind, data), WriteRefused, kind);
  await settle();
  assert.equal(waiting.settled(), false);
  assert.equal(log.head(), 0);
});

test('KBOX-31 every kind of the spec table is writable with exactly its members', async (t) => {
  const { log } = await world(t);
  const samples = {
    'approval.opened': { approval_id: 'ap_1', approval_kind: 'key_rotate', title: 'Rotate the admin key of Vercel', slot: 'admin-1', revision: 1 },
    'approval.decided': { approval_id: 'ap_1', decision: 'approved' },
    'approval.executed': { approval_id: 'ap_1', result: 'done', reason_code: 'none' },
    'key.changed': { keyref: 'openai/master' },
    'rotation.state': { run_id: 'run_1', keyref: 'openai/master', state: 'switching', step: 'push' },
    'rotation.failed': { run_id: 'run_1', keyref: 'openai/master', step: 'verify', reason_code: 'verify_failed', old_key_works: true },
    'rotation.old_key_still_on': { run_id: 'run_1', keyref: 'openai/master', gen: 2 },
    'delivery.ready': { delivery_id: 'd_1', keyref: 'openai/ordinary', project: 'shop', name: 'OPENAI_API_KEY', gen: 3 },
    'share.version': { version: 9 },
    'machine.changed': { label: 'laptop-1', change: 'revoked' },
    'token.new_network': { label: 'laptop-1', network: '203.0.113.0/24' },
    'update.state': { approval_id: 'ap_2', state: 'rolled_back' },
    'box.notice': { code: 'credential_withheld', text: 'credential withheld' },
  } as const;
  assert.deepEqual(Object.keys(samples).sort(), [...EVENT_KINDS].sort());
  const loose = log.append as (kind: string, data: unknown) => number;
  for (const [kind, data] of Object.entries(samples)) {
    const expected = log.head() + 1;
    assert.equal(loose.call(log, kind, data), expected, kind);
    const members = Object.keys(EVENT_SCHEMAS[kind as keyof typeof EVENT_SCHEMAS]).sort();
    assert.deepEqual(Object.keys(data).sort(), members, kind);
  }
  const written: readonly EventRow[] = log.after(0);
  assert.deepEqual(written.map((e) => [e.kind, e.data]), Object.entries(samples));
});

test('KBOX-2 property: random byte strings offered as any text member of any event are refused and are nowhere in the database', async (t) => {
  const { log, path } = await world(t);
  const loose = log.append as (kind: string, data: unknown) => number;
  const c = canary();
  checkProperty(seed, 100, (rng) => {
    const text = Buffer.from(rng.bytes(24 + rng.int(40))).toString('latin1');
    for (const [kind, schema] of Object.entries(EVENT_SCHEMAS)) {
      for (const [member, field] of Object.entries(schema)) {
        if (field.kind !== 'text') continue;
        const good: Record<string, unknown> = {};
        for (const [name, f] of Object.entries(schema)) good[name] = f.kind === 'text' ? 'name' : f.kind === 'int' ? 1 : f.kind === 'true' ? true : (f.values[0] ?? '');
        good[member] = text;
        assert.throws(() => loose.call(log, kind, good), WriteRefused, `${kind}.${member}`);
      }
    }
  });
  assert.throws(() => loose.call(log, 'key.changed', { keyref: Buffer.from(c.bytes).toString('latin1') }), WriteRefused);
  assert.equal(log.head(), 0);
  c.assertAbsent({ database: readFileSync(path), wal: readFileSync(`${path}-wal`) });
});
