// KBOX-50: the audit log is append-only and hash-chained, and never holds a value.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { auditContract } from './contracts/audit.contract.ts';
import { canary, checkProperty, seedFor, seededRandom, spawnNode, tempDir, tempDirSync } from './kit/index.ts';
import type { AuditLog } from '../src/ports/audit.ts';
import { createAuditLog } from '../src/shell/audit.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { WriteRefused } from '../src/pure/errors.ts';

const seed = seedFor(process.env);
const ZERO_HASH = '0'.repeat(64);

function open(dir: string): { db: DatabaseSync; log: AuditLog; path: string } {
  const path = join(dir, 'meta.db');
  const db = openMetaDatabase(path, seededRandom(seed));
  return { db, log: createAuditLog(db), path };
}

auditContract('sqlite chain', () => {
  const { log } = open(tempDirSync());
  return { audit: log, entries: () => log.read(0).entries.map((r) => ({ action: r.action, subject: r.ref, at: r.at })) };
});

const request = (at: number, actor = 'box') => ({ actor, action: 'api.request', subject: '/api/meta', at, detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200 } });

test('KBOX-50 the first row has 32 zero bytes as prev_hash and each hash is SHA-256(prev_hash bytes, canonical row without hash)', async (t) => {
  const { db, log } = open(await tempDir(t));
  t.after(() => db.close());
  log.append({ action: 'key.issued', subject: 'openai/master', at: 7 });
  log.append({ action: 'key.revoked', subject: 'openai/master', at: 8, actor: 'owner-1' });
  const [first, second] = log.read(0).entries;
  assert.ok(first !== undefined && second !== undefined);
  assert.equal(first.prev_hash, ZERO_HASH);
  const oracle = (text: string, prev: string): string => createHash('sha256').update(Buffer.from(prev, 'hex')).update(text, 'utf8').digest('hex');
  const firstText = `{"action":"key.issued","actor":"box","at":7,"detail":{},"prev_hash":"${ZERO_HASH}","ref":"openai/master","seq":1}`;
  assert.equal(first.hash, oracle(firstText, ZERO_HASH));
  assert.equal(second.prev_hash, first.hash);
  const secondText = `{"action":"key.revoked","actor":"owner-1","at":8,"detail":{},"prev_hash":"${first.hash}","ref":"openai/master","seq":2}`;
  assert.equal(second.hash, oracle(secondText, first.hash));
});

test('KBOX-50 after 1,000 appends the chain verifies; flipping one byte of a stored row makes verifyChain name the first bad seq', async (t) => {
  const { db, log, path } = open(await tempDir(t));
  t.after(() => db.close());
  for (let i = 0; i < 1000; i += 1) log.append(request(i));
  assert.deepEqual(log.verifyChain(), { ok: true, rows: 1000 });
  const attacker = new DatabaseSync(path);
  t.after(() => attacker.close());
  attacker.prepare("UPDATE audit SET actor = 'boy' WHERE seq = 640").run();
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 640 });
  attacker.prepare("UPDATE audit SET actor = 'box' WHERE seq = 640").run();
  assert.deepEqual(log.verifyChain(), { ok: true, rows: 1000 });
  attacker.prepare("UPDATE audit SET hash = '' || substr(hash, 1, 63) || CASE substr(hash, 64, 1) WHEN '0' THEN '1' ELSE '0' END WHERE seq = 3").run();
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 3 });
});

test('KBOX-50 a row rewritten together with its own hash is caught at the next row, whose prev_hash no longer matches', async (t) => {
  const { db, log, path } = open(await tempDir(t));
  t.after(() => db.close());
  for (let i = 0; i < 20; i += 1) log.append(request(i));
  const attacker = new DatabaseSync(path);
  t.after(() => attacker.close());
  const row = attacker.prepare('SELECT * FROM audit WHERE seq = 10').get() as { prev_hash: string };
  const text = `{"action":"api.request","actor":"box","at":999,"detail":{"method":"GET","request_id":"req_AAAAAAAAAAAA","status":200},"prev_hash":"${row.prev_hash}","ref":"/api/meta","seq":10}`;
  const hash = createHash('sha256').update(Buffer.from(row.prev_hash, 'hex')).update(text, 'utf8').digest('hex');
  attacker.prepare('UPDATE audit SET at = 999, hash = ? WHERE seq = 10').run(hash);
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 11 });
});

test('KBOX-50 a deleted row is detected, the first, a middle one and the later appends after a deleted last row', async (t) => {
  const { db, log, path } = open(await tempDir(t));
  t.after(() => db.close());
  for (let i = 0; i < 50; i += 1) log.append(request(i));
  const attacker = new DatabaseSync(path);
  t.after(() => attacker.close());
  attacker.prepare('DELETE FROM audit WHERE seq = 20').run();
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 21 });
  attacker.prepare('DELETE FROM audit WHERE seq = 1').run();
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 2 });
  attacker.prepare('DELETE FROM audit WHERE seq = 50').run();
  log.append(request(51));
  assert.deepEqual(log.verifyChain(), { ok: false, firstBadSeq: 2 });
  const last = log.read(48).entries;
  assert.deepEqual(last.map((r) => r.seq), [49, 51]);
});

test('KBOX-50 detail with an unknown member, a wrong type or an unregistered action is refused at the writer and nothing is stored', async (t) => {
  const { db, log } = open(await tempDir(t));
  t.after(() => db.close());
  log.append(request(1));
  const refused: unknown[] = [
    { ...request(2), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200, extra: 'x' } },
    { ...request(2), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: '200' } },
    { ...request(2), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET' } },
    { ...request(2), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200.5 } },
    { ...request(2), detail: { request_id: 'nope', method: 'GET', status: 200 } },
    { ...request(2), action: 'key.stolen' },
    { ...request(2), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200, cause: 'two words' } },
    { ...request(2), actor: 'has space' },
    { ...request(2), subject: '' },
    { ...request(2), subject: 'x'.repeat(300) },
    { ...request(2), at: 1.5 },
    { ...request(2), at: -1 },
  ];
  for (const event of refused) {
    assert.throws(() => log.append(event as Parameters<AuditLog['append']>[0]), WriteRefused);
  }
  assert.deepEqual(log.read(0).entries.map((r) => r.seq), [1]);
  assert.deepEqual(log.verifyChain(), { ok: true, rows: 1 });
});

test('KBOX-50 read returns rows after `since`, at most `limit`, and says when more remain', async (t) => {
  const { db, log } = open(await tempDir(t));
  t.after(() => db.close());
  for (let i = 0; i < 10; i += 1) log.append(request(i));
  const page = log.read(3, 4);
  assert.deepEqual(page.entries.map((r) => r.seq), [4, 5, 6, 7]);
  assert.equal(page.more, true);
  assert.deepEqual(log.read(6, 4).entries.map((r) => r.seq), [7, 8, 9, 10]);
  assert.equal(log.read(6, 4).more, false);
  assert.deepEqual(log.read(10).entries, []);
  assert.equal(log.read(10).more, false);
  assert.equal(log.read(0).entries.length, 10);
});

test('KBOX-50 two writer processes on one file get distinct sequence numbers and a valid chain', async (t) => {
  const dir = await tempDir(t);
  const { db, log, path } = open(dir);
  t.after(() => db.close());
  const writer = new URL('./kit/db-writer.ts', import.meta.url).pathname;
  const runs = await Promise.all([spawnNode([writer, 'audit', path, 'writer-a', '150'], dir), spawnNode([writer, 'audit', path, 'writer-b', '150'], dir)]);
  assert.deepEqual(runs.map((r) => r.status), [0, 0], runs.map((r) => r.stderr).join('\n'));
  const entries = log.read(0).entries;
  assert.deepEqual(entries.map((r) => r.seq), Array.from({ length: 300 }, (_, i) => i + 1));
  assert.equal(entries.filter((r) => r.actor === 'writer-a').length, 150);
  assert.equal(entries.filter((r) => r.actor === 'writer-b').length, 150);
  assert.deepEqual(log.verifyChain(), { ok: true, rows: 300 });
});

test('KBOX-2 property: random byte strings offered as actor, subject or detail text are refused and appear nowhere in the database', async (t) => {
  const dir = await tempDir(t);
  const { db, log, path } = open(dir);
  t.after(() => db.close());
  checkProperty(seed, 200, (rng) => {
    const text = Buffer.from(rng.bytes(24 + rng.int(40))).toString('latin1');
    for (const event of [
      { ...request(1), actor: text },
      { ...request(1), subject: text },
      { ...request(1), detail: { request_id: text, method: 'GET', status: 200 } },
      { ...request(1), detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200, source: text } },
      { ...request(1), action: text },
    ]) {
      assert.throws(() => log.append(event), WriteRefused);
    }
  });
  const c = canary();
  assert.throws(() => log.append({ ...request(1), actor: Buffer.from(c.bytes).toString('latin1') }), WriteRefused);
  assert.deepEqual(log.read(0).entries, []);
  assert.equal((db.prepare('SELECT count(*) AS n FROM audit').get() as { n: number }).n, 0);
  c.assertAbsent({ database: readFileSync(path), wal: readFileSync(`${path}-wal`) });
});
