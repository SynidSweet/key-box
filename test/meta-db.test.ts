// KBOX-5: the metadata database never holds a value, by construction; private.db is a separate file behind a separate port.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { openMetaDatabase } from '../src/shell/db.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';
import { canary, seedFor, seededRandom, tempDir } from './kit/index.ts';

const seed = seedFor(process.env);

interface Column {
  readonly table: string;
  readonly column: string;
  readonly type: string;
}

function columnsOf(db: DatabaseSync): Column[] {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[];
  return tables.flatMap(({ name }) =>
    (db.prepare(`PRAGMA table_info(${JSON.stringify(name)})`).all() as { name: string; type: string }[]).map((c) => ({ table: name, column: c.name, type: c.type })),
  );
}

/** A column is a value store when it is named as one (`token` only counts without `_sha256`) or typed to hold raw bytes. */
export function valueStoreColumns(columns: readonly Column[]): string[] {
  const named = (c: Column): boolean => {
    const name = c.column.toLowerCase();
    return /value|secret/.test(name) || (/token/.test(name) && !/_sha256$/.test(name));
  };
  return columns.filter((c) => named(c) || /blob/i.test(c.type)).map((c) => `${c.table}.${c.column}`);
}

test('KBOX-5 no column of meta.db is named or typed as a value store, and the check names a planted one', async (t) => {
  const dir = await tempDir(t);
  const db = openMetaDatabase(join(dir, 'meta.db'), seededRandom(seed));
  t.after(() => db.close());
  const columns = columnsOf(db);
  assert.ok(columns.length > 30, `the check must see the real schema, saw ${columns.length} columns`);
  assert.ok(columns.some((c) => c.table === 'machines' && c.column === 'token_sha256'), 'token hashes are kept, under a _sha256 name');
  assert.deepEqual(valueStoreColumns(columns), []);

  const planted = new DatabaseSync(':memory:');
  t.after(() => planted.close());
  planted.exec('CREATE TABLE a(token TEXT, api_secret TEXT, key_value TEXT, token_sha256 TEXT, raw BLOB, fine TEXT)');
  assert.deepEqual(valueStoreColumns(columnsOf(planted)), ['a.token', 'a.api_secret', 'a.key_value', 'a.raw']);
});

test('KBOX-5 meta.db is in WAL mode with foreign keys on, and every table of the spec is there', async (t) => {
  const dir = await tempDir(t);
  const db = openMetaDatabase(join(dir, 'meta.db'), seededRandom(seed));
  t.after(() => db.close());
  assert.equal((db.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode, 'wal');
  assert.equal((db.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }).foreign_keys, 1);
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as { name: string }[]).map((r) => r.name).sort();
  assert.deepEqual(tables, ['allow_rules', 'approvals', 'audit', 'box_info', 'destinations', 'events', 'grants', 'keys', 'machines']);
});

test('KBOX-30 the epoch is 8 random hex characters chosen when meta.db is created and kept when it is opened again', async (t) => {
  const dir = await tempDir(t);
  const epochOf = (db: DatabaseSync): string => (db.prepare('SELECT epoch FROM box_info').get() as { epoch: string }).epoch;
  const first = openMetaDatabase(join(dir, 'a.db'), seededRandom(seed));
  const epoch = epochOf(first);
  first.close();
  assert.match(epoch, /^[0-9a-f]{8}$/);
  const again = openMetaDatabase(join(dir, 'a.db'), seededRandom(seed + 1));
  t.after(() => again.close());
  assert.equal(epochOf(again), epoch);
  const other = openMetaDatabase(join(dir, 'b.db'), seededRandom(seed + 1));
  t.after(() => other.close());
  assert.notEqual(epochOf(other), epoch);
});

test('KBOX-5 private.db is its own file and its rows never reach meta.db', async (t) => {
  const dir = await tempDir(t);
  const c = canary();
  const meta = openMetaDatabase(join(dir, 'meta.db'), seededRandom(seed));
  const priv = openPrivateDatabase(join(dir, 'private.db'));
  t.after(() => {
    meta.close();
    priv.close();
  });
  priv.addPushSubscription({ endpoint: `https://push.example/${Buffer.from(c.bytes).toString('base64url')}`, p256dh: 'p', auth: 'a' });
  priv.addApprover({ approverId: 'owner-1', credentialId: Buffer.from(c.bytes).toString('base64url'), publicKey: 'cose' });
  const files = readdirSync(dir);
  assert.ok(files.includes('private.db') && files.includes('meta.db'));
  for (const file of files.filter((f) => f.startsWith('meta.db'))) c.assertAbsent({ [file]: readFileSync(join(dir, file)) });
  const reader = new DatabaseSync(join(dir, 'private.db'));
  t.after(() => reader.close());
  assert.equal((reader.prepare('SELECT count(*) AS n FROM push_subscriptions').get() as { n: number }).n, 1, 'the rows really are in private.db');
});

test('KBOX-5 no code outside private-db.ts and main-core.ts opens private.db or imports its adapter', () => {
  const root = new URL('../src/', import.meta.url).pathname;
  const files = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
  const naming = files(root)
    .filter((f) => /private[.-]db/.test(readFileSync(f, 'utf8')))
    .map((f) => relative(root, f))
    .sort();
  assert.deepEqual(naming, ['main-core.ts', 'shell/private-db.ts']);
});
