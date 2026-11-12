// KBOX-56: schema versions. A file written by release 1 (user_version 0, the table statements of tag v1 kept in test/fixtures/schema-v0.sql)
// migrates to the newest version without losing a row; a failing migration changes nothing and stops core; a newer file opens as is.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { META_SCHEMA_V0, openMetaDatabase } from '../src/shell/db.ts';
import { openCore } from '../src/shell/core.ts';
import { META_MIGRATIONS, PRIVATE_MIGRATIONS, migrate } from '../src/shell/migrations.ts';
import { PRIVATE_SCHEMA_V0, openPrivateDatabase } from '../src/shell/private-db.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import { TimedClock, seedFor, seededRandom, startCore, tempDir } from './kit/index.ts';

const seed = seedFor(process.env);
const NEWEST_META = META_MIGRATIONS.length;
const NEWEST_PRIVATE = PRIVATE_MIGRATIONS.length;

/** The release-1 statements by file section: `-- file: <name>` lines open a section. */
function fixtureSections(): Map<string, string> {
  const sections = new Map<string, string>();
  let name = '';
  for (const line of readFileSync(new URL('./fixtures/schema-v0.sql', import.meta.url), 'utf8').split('\n')) {
    const header = /^-- file: (.+)$/.exec(line);
    if (header?.[1] !== undefined) {
      name = header[1];
      sections.set(name, '');
    } else if (name !== '') sections.set(name, `${sections.get(name) ?? ''}${line}\n`);
  }
  return sections;
}
const section = (name: string): string => {
  const text = fixtureSections().get(name);
  assert.ok(text !== undefined, `fixture section ${name}`);
  return text;
};
const squash = (sql: string): string => sql.replace(/\s+/g, ' ').trim();
const META_FIXTURE = (): string => ['meta.db kernel', 'meta.db rotation', 'meta.db paste'].map(section).join('\n');

const versionOf = (db: DatabaseSync): number => (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
const tablesOf = (db: DatabaseSync): string[] => (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[]).map((r) => r.name);
const columnsOf = (db: DatabaseSync, table: string): string[] => (db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name);
const dumpOf = (db: DatabaseSync, table: string): unknown[] => db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();

/** A file as release 1 wrote it: the given statements, user_version 0. */
function writeV0(path: string, sql: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec(sql);
  assert.equal(versionOf(db), 0);
  return db;
}

const META_ROWS = `
  INSERT INTO keys (keyref, platform, name, projects_json, class, status, gen_current, rotate_every_days, grace_hours) VALUES ('k1', 'vercel', 'deploy key', '["p1"]', 'ordinary', 'works', 3, 30, 24);
  INSERT INTO box_info (id, release, share_version, epoch) VALUES (1, 'v1', 0, 'abc12345');
  INSERT INTO rotation_keys (keyref, scope_json, region, project, rotated_at, mark_admin) VALUES ('k1', '["a"]', NULL, 'p1', 111, 1);
  INSERT INTO paste_tasks (paste_id, slot, action_json, digest_hex, revision, requester, opened_at, expires_at) VALUES ('t1', 's', '{}', 'ff', 1, 'box', 5, 6);
`;
const PRIVATE_ROWS = `
  INSERT INTO push_subscriptions (endpoint, p256dh, auth, approver_id) VALUES ('https://push/e', 'k', 'a', 'ap1');
  INSERT INTO approvers (approver_id, credential_id, public_key, device_public_key, phrase, sign_count) VALUES ('ap1', 'c', 'pk', 'dpk', 'ph', 4);
  INSERT INTO vapid_key (id, private_key, public_key) VALUES (1, 'priv', 'pub');
`;
const META_TABLES = ['keys', 'box_info', 'rotation_keys', 'paste_tasks'];

test('KBOX-56 a meta.db written by release 1 migrates to the newest version with every row kept and verify_hint empty', async (t) => {
  const path = join(await tempDir(t), 'meta.db');
  const old = writeV0(path, META_FIXTURE() + META_ROWS);
  const before = META_TABLES.map((table) => dumpOf(old, table));
  old.close();
  const db = openMetaDatabase(path, seededRandom(seed), () => undefined);
  t.after(() => db.close());
  assert.equal(versionOf(db), NEWEST_META);
  assert.ok(NEWEST_META >= 1);
  const after = META_TABLES.map((table) => dumpOf(db, table).map((row) => (table === 'rotation_keys' ? Object.fromEntries(Object.entries(row as object).filter(([k]) => k !== 'verify_hint')) : row)));
  assert.deepEqual(after, before);
  assert.deepEqual(db.prepare('SELECT verify_hint FROM rotation_keys').all(), [{ verify_hint: null }]);
});

test('KBOX-56 a private.db written by release 1 migrates to the newest version with every row kept', async (t) => {
  const path = join(await tempDir(t), 'private.db');
  const old = writeV0(path, section('private.db') + PRIVATE_ROWS);
  const tables = ['push_subscriptions', 'approvers', 'vapid_key'];
  const before = tables.map((table) => dumpOf(old, table));
  old.close();
  openPrivateDatabase(path, () => undefined).close();
  const db = new DatabaseSync(path);
  t.after(() => db.close());
  assert.equal(versionOf(db), NEWEST_PRIVATE);
  assert.deepEqual(tables.map((table) => dumpOf(db, table)), before);
});

test('KBOX-56 a version-0 meta.db with only the kernel tables (a box without a domain) gets the rotation and paste tables and reaches the newest version', async (t) => {
  const path = join(await tempDir(t), 'meta.db');
  writeV0(path, section('meta.db kernel')).close();
  const db = openMetaDatabase(path, seededRandom(seed), () => undefined);
  t.after(() => db.close());
  assert.equal(versionOf(db), NEWEST_META);
  const tables = tablesOf(db);
  for (const name of ['rotation_keys', 'rotation_runs', 'rotation_gens', 'rotation_receipts', 'orphan_notices', 'deliveries', 'paste_tasks']) assert.ok(tables.includes(name), name);
  assert.ok(columnsOf(db, 'rotation_keys').includes('verify_hint'));
});

test('KBOX-56 a new empty meta.db and private.db reach the newest version', async (t) => {
  const dir = await tempDir(t);
  const meta = openMetaDatabase(join(dir, 'meta.db'), seededRandom(seed), () => undefined);
  t.after(() => meta.close());
  assert.equal(versionOf(meta), NEWEST_META);
  openPrivateDatabase(join(dir, 'private.db'), () => undefined).close();
  const priv = new DatabaseSync(join(dir, 'private.db'));
  t.after(() => priv.close());
  assert.equal(versionOf(priv), NEWEST_PRIVATE);
});

test('KBOX-56 openCore alone on a new directory has rotation_keys.verify_hint', async (t) => {
  const dir = await tempDir(t);
  const clock = new TimedClock(1000);
  const parts = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random: seededRandom(seed) });
  t.after(() => parts.close());
  assert.ok(columnsOf(parts.db, 'rotation_keys').includes('verify_hint'));
});

test('KBOX-56 core started on a version-0 file written without a domain starts and serves GET /api/meta', async (t) => {
  const stateDir = join(await tempDir(t), 'state');
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeV0(join(stateDir, 'meta.db'), section('meta.db kernel')).close();
  const box = await startCore(t, { stateDir });
  const reply = await box.call('/api/meta', { token: box.enrol('laptop', 'control') });
  assert.equal(reply.status, 200);
  assert.equal(versionOf(box.db), NEWEST_META);
});

test('KBOX-56 opening a file twice runs each migration once', async (t) => {
  const db = new DatabaseSync(join(await tempDir(t), 'x.db'));
  t.after(() => db.close());
  db.exec('CREATE TABLE ran (n INTEGER)');
  const migrations = [['INSERT INTO ran VALUES (1)'], ['INSERT INTO ran VALUES (2)', 'ALTER TABLE ran ADD COLUMN extra TEXT']];
  migrate(db, migrations, () => undefined);
  migrate(db, migrations, () => undefined);
  assert.deepEqual(db.prepare('SELECT n FROM ran ORDER BY n').all(), [{ n: 1 }, { n: 2 }]);
  assert.equal(versionOf(db), 2);
  const path = join(await tempDir(t), 'meta.db');
  openMetaDatabase(path, seededRandom(seed), () => undefined).close();
  openMetaDatabase(path, seededRandom(seed), () => undefined).close();
});

test('KBOX-56 a migration that throws leaves user_version and the tables as they were, journals schema_migration_failed and throws', async (t) => {
  const db = new DatabaseSync(join(await tempDir(t), 'x.db'));
  t.after(() => db.close());
  db.exec('CREATE TABLE base (a TEXT)');
  const journal: string[] = [];
  const migrations = [['ALTER TABLE base ADD COLUMN b TEXT'], ['CREATE TABLE half (x TEXT)', 'INSERT INTO base (nope) VALUES (1)']];
  assert.throws(() => migrate(db, migrations, (code) => void journal.push(code)), /schema_migration_failed/);
  assert.equal(versionOf(db), 1, 'the first migration stays done, the failing one is not');
  assert.deepEqual(tablesOf(db), ['base']);
  assert.deepEqual(columnsOf(db, 'base'), ['a', 'b']);
  assert.deepEqual(journal, ['schema_migration_failed']);
});

test('KBOX-56 core does not start on a file whose migration cannot apply, and the file is left at its old version', async (t) => {
  const stateDir = join(await tempDir(t), 'state');
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const path = join(stateDir, 'meta.db');
  // A version-0 file that already holds the column migration 1 adds: the migration cannot apply.
  writeV0(path, `${META_FIXTURE()} ALTER TABLE rotation_keys ADD COLUMN verify_hint TEXT;`).close();
  const clock = new TimedClock(1000);
  const journal: string[] = [];
  assert.throws(() => openCore({ stateDir, clock, scheduler: clock, random: seededRandom(seed), journal: (code) => void journal.push(code) }), /schema_migration_failed/);
  const after = new DatabaseSync(path);
  t.after(() => after.close());
  assert.equal(versionOf(after), 0);
  assert.deepEqual(journal, ['schema_migration_failed']);
});

test('KBOX-56 a file at a version above the newest opens as is, serves GET /api/meta and logs schema_newer once', async (t) => {
  const stateDir = join(await tempDir(t), 'state');
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const path = join(stateDir, 'meta.db');
  const newer = writeV0(path, META_FIXTURE() + META_ROWS);
  newer.exec(`ALTER TABLE keys ADD COLUMN from_the_future TEXT; PRAGMA user_version = ${NEWEST_META + 3}`);
  newer.close();
  const journal: string[] = [];
  openMetaDatabase(path, seededRandom(seed), (code) => void journal.push(code)).close();
  assert.deepEqual(journal, ['schema_newer']);
  const box = await startCore(t, { stateDir });
  const reply = await box.call('/api/meta', { token: box.enrol('laptop', 'control') });
  assert.equal(reply.status, 200);
  assert.equal(versionOf(box.db), NEWEST_META + 3);
  assert.ok(columnsOf(box.db, 'keys').includes('from_the_future'));
});

test('KBOX-56 a private.db above the newest version opens as is and logs schema_newer', async (t) => {
  const path = join(await tempDir(t), 'private.db');
  const newer = writeV0(path, section('private.db') + PRIVATE_ROWS);
  newer.exec(`PRAGMA user_version = ${NEWEST_PRIVATE + 2}`);
  newer.close();
  const journal: string[] = [];
  openPrivateDatabase(path, (code) => void journal.push(code)).close();
  assert.deepEqual(journal, ['schema_newer']);
});

test('KBOX-56 the code version-0 statements equal release 1 (whitespace aside), so a column added by editing a CREATE fails', () => {
  assert.equal(squash(META_SCHEMA_V0), squash(META_FIXTURE()));
  assert.equal(squash(PRIVATE_SCHEMA_V0), squash(section('private.db')));
});

test('KBOX-56 the rotation store keeps a key verify_hint: empty until set, kept by putKeyInfo, changed by setVerifyHint', async (t) => {
  const dir = await tempDir(t);
  const clock = new TimedClock(1000);
  const parts = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random: seededRandom(seed) });
  t.after(() => parts.close());
  parts.db.exec(META_ROWS.split('\n').filter((l) => l.includes('INTO keys')).join('\n'));
  const store = createRotationStore(parts.db, clock, parts.hub);
  store.putKeyInfo('k1', { scopeItems: [], location: {}, rotatedAt: 1, markAdmin: false });
  assert.equal(store.keyInfo('k1')?.verifyHint, undefined);
  store.setVerifyHint('k1', 'list_projects');
  assert.equal(store.keyInfo('k1')?.verifyHint, 'list_projects');
  store.putKeyInfo('k1', { scopeItems: [], location: {}, rotatedAt: 2, markAdmin: false });
  assert.equal(store.keyInfo('k1')?.verifyHint, 'list_projects', 'a re-put of the key info does not clear the hint');
  store.setVerifyHint('k1', 'list_teams');
  assert.equal(store.keyInfo('k1')?.verifyHint, 'list_teams');
});
