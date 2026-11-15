// Pi move, sqlite-durable: every connection to meta.db and private.db commits with synchronous = FULL (2), so a power cut loses no commit.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { seedFor, seededRandom, tempDirSync } from './kit/index.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';

const seed = seedFor(process.env);

/** Opens a store while recording the connection it creates (synchronous is per connection, and private.db hides its handle). */
function connectionsOf(open: () => void): DatabaseSync[] {
  const seen = new Set<DatabaseSync>();
  const original = DatabaseSync.prototype.exec;
  DatabaseSync.prototype.exec = function (this: DatabaseSync, sql: string) {
    seen.add(this);
    return original.call(this, sql);
  };
  try {
    open();
  } finally {
    DatabaseSync.prototype.exec = original;
  }
  return [...seen];
}

function synchronousOf(db: DatabaseSync): number {
  return (db.prepare('PRAGMA synchronous').get() as { synchronous: number }).synchronous;
}

test('meta.db reads synchronous = FULL (2) after open', () => {
  const dir = tempDirSync();
  let value = -1;
  const dbs = connectionsOf(() => {
    const db = openMetaDatabase(join(dir, 'meta.db'), seededRandom(seed));
    value = synchronousOf(db);
    db.close();
  });
  assert.equal(dbs.length, 1);
  assert.equal(value, 2);
});

test('private.db reads synchronous = FULL (2) after open', () => {
  const dir = tempDirSync();
  let value = -1;
  const original = DatabaseSync.prototype.exec;
  let captured: DatabaseSync | undefined;
  DatabaseSync.prototype.exec = function (this: DatabaseSync, sql: string) {
    captured = this;
    return original.call(this, sql);
  };
  let store;
  try {
    store = openPrivateDatabase(join(dir, 'private.db'));
  } finally {
    DatabaseSync.prototype.exec = original;
  }
  assert.ok(captured);
  value = synchronousOf(captured);
  store.close();
  assert.equal(value, 2);
});
