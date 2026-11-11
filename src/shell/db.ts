// KBOX-5, KBOX-30: meta.db, the metadata database. Values live only under the vault directory; no column here can hold one.
// This file is the one home of the schema.
import { DatabaseSync } from 'node:sqlite';
import type { Random } from '../ports/random.ts';

const KEY_CLASSES = "('ordinary', 'admin', 'master')";
const KEY_STATUSES = "('works', 'rotating', 'awaiting_approval', 'awaiting_paste', 'failed')";
const COVERAGES = "('windowed', 'anchored', 'none')";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS keys (
    keyref TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    name TEXT NOT NULL,
    projects_json TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ${KEY_CLASSES}),
    status TEXT NOT NULL CHECK (status IN ${KEY_STATUSES}),
    gen_current INTEGER NOT NULL,
    rotate_every_days INTEGER NOT NULL,
    grace_hours INTEGER NOT NULL,
    next_due_at INTEGER,
    expires_at INTEGER,
    coverage TEXT CHECK (coverage IS NULL OR coverage IN ${COVERAGES}),
    last_use_at INTEGER
  ) STRICT;
  CREATE TABLE IF NOT EXISTS destinations (
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    readable_by TEXT NOT NULL CHECK (readable_by IN ('api', 'runtime')),
    PRIMARY KEY (keyref, kind, target)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS grants (
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    machine TEXT NOT NULL,
    PRIMARY KEY (keyref, machine)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS allow_rules (
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    rule_id TEXT NOT NULL,
    PRIMARY KEY (keyref, rule_id)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS machines (
    label TEXT PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('control', 'relay')),
    token_sha256 TEXT NOT NULL UNIQUE,
    enrolled_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    last_network TEXT
  ) STRICT;
  CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    slot TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    data_json TEXT NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    ref TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS box_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    release TEXT NOT NULL,
    share_version INTEGER NOT NULL,
    share_public_key_ed25519_b64 TEXT,
    oidc_issuer TEXT,
    epoch TEXT NOT NULL
  ) STRICT;
`;

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Opens (and on first use creates) meta.db. The epoch is drawn once, when the file is created, and kept after that. */
export function openMetaDatabase(path: string, random: Random): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(SCHEMA);
  db.prepare("INSERT OR IGNORE INTO box_info (id, release, share_version, epoch) VALUES (1, 'unreleased', 0, ?)").run(hex(random.bytes(4)));
  return db;
}

/** One write transaction: it takes the write lock at once, so two processes on the file queue behind each other. */
export function inTransaction<T>(db: DatabaseSync, work: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = work();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

/** One read transaction: everything read inside it comes from the same moment of the database. */
export function inReadTransaction<T>(db: DatabaseSync, work: () => T): T {
  db.exec('BEGIN');
  try {
    return work();
  } finally {
    db.exec('COMMIT');
  }
}
