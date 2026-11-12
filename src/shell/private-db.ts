// KBOX-5: private.db holds Web Push subscriptions and approver credentials. Only core's main opens it, and no export
// route can: this adapter is the one place that names the file.
import { DatabaseSync } from 'node:sqlite';
import { BUSY_TIMEOUT_MS, noJournal } from './db.ts';
import { PRIVATE_MIGRATIONS, migrate } from './migrations.ts';
import type { ApproverRecord, ApproverRow, PrivateStore, PushSubscriptionRow, VapidKeyPairRow } from '../ports/private.ts';

/** Every private.db table release 1 creates (version 0); the file's migrations run after it (KBOX-56). */
export const PRIVATE_SCHEMA_V0 = `
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    endpoint TEXT PRIMARY KEY,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    approver_id TEXT
  ) STRICT;
  CREATE TABLE IF NOT EXISTS approvers (
    approver_id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    device_public_key TEXT,
    phrase TEXT,
    sign_count INTEGER NOT NULL DEFAULT 0
  ) STRICT;
  CREATE TABLE IF NOT EXISTS vapid_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL
  ) STRICT;
`;

export function openPrivateDatabase(path: string, journal: (code: string) => void = noJournal): PrivateStore {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
  db.exec(PRIVATE_SCHEMA_V0);
  try {
    migrate(db, PRIVATE_MIGRATIONS, journal);
  } catch (error) {
    db.close();
    throw error;
  }
  // A private.db from before subscriptions belonged to approvers has no owner column: add it and delete the rows that had no owner
  // (no key box exists in the wild yet, so none of them is real; none would ever be forgotten with its approver).
  const columns = db.prepare('PRAGMA table_info(push_subscriptions)').all() as unknown as { name: string }[];
  if (!columns.some((c) => c.name === 'approver_id')) {
    db.exec('ALTER TABLE push_subscriptions ADD COLUMN approver_id TEXT');
    db.exec('DELETE FROM push_subscriptions WHERE approver_id IS NULL');
  }
  const putApprover =(r: ApproverRecord): void => {
    db.prepare('INSERT OR REPLACE INTO approvers (approver_id, credential_id, public_key, device_public_key, phrase, sign_count) VALUES (?, ?, ?, ?, ?, ?)').run(r.approverId, r.credentialId, r.coseKey, r.devicePublicKey, r.phrase, r.signCount);
  };
  const inTransaction = (work: () => void): void => {
    db.exec('BEGIN IMMEDIATE');
    try {
      work();
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  };
  return {
    addPushSubscription(row: PushSubscriptionRow, approverId?: string): void {
      db.prepare('INSERT OR REPLACE INTO push_subscriptions (endpoint, p256dh, auth, approver_id) VALUES (?, ?, ?, ?)').run(row.endpoint, row.p256dh, row.auth, approverId ?? null);
    },
    addApprover(row: ApproverRow): void {
      db.prepare('INSERT OR REPLACE INTO approvers (approver_id, credential_id, public_key) VALUES (?, ?, ?)').run(row.approverId, row.credentialId, row.publicKey);
    },
    // Web Push (KBOX-22) --------------------------------------------------------------------------------------------
    listPushSubscriptions(): readonly PushSubscriptionRow[] {
      return (db.prepare('SELECT endpoint, p256dh, auth FROM push_subscriptions ORDER BY rowid').all() as unknown as PushSubscriptionRow[]).map((r) => ({ endpoint: r.endpoint, p256dh: r.p256dh, auth: r.auth }));
    },
    removePushSubscription(endpoint: string): void {
      db.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').run(endpoint);
    },
    removePushSubscriptionsOf(approverId: string): void {
      db.prepare('DELETE FROM push_subscriptions WHERE approver_id = ?').run(approverId);
    },
    retainPushSubscriptionsOf(approverIds: readonly string[]): void {
      db.prepare(`DELETE FROM push_subscriptions WHERE approver_id IS NULL OR approver_id NOT IN (${approverIds.map(() => '?').join(', ')})`).run(...approverIds);
    },
    getVapidKeyPair():VapidKeyPairRow | undefined {
      const row = db.prepare('SELECT private_key, public_key FROM vapid_key WHERE id = 1').get() as { private_key: string; public_key: string } | undefined;
      return row === undefined ? undefined : { privateKey: row.private_key, publicKey: row.public_key };
    },
    putVapidKeyPair(row: VapidKeyPairRow): void {
      db.prepare('INSERT OR REPLACE INTO vapid_key (id, private_key, public_key) VALUES (1, ?, ?)').run(row.privateKey, row.publicKey);
    },
    // ---------------------------------------------------------------------------------------------------------------
    // Approvers (KBOX-9, KBOX-49, KBOX-20) ----------------------------------------------------------------------------
    listApprovers(): readonly ApproverRecord[] {
      const rows = db
        .prepare('SELECT approver_id, credential_id, public_key, device_public_key, phrase, sign_count FROM approvers WHERE device_public_key IS NOT NULL AND phrase IS NOT NULL ORDER BY approver_id')
        .all() as unknown as { approver_id: string; credential_id: string; public_key: string; device_public_key: string; phrase: string; sign_count: number }[];
      return rows.map((r) => ({ approverId: r.approver_id, credentialId: r.credential_id, coseKey: r.public_key, devicePublicKey: r.device_public_key, phrase: r.phrase, signCount: r.sign_count }));
    },
    putApprover,
    removeApprover(approverId: string): void {
      db.prepare('DELETE FROM approvers WHERE approver_id = ?').run(approverId);
    },
    replaceApprovers(records: readonly ApproverRecord[]): void {
      inTransaction(() => {
        db.exec('DELETE FROM approvers');
        for (const r of records) putApprover(r);
      });
    },
    setSignCount(approverId: string, signCount: number): void {
      db.prepare('UPDATE approvers SET sign_count = ? WHERE approver_id = ?').run(signCount, approverId);
    },
    close(): void {
      db.close();
    },
  };
}
