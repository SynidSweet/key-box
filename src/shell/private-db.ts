// KBOX-5: private.db holds Web Push subscriptions and approver credentials. Only core's main opens it, and no export
// route can: this adapter is the one place that names the file.
import { DatabaseSync } from 'node:sqlite';
import type { ApproverRow, PrivateStore, PushSubscriptionRow, VapidKeyPairRow } from '../ports/private.ts';

export function openPrivateDatabase(path: string): PrivateStore {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      endpoint TEXT PRIMARY KEY,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS approvers (
      approver_id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL,
      public_key TEXT NOT NULL
    ) STRICT;
  `);
  // Web Push (KBOX-22): the one VAPID key pair of this box.
  db.exec(`
    CREATE TABLE IF NOT EXISTS vapid_key (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      private_key TEXT NOT NULL,
      public_key TEXT NOT NULL
    ) STRICT;
  `);
  return {
    addPushSubscription(row: PushSubscriptionRow): void {
      db.prepare('INSERT OR REPLACE INTO push_subscriptions (endpoint, p256dh, auth) VALUES (?, ?, ?)').run(row.endpoint, row.p256dh, row.auth);
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
    getVapidKeyPair(): VapidKeyPairRow | undefined {
      const row = db.prepare('SELECT private_key, public_key FROM vapid_key WHERE id = 1').get() as { private_key: string; public_key: string } | undefined;
      return row === undefined ? undefined : { privateKey: row.private_key, publicKey: row.public_key };
    },
    putVapidKeyPair(row: VapidKeyPairRow): void {
      db.prepare('INSERT OR REPLACE INTO vapid_key (id, private_key, public_key) VALUES (1, ?, ?)').run(row.privateKey, row.publicKey);
    },
    // ---------------------------------------------------------------------------------------------------------------
    close(): void {
      db.close();
    },
  };
}
