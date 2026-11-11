// KBOX-5: private.db holds Web Push subscriptions and approver credentials. Only core's main opens it, and no export
// route can: this adapter is the one place that names the file.
import { DatabaseSync } from 'node:sqlite';
import type { ApproverRow, PrivateStore, PushSubscriptionRow } from '../ports/private.ts';

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
  return {
    addPushSubscription(row: PushSubscriptionRow): void {
      db.prepare('INSERT OR REPLACE INTO push_subscriptions (endpoint, p256dh, auth) VALUES (?, ?, ?)').run(row.endpoint, row.p256dh, row.auth);
    },
    addApprover(row: ApproverRow): void {
      db.prepare('INSERT OR REPLACE INTO approvers (approver_id, credential_id, public_key) VALUES (?, ?, ?)').run(row.approverId, row.credentialId, row.publicKey);
    },
    close(): void {
      db.close();
    },
  };
}
