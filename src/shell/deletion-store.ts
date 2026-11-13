// KBOX-62: the deletion ledger (`key_deletions`, meta.db migration 3) and every write a deletion makes to the key's rows. The ledger outlives
// the erase: it links the approval to its run, holds the run's durable flags (notified, the first dead verdict, the confirmation) and records
// that a keyref was deleted, when and by which approval. Names, ids and times only: no column here can hold a value or a digest.
import type { DatabaseSync } from 'node:sqlite';
import type { Clock } from '../ports/clock.ts';
import type { EventSignal } from '../ports/events.ts';
import { ApiError } from '../pure/errors.ts';
import { inTransaction } from './db.ts';
import { insertEvent } from './events.ts';

export type LedgerOutcome = 'erased' | 'abandoned';

export interface Ledger {
  readonly approvalId: string;
  readonly keyref: string;
  readonly platform: string;
  readonly runId: string;
  readonly openedAt: number;
  readonly notified: boolean;
  /** The first "every generation of the batch is dead" verdict; the second comes no sooner than a minute after it. */
  readonly deadSeenAt: number | null;
  /** Every live generation was proven dead twice: what is left is the erase. */
  readonly confirmedAt: number | null;
  /** Null while the deletion is open. */
  readonly outcome: LedgerOutcome | null;
}

/** The tables that keep naming a key after its erase: the ledger (by text, no REFERENCES). */
export const KEPT_TABLES = ['key_deletions'] as const;
/** The tables the erase deletes the key's rows from, in this order (receipts before their runs, `keys` last). */
export const ERASED_TABLES = ['rotation_receipts', 'rotation_runs', 'rotation_gens', 'rotation_keys', 'deliveries', 'destinations', 'grants', 'allow_rules', 'keys'] as const;

interface LedgerStored {
  readonly approval_id: string;
  readonly keyref: string;
  readonly platform: string;
  readonly run_id: string;
  readonly opened_at: number;
  readonly notified: number;
  readonly dead_seen_at: number | null;
  readonly confirmed_at: number | null;
  readonly outcome: LedgerOutcome | null;
}

const toLedger = (r: LedgerStored): Ledger => ({
  approvalId: r.approval_id,
  keyref: r.keyref,
  platform: r.platform,
  runId: r.run_id,
  openedAt: r.opened_at,
  notified: r.notified === 1,
  deadSeenAt: r.dead_seen_at,
  confirmedAt: r.confirmed_at,
  outcome: r.outcome,
});

/**
 * Whether meta.db has the ledger. KBOX-56: a file above the newest version opens as is and is served; one written without migration 3's
 * table (no release made such a file, migrations being additive) has recorded no deletion, so the reads below find none there.
 */
const hasLedger = (db: DatabaseSync): boolean => db.prepare("SELECT 1 AS one FROM sqlite_master WHERE type = 'table' AND name = 'key_deletions'").get() !== undefined;

/** The keyrefs with an open deletion, read straight from meta.db: what the platform source, the lend handler and `putKey` refuse. */
export function deletingKeyrefs(db: DatabaseSync): ReadonlySet<string> {
  if (!hasLedger(db)) return new Set();
  return new Set((db.prepare('SELECT keyref FROM key_deletions WHERE outcome IS NULL').all() as unknown as { keyref: string }[]).map((r) => r.keyref));
}

/** Whether the key has an open deletion (one read). */
export function isDeleting(db: DatabaseSync, keyref: string): boolean {
  if (!hasLedger(db)) return false;
  return db.prepare('SELECT 1 AS one FROM key_deletions WHERE keyref = ? AND outcome IS NULL').get(keyref) !== undefined;
}

export interface OpenDeletion {
  readonly approvalId: string;
  readonly keyref: string;
  readonly platform: string;
  readonly runId: string;
  /** The key's current generation (the run's `gen_new`). */
  readonly gen: number;
  readonly intentName: string;
  /** An unleased `grace` or `revoking` run of the key the deletion supersedes; it must still be active, or nothing is written (`conflict`). */
  readonly supersede?: string;
}

export interface DeletionStore {
  /**
   * One transaction: the superseded run abandoned, the deletion's run (origin `delete`, state `revoking`, `gen_old` 0) and its ledger row
   * inserted, the key's grants and deliveries deleted, `rotation.state` and `key.changed` written. A second active run is `conflict`
   * (`run_exists`); a superseded run no longer active is `conflict` (`run_open`).
   */
  open(input: OpenDeletion): void;
  ofRun(runId: string): Ledger | undefined;
  ofApproval(approvalId: string): Ledger | undefined;
  /** Whether the key has an open deletion. */
  isOpen(keyref: string): boolean;
  /** Every ledger with no outcome yet. */
  openLedgers(): readonly Ledger[];
  /** Deletes the key's grants and deliveries; writes `key.changed` only when a row went. */
  stopUse(keyref: string): void;
  /** Sets `notified`; true only the first time (what the one notice and the one push hang on). */
  markNotified(runId: string): boolean;
  setDeadSeen(runId: string, at: number | null): void;
  /**
   * The second verdict proved the batch dead: in one transaction each of its generations is `retired`, the first verdict cleared and, when
   * `last` (no live generation is left), `confirmed_at` set.
   */
  retireBatch(keyref: string, runId: string, gens: readonly number[], last: boolean): void;
  /** Sets `confirmed_at` with no generation to retire (none was live). */
  confirm(runId: string): void;
  /**
   * The erase, in one transaction: every platform key id of the key into `orphan_notices`, then the key's rows of each `ERASED_TABLES` table,
   * the ledger `erased`, `key.changed`. Answers how many generation rows and destinations it erased.
   */
  erase(keyref: string, runId: string): { readonly gens: number; readonly destinations: number };
  /** Closes an open ledger with an outcome (start-up's repair); a closed one is left as it is. */
  close(approvalId: string, outcome: LedgerOutcome): void;
}

export function createDeletionStore(db: DatabaseSync, clock: Clock, hub: EventSignal): DeletionStore {
  const write = <T>(work: () => T): T => {
    const result = inTransaction(db, work);
    hub.notify();
    return result;
  };
  const keyChanged = (keyref: string): void => void insertEvent(db, clock.now(), 'key.changed', { keyref });
  const one = (sql: string, ...params: string[]): Ledger | undefined => {
    const r = db.prepare(sql).get(...params) as LedgerStored | undefined;
    return r === undefined ? undefined : toLedger(r);
  };
  const dropUse = (keyref: string): boolean => {
    const grants = db.prepare('DELETE FROM grants WHERE keyref = ?').run(keyref).changes;
    const deliveries = db.prepare('DELETE FROM deliveries WHERE keyref = ?').run(keyref).changes;
    return Number(grants) + Number(deliveries) > 0;
  };

  return {
    open(input) {
      write(() => {
        if (input.supersede !== undefined) {
          const superseded = db.prepare("UPDATE rotation_runs SET state = 'abandoned' WHERE run_id = ? AND state IN ('grace', 'revoking')").run(input.supersede).changes;
          if (Number(superseded) !== 1) throw new ApiError('conflict', 'run_open');
          insertEvent(db, clock.now(), 'rotation.state', { run_id: input.supersede, keyref: input.keyref, state: 'abandoned', step: 'abandoned' });
        }
        try {
          db.prepare("INSERT INTO rotation_runs (run_id, keyref, state, gen_old, gen_new, intent_name, origin, opened_at) VALUES (?, ?, 'revoking', 0, ?, ?, 'delete', ?)").run(
            input.runId,
            input.keyref,
            input.gen,
            input.intentName,
            clock.now(),
          );
        } catch (error) {
          if (error instanceof Error && /UNIQUE/i.test(error.message)) throw new ApiError('conflict', 'run_exists');
          throw error;
        }
        db.prepare('INSERT INTO key_deletions (approval_id, keyref, platform, run_id, opened_at) VALUES (?, ?, ?, ?, ?)').run(input.approvalId, input.keyref, input.platform, input.runId, clock.now());
        insertEvent(db, clock.now(), 'rotation.state', { run_id: input.runId, keyref: input.keyref, state: 'revoking', step: 'revoking' });
        dropUse(input.keyref);
        keyChanged(input.keyref);
      });
    },
    ofRun: (runId) => one('SELECT * FROM key_deletions WHERE run_id = ?', runId),
    ofApproval: (approvalId) => one('SELECT * FROM key_deletions WHERE approval_id = ?', approvalId),
    isOpen: (keyref) => isDeleting(db, keyref),
    openLedgers: () => (db.prepare('SELECT * FROM key_deletions WHERE outcome IS NULL ORDER BY opened_at, approval_id').all() as unknown as LedgerStored[]).map(toLedger),
    stopUse(keyref) {
      write(() => {
        if (dropUse(keyref)) keyChanged(keyref);
      });
    },
    markNotified: (runId) => write(() => Number(db.prepare('UPDATE key_deletions SET notified = 1 WHERE run_id = ? AND notified = 0').run(runId).changes) === 1),
    setDeadSeen(runId, at) {
      write(() => void db.prepare('UPDATE key_deletions SET dead_seen_at = ? WHERE run_id = ?').run(at, runId));
    },
    retireBatch(keyref, runId, gens, last) {
      write(() => {
        for (const gen of gens) db.prepare("UPDATE rotation_gens SET status = 'retired' WHERE keyref = ? AND gen = ?").run(keyref, gen);
        db.prepare('UPDATE key_deletions SET dead_seen_at = NULL, confirmed_at = CASE WHEN ? THEN ? ELSE confirmed_at END WHERE run_id = ?').run(last ? 1 : 0, clock.now(), runId);
        keyChanged(keyref);
      });
    },
    confirm(runId) {
      write(() => void db.prepare('UPDATE key_deletions SET dead_seen_at = NULL, confirmed_at = ? WHERE run_id = ?').run(clock.now(), runId));
    },
    erase(keyref, runId) {
      return write(() => {
        const ids = db.prepare('SELECT platform_key_id FROM rotation_gens WHERE keyref = ? AND platform_key_id IS NOT NULL').all(keyref) as unknown as { platform_key_id: string }[];
        for (const { platform_key_id } of ids) db.prepare('INSERT OR IGNORE INTO orphan_notices (platform_key_id) VALUES (?)').run(platform_key_id);
        const count = (table: string): number => (db.prepare(`SELECT count(*) AS n FROM ${table} WHERE keyref = ?`).get(keyref) as { n: number }).n;
        const erased = { gens: count('rotation_gens'), destinations: count('destinations') };
        for (const table of ERASED_TABLES) {
          if (table === 'rotation_receipts') db.prepare('DELETE FROM rotation_receipts WHERE run_id IN (SELECT run_id FROM rotation_runs WHERE keyref = ?)').run(keyref);
          else db.prepare(`DELETE FROM ${table} WHERE keyref = ?`).run(keyref);
        }
        db.prepare("UPDATE key_deletions SET outcome = 'erased', ended_at = ? WHERE run_id = ?").run(clock.now(), runId);
        keyChanged(keyref);
        return erased;
      });
    },
    close(approvalId, outcome) {
      write(() => void db.prepare('UPDATE key_deletions SET outcome = ?, ended_at = ? WHERE approval_id = ? AND outcome IS NULL').run(outcome, clock.now(), approvalId));
    },
  };
}
