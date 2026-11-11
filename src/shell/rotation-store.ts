// KBOX-51, KBOX-34: the rotation state in meta.db: runs (one active per key, structurally), generations, destination receipts,
// deliveries and the orphan notices already sent. Names, ids and numbers only: no column here can hold a value. The tables are
// created beside the kernel's (`CREATE TABLE IF NOT EXISTS` on the same connection), so this unit adds no line to db.ts.
import type { DatabaseSync } from 'node:sqlite';
import type { Clock } from '../ports/clock.ts';
import type { EventSignal } from '../ports/events.ts';
import type { KeyClass, KeyLocation, PlatformKeyId } from '../ports/types.ts';
import { ApiError } from '../pure/errors.ts';
import { insertEvent } from './events.ts';
import { inTransaction } from './db.ts';
import type { MetaKey } from '../ports/meta.ts';
import type { Step } from '../pure/rotation-machine.ts';

export type RunState = Step | 'rolling_back' | 'done' | 'failed' | 'abandoned';
export type RunOrigin = 'schedule' | 'owner' | 'agent' | 'approval' | 'paste' | 'create' | 'reconcile';
export type GenStatus = 'pending' | 'current' | 'grace' | 'retired' | 'failed';

/** `rotation_receipts.pushed`: the intent is written (the push may or may not have applied), the push applied, or the destination refused it (applied nothing). */
const PUSH_MAYBE = 1;
const PUSH_DONE = 2;
const PUSH_REFUSED = 3;
const RUN_STATES ="('issuing','verifying','pushing','redeploying','checking','promoting','grace','revoking','rolling_back','done','failed','abandoned')";
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS rotation_keys (
    keyref TEXT PRIMARY KEY REFERENCES keys (keyref),
    scope_json TEXT NOT NULL,
    region TEXT,
    project TEXT,
    rotated_at INTEGER NOT NULL,
    mark_admin INTEGER NOT NULL DEFAULT 0 CHECK (mark_admin IN (0, 1))
  ) STRICT;
  CREATE TABLE IF NOT EXISTS rotation_runs (
    run_id TEXT PRIMARY KEY,
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    state TEXT NOT NULL CHECK (state IN ${RUN_STATES}),
    gen_old INTEGER NOT NULL,
    gen_new INTEGER NOT NULL,
    intent_name TEXT NOT NULL,
    origin TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    revoke_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    failed_step TEXT,
    reason_code TEXT,
    failed_notified INTEGER NOT NULL DEFAULT 0,
    still_on_notified INTEGER NOT NULL DEFAULT 0,
    failed_at INTEGER,
    CHECK (state <> 'failed' OR failed_at IS NOT NULL)
  ) STRICT;
  CREATE UNIQUE INDEX IF NOT EXISTS rotation_one_active_run_per_key ON rotation_runs (keyref) WHERE state NOT IN ('done', 'failed', 'abandoned');
  CREATE TABLE IF NOT EXISTS rotation_gens (
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    gen INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'current', 'grace', 'retired', 'failed')),
    platform_key_id TEXT,
    region TEXT,
    project TEXT,
    PRIMARY KEY (keyref, gen)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS rotation_receipts (
    run_id TEXT NOT NULL REFERENCES rotation_runs (run_id),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    version TEXT,
    pushed INTEGER NOT NULL CHECK (pushed IN (1, 2, 3)),
    -- 1 once a redeploy's intent is written, before the redeploy is called: the destination may run the new value from then on.
    redeployed INTEGER NOT NULL DEFAULT 0,
    rollback_notified INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, kind, target)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS orphan_notices (
    platform_key_id TEXT PRIMARY KEY
  ) STRICT;
  CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    gen INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    acked_at INTEGER,
    notified INTEGER NOT NULL DEFAULT 0
  ) STRICT;
`;

export interface RunRow {
  readonly runId: string;
  readonly keyref: string;
  readonly state: RunState;
  readonly genOld: number;
  readonly genNew: number;
  readonly intentName: string;
  readonly origin: RunOrigin;
  readonly openedAt: number;
  readonly revokeAt: number | null;
  readonly attempts: number;
  readonly failedStep: string | null;
  readonly reasonCode: string | null;
  readonly failedNotified: boolean;
  readonly stillOnNotified: boolean;
  /** When the fault happened (KBOX-52 counts the 24 hours from here); set on every failed run. */
  readonly failedAt: number | null;
}

export interface GenRow {
  readonly keyref: string;
  readonly gen: number;
  readonly status: GenStatus;
  readonly platformKeyId: PlatformKeyId | null;
  readonly location: KeyLocation;
}

export interface KeyInfo {
  readonly scopeItems: readonly string[];
  readonly location: KeyLocation;
  readonly rotatedAt: number;
  readonly markAdmin: boolean;
}

export interface KeyHead {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects: readonly string[];
  readonly class: KeyClass;
  readonly status: MetaKey['status'];
  readonly genCurrent: number;
  readonly rotateEveryDays: number;
  readonly graceHours: number;
  readonly expiresAt: number | null;
  readonly rotatedAt: number;
}

export interface DestinationRow {
  readonly kind: string;
  readonly target: string;
  readonly readable_by: 'api' | 'runtime';
}

interface HeadStored {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects_json: string;
  readonly class: KeyClass;
  readonly status: MetaKey['status'];
  readonly gen_current: number;
  readonly rotate_every_days: number;
  readonly grace_hours: number;
  readonly expires_at: number | null;
  readonly rotated_at: number | null;
}

const HEAD_SELECT =
  'SELECT k.keyref, k.platform, k.name, k.projects_json, k.class, k.status, k.gen_current, k.rotate_every_days, k.grace_hours, k.expires_at, r.rotated_at FROM keys k LEFT JOIN rotation_keys r ON r.keyref = k.keyref';

const toHead = (k: HeadStored): KeyHead => ({
  keyref: k.keyref,
  platform: k.platform,
  name: k.name,
  projects: JSON.parse(k.projects_json) as string[],
  class: k.class,
  status: k.status,
  genCurrent: k.gen_current,
  rotateEveryDays: k.rotate_every_days,
  graceHours: k.grace_hours,
  expiresAt: k.expires_at,
  rotatedAt: k.rotated_at ?? 0,
});

const pushedCode = (pushed: true | 'refused' | undefined): number | null => (pushed === true ? PUSH_DONE : pushed === 'refused' ? PUSH_REFUSED : null);
const pushedOf = (code: number): Receipt['pushed'] => (code === PUSH_DONE ? true : code === PUSH_REFUSED ? 'refused' : 'maybe');

export interface Receipt {
  readonly runId: string;
  readonly kind: string;
  readonly target: string;
  readonly version: string | null;
  /**
   * `maybe` from the intent written before the push until it answered, or when it never did; `true` when it applied; `refused` when the
   * destination answered that it applied nothing. A rollback undoes `maybe` and `true` and leaves `refused` alone: it holds nothing.
   */
  readonly pushed: 'maybe' | 'refused' | true;
  /**
   * The intent of a redeploy was written before it was called (review N1): a deploy may have started and may run the new value, whatever the
   * redeploy answered. A rollback redeploys the old value wherever this is set, and the new key is not revoked until that deploy is ready.
   */
  readonly redeployIntended: boolean;
  readonly rollbackNotified: boolean;
}

export interface DeliveryRow {
  readonly deliveryId: string;
  readonly keyref: string;
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly createdAt: number;
  readonly ackedAt: number | null;
  readonly notified: boolean;
}

export interface NewRun {
  readonly runId: string;
  readonly keyref: string;
  readonly state: RunState;
  readonly genOld: number;
  readonly genNew: number;
  readonly intentName: string;
  readonly origin: RunOrigin;
}

/** What may change on a run after it is opened. */
export interface RunPatch {
  readonly state?: RunState;
  readonly revokeAt?: number;
  readonly attempts?: number;
  readonly failedStep?: string;
  readonly reasonCode?: string;
  readonly failedNotified?: true;
  readonly stillOnNotified?: true;
  readonly failedAt?: number;
}

interface RunStored {
  readonly run_id: string;
  readonly keyref: string;
  readonly state: RunState;
  readonly gen_old: number;
  readonly gen_new: number;
  readonly intent_name: string;
  readonly origin: RunOrigin;
  readonly opened_at: number;
  readonly revoke_at: number | null;
  readonly attempts: number;
  readonly failed_step: string | null;
  readonly reason_code: string | null;
  readonly failed_notified: number;
  readonly still_on_notified: number;
  readonly failed_at: number | null;
}

const toRun = (r: RunStored): RunRow => ({
  runId: r.run_id,
  keyref: r.keyref,
  state: r.state,
  genOld: r.gen_old,
  genNew: r.gen_new,
  intentName: r.intent_name,
  origin: r.origin,
  openedAt: r.opened_at,
  revokeAt: r.revoke_at,
  attempts: r.attempts,
  failedStep: r.failed_step,
  reasonCode: r.reason_code,
  failedNotified: r.failed_notified === 1,
  stillOnNotified: r.still_on_notified === 1,
  failedAt: r.failed_at,
});

interface GenStored {
  readonly keyref: string;
  readonly gen: number;
  readonly status: GenStatus;
  readonly platform_key_id: string | null;
  readonly region: string | null;
  readonly project: string | null;
}

const locationOf = (region: string | null, project: string | null): KeyLocation => ({ ...(region === null ? {} : { region }), ...(project === null ? {} : { project }) });
const toGen = (g: GenStored): GenRow => ({ keyref: g.keyref, gen: g.gen, status: g.status, platformKeyId: g.platform_key_id, location: locationOf(g.region, g.project) });

export interface RotationStore {
  /** Opens a run. A second active run for the key is `conflict` (the unique index, not a check). Writes `rotation.state`. */
  openRun(run: NewRun): RunRow;
  run(runId: string): RunRow | undefined;
  /** Runs that are not done, failed or abandoned. */
  activeRuns(): readonly RunRow[];
  /** The key's active run, if one is working or waiting. */
  activeRunOf(keyref: string): RunRow | undefined;
  /** Runs, in any state, whose intent name a platform key may carry. */
  runs(): readonly RunRow[];
  update(runId: string, patch: RunPatch): RunRow;

  putKeyInfo(keyref: string, info: KeyInfo): void;
  keyInfo(keyref: string): KeyInfo | undefined;
  /** The key's own row, with what rotation needs of its rotation record. */
  key(keyref: string): KeyHead | undefined;
  keys(): readonly KeyHead[];
  /** The key's destinations as the snapshot shows them. */
  destinationsOf(keyref: string): readonly DestinationRow[];
  /** Sets the status the snapshot shows (and the current generation) and writes `key.changed`. */
  setStatus(keyref: string, status: MetaKey['status'], genCurrent?: number): void;
  markRotated(keyref: string, at: number): void;

  putGen(gen: GenRow): void;
  gen(keyref: string, gen: number): GenRow | undefined;
  gens(keyref: string): readonly GenRow[];
  setGenStatus(keyref: string, gen: number, status: GenStatus): void;
  /** The highest generation number ever used, 0 for a key with none. */
  topGen(keyref: string): number;
  generationIdKnown(platformKeyId: string): boolean;

  /**
   * The intent written BEFORE a push: the destination may hold the new value from here on, whatever the push answers. Answers whether this
   * push is the only one that could have applied (no receipt yet, or a refused one); false when an earlier attempt of the run, whose receipt
   * is `maybe` or `true`, may have: a `refused` answer to this push then proves nothing about that one and is not recorded.
   */
  intendPush(runId: string, kind: string, target: string): boolean;
  /** The intent written BEFORE a redeploy, on the receipt of the push it follows (`internal` when that push's intent is missing). */
  intendRedeploy(runId: string, kind: string, target: string): void;
  /** Patches a receipt whose intent was written (`internal` otherwise). */
  putReceipt(runId: string, kind: string, target: string, patch: { readonly version?: string; readonly pushed?: true | 'refused'; readonly rollbackNotified?: true }): void;
  receipts(runId: string): readonly Receipt[];

  /** True the first time for an id: one notice per stray key. */
  firstOrphanNotice(platformKeyId: string): boolean;

  putDelivery(row: Omit<DeliveryRow, 'ackedAt' | 'notified'>): void;
  deliveries(): readonly DeliveryRow[];
  delivery(deliveryId: string): DeliveryRow | undefined;
  ackDelivery(deliveryId: string, at: number): void;
  markDeliveryNotified(deliveryId: string): void;
}

export function createRotationStore(db: DatabaseSync, clock: Clock, hub: EventSignal): RotationStore {
  db.exec(SCHEMA);
  const write = <T>(work: () => T): T => {
    const result = inTransaction(db, work);
    hub.notify();
    return result;
  };
  const runStored = (runId: string): RunStored | undefined => db.prepare('SELECT * FROM rotation_runs WHERE run_id = ?').get(runId) as RunStored | undefined;
  const keyChanged = (keyref: string): void => void insertEvent(db, clock.now(), 'key.changed', { keyref });
  const rotationState = (r: RunStored): void => void insertEvent(db, clock.now(), 'rotation.state', { run_id: r.run_id, keyref: r.keyref, state: r.state, step: r.failed_step ?? r.state });

  const self: RotationStore = {
    openRun(run) {
      return write(() => {
        try {
          db.prepare('INSERT INTO rotation_runs (run_id, keyref, state, gen_old, gen_new, intent_name, origin, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
            run.runId,
            run.keyref,
            run.state,
            run.genOld,
            run.genNew,
            run.intentName,
            run.origin,
            clock.now(),
          );
        } catch (error) {
          if (error instanceof Error && /UNIQUE/i.test(error.message)) throw new ApiError('conflict', 'run_exists');
          throw error;
        }
        const stored = runStored(run.runId);
        if (stored === undefined) throw new ApiError('internal');
        rotationState(stored);
        return toRun(stored);
      });
    },
    run: (runId) => {
      const r = runStored(runId);
      return r === undefined ? undefined : toRun(r);
    },
    activeRuns: () => (db.prepare("SELECT * FROM rotation_runs WHERE state NOT IN ('done','failed','abandoned') ORDER BY opened_at, run_id").all() as unknown as RunStored[]).map(toRun),
    activeRunOf: (keyref) => {
      const r = db.prepare("SELECT * FROM rotation_runs WHERE keyref = ? AND state NOT IN ('done','failed','abandoned')").get(keyref) as RunStored | undefined;
      return r === undefined ? undefined : toRun(r);
    },
    runs: () => (db.prepare('SELECT * FROM rotation_runs ORDER BY opened_at, run_id').all() as unknown as RunStored[]).map(toRun),
    update(runId, patch) {
      return write(() => {
        const before = runStored(runId);
        if (before === undefined) throw new ApiError('not_found');
        db.prepare(
          `UPDATE rotation_runs SET state = ?, revoke_at = ?, attempts = ?, failed_step = ?, reason_code = ?, failed_notified = ?, still_on_notified = ?, failed_at = ? WHERE run_id = ?`,
        ).run(
          patch.state ?? before.state,
          patch.revokeAt ?? before.revoke_at,
          patch.attempts ?? before.attempts,
          patch.failedStep ?? before.failed_step,
          patch.reasonCode ?? before.reason_code,
          patch.failedNotified === true ? 1 : before.failed_notified,
          patch.stillOnNotified === true ? 1 : before.still_on_notified,
          before.failed_at ?? patch.failedAt ?? null,
          runId,
        );
        const after = runStored(runId);
        if (after === undefined) throw new ApiError('internal');
        if (patch.state !== undefined && patch.state !== before.state) rotationState(after);
        return toRun(after);
      });
    },

    putKeyInfo(keyref, info) {
      write(() => {
        db.prepare(
          `INSERT INTO rotation_keys (keyref, scope_json, region, project, rotated_at, mark_admin) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (keyref) DO UPDATE SET scope_json = excluded.scope_json, region = excluded.region, project = excluded.project, rotated_at = excluded.rotated_at, mark_admin = excluded.mark_admin`,
        ).run(keyref, JSON.stringify(info.scopeItems), info.location.region ?? null, info.location.project ?? null, info.rotatedAt, info.markAdmin ? 1 : 0);
      });
    },
    keyInfo(keyref) {
      const r = db.prepare('SELECT scope_json, region, project, rotated_at, mark_admin FROM rotation_keys WHERE keyref = ?').get(keyref) as
        | { scope_json: string; region: string | null; project: string | null; rotated_at: number; mark_admin: number }
        | undefined;
      return r === undefined ? undefined : { scopeItems: JSON.parse(r.scope_json) as string[], location: locationOf(r.region, r.project), rotatedAt: r.rotated_at, markAdmin: r.mark_admin === 1 };
    },
    key: (keyref) => {
      const k = db.prepare(`${HEAD_SELECT} WHERE k.keyref = ?`).get(keyref) as HeadStored | undefined;
      return k === undefined ? undefined : toHead(k);
    },
    keys: () => (db.prepare(`${HEAD_SELECT} ORDER BY k.keyref`).all() as unknown as HeadStored[]).map(toHead),
    destinationsOf: (keyref) => db.prepare('SELECT kind, target, readable_by FROM destinations WHERE keyref = ? ORDER BY kind, target').all(keyref) as unknown as DestinationRow[],
    setStatus(keyref, status, genCurrent) {
      write(() => {
        const done = db.prepare('UPDATE keys SET status = ?, gen_current = coalesce(?, gen_current) WHERE keyref = ?').run(status, genCurrent ?? null, keyref).changes;
        if (done === 0) throw new ApiError('not_found');
        keyChanged(keyref);
      });
    },
    markRotated(keyref, at) {
      write(() => void db.prepare('UPDATE rotation_keys SET rotated_at = ? WHERE keyref = ?').run(at, keyref));
    },

    putGen(gen) {
      write(() => {
        db.prepare(
          `INSERT INTO rotation_gens (keyref, gen, status, platform_key_id, region, project) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (keyref, gen) DO UPDATE SET status = excluded.status, platform_key_id = excluded.platform_key_id, region = excluded.region, project = excluded.project`,
        ).run(gen.keyref, gen.gen, gen.status, gen.platformKeyId, gen.location.region ?? null, gen.location.project ?? null);
      });
    },
    gen: (keyref, gen) => {
      const g = db.prepare('SELECT * FROM rotation_gens WHERE keyref = ? AND gen = ?').get(keyref, gen) as GenStored | undefined;
      return g === undefined ? undefined : toGen(g);
    },
    gens: (keyref) => (db.prepare('SELECT * FROM rotation_gens WHERE keyref = ? ORDER BY gen').all(keyref) as unknown as GenStored[]).map(toGen),
    setGenStatus(keyref, gen, status) {
      write(() => {
        if (db.prepare('UPDATE rotation_gens SET status = ? WHERE keyref = ? AND gen = ?').run(status, keyref, gen).changes === 0) throw new ApiError('not_found');
        // A generation going live, into grace or out of it is a change of what the share file lists (KBOX-33): the share writer follows this event.
        keyChanged(keyref);
      });
    },
    topGen: (keyref) => (db.prepare('SELECT coalesce(max(gen), 0) AS g FROM rotation_gens WHERE keyref = ?').get(keyref) as { g: number }).g,
    generationIdKnown: (id) => db.prepare('SELECT 1 AS one FROM rotation_gens WHERE platform_key_id = ?').get(id) !== undefined,

    intendPush(runId, kind, target) {
      return write(() => {
        const prior = db.prepare('SELECT pushed FROM rotation_receipts WHERE run_id = ? AND kind = ? AND target = ?').get(runId, kind, target) as { pushed: number } | undefined;
        if (prior === undefined) {
          db.prepare(`INSERT INTO rotation_receipts (run_id, kind, target, pushed) VALUES (?, ?, ?, ${PUSH_MAYBE})`).run(runId, kind, target);
          return true;
        }
        if (prior.pushed !== PUSH_REFUSED) return false;
        db.prepare(`UPDATE rotation_receipts SET pushed = ${PUSH_MAYBE} WHERE run_id = ? AND kind = ? AND target = ?`).run(runId, kind, target);
        return true;
      });
    },
    intendRedeploy(runId, kind, target) {
      write(() => {
        const changed = db.prepare('UPDATE rotation_receipts SET redeployed = 1 WHERE run_id = ? AND kind = ? AND target = ?').run(runId, kind, target).changes;
        if (changed === 0) throw new ApiError('internal', 'no_intent_receipt');
      });
    },
    putReceipt(runId, kind, target, patch) {
      write(() => {
        const changed = db
          .prepare('UPDATE rotation_receipts SET version = coalesce(?, version), pushed = coalesce(?, pushed), rollback_notified = max(rollback_notified, ?) WHERE run_id = ? AND kind = ? AND target = ?')
          .run(patch.version ?? null, pushedCode(patch.pushed), patch.rollbackNotified === true ? 1 : 0, runId, kind, target).changes;
        // A receipt exists only once its intent was written: a patch without one is a fault of the caller, not a row to invent.
        if (changed === 0) throw new ApiError('internal', 'no_intent_receipt');
      });
    },
    receipts: (runId) =>
      (db.prepare('SELECT * FROM rotation_receipts WHERE run_id = ? ORDER BY kind, target').all(runId) as unknown as { run_id: string; kind: string; target: string; version: string | null; pushed: number; redeployed: number; rollback_notified: number }[]).map(
        (r): Receipt => ({ runId: r.run_id, kind: r.kind, target: r.target, version: r.version, pushed: pushedOf(r.pushed), redeployIntended: r.redeployed === 1, rollbackNotified: r.rollback_notified === 1 }),
      ),

    firstOrphanNotice: (id) => db.prepare('INSERT OR IGNORE INTO orphan_notices (platform_key_id) VALUES (?)').run(id).changes === 1,

    putDelivery(row) {
      write(() => void db.prepare('INSERT OR IGNORE INTO deliveries (delivery_id, keyref, project, name, gen, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(row.deliveryId, row.keyref, row.project, row.name, row.gen, row.createdAt));
    },
    deliveries: () => (db.prepare('SELECT * FROM deliveries ORDER BY created_at, delivery_id').all() as unknown as DeliveryStored[]).map(toDelivery),
    delivery: (id) => {
      const d = db.prepare('SELECT * FROM deliveries WHERE delivery_id = ?').get(id) as DeliveryStored | undefined;
      return d === undefined ? undefined : toDelivery(d);
    },
    ackDelivery(deliveryId, at) {
      write(() => void db.prepare('UPDATE deliveries SET acked_at = coalesce(acked_at, ?) WHERE delivery_id = ?').run(at, deliveryId));
    },
    markDeliveryNotified(deliveryId) {
      write(() => void db.prepare('UPDATE deliveries SET notified = 1 WHERE delivery_id = ?').run(deliveryId));
    },
  };
  return self;
}

interface DeliveryStored {
  readonly delivery_id: string;
  readonly keyref: string;
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly created_at: number;
  readonly acked_at: number | null;
  readonly notified: number;
}

const toDelivery = (d: DeliveryStored): DeliveryRow => ({ deliveryId: d.delivery_id, keyref: d.keyref, project: d.project, name: d.name, gen: d.gen, createdAt: d.created_at, ackedAt: d.acked_at, notified: d.notified === 1 });
