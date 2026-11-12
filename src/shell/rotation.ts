// The rotation unit as one wiring: the orchestrator, reconcile, the paste flow, the key and delivery routes, the executors of the two kinds this
// unit owns (`rotate_key`, `add_key`) and the scheduler's tick. main-core hands it the platform registry when the adapter units build one.
import type { Audit, AuditEvent } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { ActionKind } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { dueDates } from '../pure/scheduler.ts';
import { slotOf } from '../pure/slots.ts';
import { lastBoxRequestEnd } from './approvals.ts';
import type { Approvals, Executor } from './approvals.ts';
import type { Approvers } from './approvers.ts';
import type { CoreParts } from './core.ts';
import { deliveryRoutes, noticeStaleDeliveries } from './deliveries.ts';
import type { Route } from './http.ts';
import { keyRoutes } from './key-routes.ts';
import { newKeyOf } from './new-key.ts';
import type { RotateKey } from './new-key.ts';
import { createOrchestrator } from './orchestrator.ts';
import type { Orchestrator } from './orchestrator.ts';
import { createPaste, pasteRoutes } from './paste.ts';
import type { Paste } from './paste.ts';
import { createReconciler } from './reconcile.ts';
import type { Reconciler } from './reconcile.ts';
import { createRotationStore } from './rotation-store.ts';
import type { KeyHead, RotationStore } from './rotation-store.ts';
import { isPasteSource as pasteSource, overlapOf, storedPlacement } from './rotation-ports.ts';
import type { LocationRefusal } from '../pure/location.ts';
import type { PlatformSource, Point } from './rotation-ports.ts';

const HOUR_MS = 3600_000;
const TICK_MS = HOUR_MS;
const RECONCILE_MS = 24 * HOUR_MS;
/** A key whose last run failed is not tried again by the schedule for this long: one notice per day at most. */
const AFTER_FAILURE_MS = 24 * HOUR_MS;
/** A request the scheduler opened and the owner refused is not opened again for this long after the refusal (KBOX-52). */
const AFTER_REFUSAL_MS = 7 * 24 * HOUR_MS;
/** One that expired unanswered, for this long after the expiry (KBOX-52). */
const AFTER_EXPIRY_MS = 24 * HOUR_MS;
/** The fixed codes a failed part of the schedule is audited with (`rotation.drive_failed`). */
type ScheduleFault = 'tick_failed' | 'resume_failed' | 'reconcile_failed';
/** The part of the schedule each code names, recorded as the audit row's `run_id`. */
const PART_OF: Readonly<Record<ScheduleFault, string>> = { tick_failed: 'tick', resume_failed: 'resume', reconcile_failed: 'reconcile' };

export interface RotationDeps {
  readonly parts: CoreParts;
  readonly approvals: Pick<Approvals, 'propose' | 'sweep'>;
  readonly approvers: Approvers;
  readonly push: Push;
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly random: Random;
  readonly audit: Audit;
  readonly source: PlatformSource;
  readonly checkpoint?: (point: Point) => void | Promise<void>;
}

export interface Rotation {
  readonly store: RotationStore;
  readonly orchestrator: Orchestrator;
  readonly reconciler: Reconciler;
  readonly paste: Paste;
  readonly routes: readonly Route[];
  /** Executors for `openApproveCore`: an approved `rotate_key` or `add_key`. */
  readonly executors: Partial<Readonly<Record<ActionKind, Executor>>>;
  /** Opens what is due: ordinary keys start a run, admin and master keys open their approval or paste task, once. */
  tick(): void;
  /**
   * Starts rotation without waiting on any port (review N4): arms the hourly tick and the daily reconcile, and in the background resumes
   * unfinished runs, then reconciles, then ticks, each audited when it fails. Returns the stop, which also stops the orchestrator's run timers;
   * start-up work not begun when it is called is not begun.
   */
  run(): () => void;
  /** Resolves when the start-up work has ended and every run this process works on has finished or waits for a clock. */
  idle(): Promise<void>;
}

export function openRotation(deps: RotationDeps): Rotation {
  const { parts } = deps;
  const store = createRotationStore(parts.db, deps.clock, parts.hub);
  const orchestrator = createOrchestrator({ ...deps.source, store, meta: parts.meta, vault: parts.vault, clock: deps.clock, scheduler: deps.scheduler, random: deps.random, audit: deps.audit, events: parts.events, push: deps.push, ...(deps.checkpoint === undefined ? {} : { checkpoint: deps.checkpoint }) });
  const reconciler = createReconciler({ ...deps.source, store, audit: deps.audit, events: parts.events, clock: deps.clock, orchestrator });
  const paste = createPaste({ db: parts.db, approvers: deps.approvers, clock: deps.clock, random: deps.random, audit: deps.audit, events: parts.events, push: deps.push, meta: parts.meta, source: deps.source, orchestrator, store });
  const delivery = { store, vault: parts.vault, audit: deps.audit, events: parts.events, clock: deps.clock };
  const routes = [
    ...keyRoutes({ store, meta: parts.meta, orchestrator, approvals: deps.approvals, paste, source: deps.source, vault: parts.vault, audit: deps.audit, events: parts.events, clock: deps.clock, random: deps.random }),
    ...deliveryRoutes(delivery),
    ...pasteRoutes(paste),
  ];
  const isPasteSource = (platform: string): boolean => pasteSource(deps.source, platform);

  const executors: Rotation['executors'] = {
    add_key: async (a) => {
      const action = a.action;
      if (action.kind !== 'add_key') return { result: 'failed', reason: 'wrong_kind' };
      if (isPasteSource(action.platform)) return { result: 'failed', reason: 'paste_required' };
      if (!overlapOf(deps.source.platform(action.platform))) return { result: 'failed', reason: 'overlap_needs_paste' };
      const key = newKeyOf(action, deps.source);
      if (store.keyExists(key.keyref)) return { result: 'failed', reason: 'key_exists' };
      const created = await orchestrator.create(key);
      if (action.label !== undefined) parts.meta.putGrant(key.keyref, action.label);
      return created.status === 'works' ? { result: 'done' } : { result: 'failed', reason: 'create_failed' };
    },
    rotate_key: (a) => {
      const action = a.action;
      if (action.kind !== 'rotate_key') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      const head = store.key(action.keyref);
      if (head === undefined) return Promise.resolve({ result: 'failed', reason: 'unknown_key' });
      // A paste-source key is rotated by the paste, which is its approval (KBOX-12); an approval alone has no new value to store.
      if (isPasteSource(head.platform)) return Promise.resolve({ result: 'failed', reason: 'paste_required' });
      try {
        orchestrator.start({ keyref: action.keyref, origin: 'approval' });
        return Promise.resolve({ result: 'done' });
      } catch (error) {
        if (error instanceof ApiError && error.code === 'conflict') return Promise.resolve({ result: 'failed', reason: 'run_exists' });
        throw error;
      }
    },
  };

  const openRequest = (keyref: string, platform: string): void => {
    const action: RotateKey = { kind: 'rotate_key', keyref };
    if (isPasteSource(platform)) {
      paste.open({ action, requester: { kind: 'box' } });
      store.setStatus(keyref, 'awaiting_paste');
    } else {
      deps.approvals.propose({ action, requester: { kind: 'box' } });
      store.setStatus(keyref, 'awaiting_approval');
    }
  };

  /**
   * One part of the schedule (review N2): a throw is audited with the part's fixed code and the schedule goes on, so a failed sweep or one bad
   * key never stops the others and never reaches a timer (where it would end core).
   */
  const scheduled = (subject: string, code: ScheduleFault, work: () => void): void => {
    try {
      work();
    } catch {
      deps.audit.append(faultOf(subject, code));
    }
  };
  const faultOf = (subject: string, code: ScheduleFault): AuditEvent => ({ action: 'rotation.drive_failed', subject, at: deps.clock.now(), detail: { run_id: PART_OF[code], code } });

  /** KBOX-52: whether the scheduler's last request for this slot was refused or expired and its wait still runs. A manual rotation never asks this. */
  const requestWaits = (slot: string, platform: string, now: number): boolean => {
    if (isPasteSource(platform)) {
      const expired = paste.lastExpiredAt(slot);
      return expired !== undefined && now - expired < AFTER_EXPIRY_MS;
    }
    const ended = lastBoxRequestEnd(parts.db, slot);
    return ended !== undefined && now - ended.at < (ended.outcome === 'denied' ? AFTER_REFUSAL_MS : AFTER_EXPIRY_MS);
  };

  /** The key and code pairs this process already recorded as skipped by the schedule (KBOX-57: one record per key and code). */
  const refused = new Set<string>();
  const refusedOnce = (keyref: string, code: LocationRefusal): void => {
    const pair = `${keyref} ${code}`;
    if (refused.has(pair)) return;
    deps.audit.append({ action: 'rotation.refused', subject: keyref, at: deps.clock.now(), detail: { code } });
    refused.add(pair);
  };

  const tickKey = (key: KeyHead, now: number, due: ReadonlyMap<string, number>, waiting: ReadonlySet<string>): void => {
    const slot = slotOf({ kind: 'rotate_key', keyref: key.keyref });
    const pending = waiting.has(slot) || paste.hasPending(slot);
    if ((key.status === 'awaiting_approval' || key.status === 'awaiting_paste') && !pending && store.activeRunOf(key.keyref) === undefined) store.setStatus(key.keyref, 'works');
    const at = due.get(key.keyref);
    if (at === undefined || at > now || pending || store.activeRunOf(key.keyref) !== undefined) return;
    if (!store.gens(key.keyref).some((g) => g.status === 'current')) return;
    const last = store.runs().filter((r) => r.keyref === key.keyref).at(-1);
    // KBOX-52: no sooner than 24 hours after the failure itself (the schema refuses a failed run without its failure time).
    if (last?.state === 'failed' && now - (last.failedAt ?? last.openedAt) < AFTER_FAILURE_MS) return;
    if (key.class !== 'ordinary' && requestWaits(slot, key.platform, now)) return;
    // KBOX-34: an ordinary key on a paste-source platform has no issuer; the box holds no such key and never runs it as an api run.
    if (key.class === 'ordinary' && isPasteSource(key.platform)) return;
    // KBOX-57: a stored location the entry now refuses is skipped, recorded once per key and code; nothing is rewritten.
    const info = store.keyInfo(key.keyref);
    const placed = info === undefined ? 'ok' : storedPlacement(deps.source, key, info);
    if (placed !== 'ok') {
      refusedOnce(key.keyref, placed);
      return;
    }
    if (key.class === 'ordinary') orchestrator.start({ keyref: key.keyref, origin: 'schedule' });
    else openRequest(key.keyref, key.platform);
  };

  const tick = (): void => {
    scheduled('tick', 'tick_failed', () => deps.approvals.sweep());
    scheduled('tick', 'tick_failed', () => {
      const now = deps.clock.now();
      const keys = store.keys();
      const due = dueDates(keys.map((k) => ({ keyref: k.keyref, class: k.class, rotateEveryDays: k.rotateEveryDays, graceHours: k.graceHours, lastRotatedAt: k.rotatedAt, expiresAt: k.expiresAt, manual: false })));
      const waiting = new Set(parts.meta.snapshot().approvals.map((a) => a.slot));
      for (const key of keys) scheduled(key.keyref, 'tick_failed', () => tickKey(key, now, due, waiting));
    });
    scheduled('tick', 'tick_failed', () => noticeStaleDeliveries(delivery));
  };

  /** Start-up work and daily reconciles in flight: `idle()` waits for them, so the stores are not closed under them. */
  const inBackground = new Set<Promise<void>>();
  const background = (job: Promise<void>): void => {
    inBackground.add(job);
    void job.finally(() => inBackground.delete(job));
  };

  /** The start-up and daily work that awaits ports: a throw is audited and the start or the loop goes on. */
  const scheduledAsync = async (subject: 'resume' | 'reconcile', code: ScheduleFault, work: () => Promise<void>): Promise<void> => {
    try {
      await work();
    } catch {
      deps.audit.append(faultOf(subject, code));
    }
  };

  return {
    store,
    orchestrator,
    reconciler,
    paste,
    routes,
    executors,
    tick,
    run() {
      let stopped = false;
      let cancelTick = (): void => undefined;
      let cancelReconcile = (): void => undefined;
      const loopTick = (): void => {
        if (stopped) return;
        cancelTick = deps.scheduler.after(TICK_MS, loopTick);
        tick();
      };
      const loopReconcile = (): void => {
        if (stopped) return;
        background(
          scheduledAsync('reconcile', 'reconcile_failed', () => reconciler.run()).finally(() => {
            if (!stopped) cancelReconcile = deps.scheduler.after(RECONCILE_MS, loopReconcile);
          }),
        );
      };
      cancelTick = deps.scheduler.after(TICK_MS, loopTick);
      cancelReconcile = deps.scheduler.after(RECONCILE_MS, loopReconcile);
      // KBOX-51: reconcile on start runs after resume has re-leased the unfinished runs; neither holds back the caller (a port may hang).
      background(
        (async (): Promise<void> => {
          await scheduledAsync('resume', 'resume_failed', () => orchestrator.resume());
          if (stopped) return;
          await scheduledAsync('reconcile', 'reconcile_failed', () => reconciler.run());
          if (!stopped) tick();
        })(),
      );
      return () => {
        stopped = true;
        cancelTick();
        cancelReconcile();
        orchestrator.stop();
      };
    },
    async idle() {
      while (inBackground.size > 0) await Promise.all([...inBackground]);
      await orchestrator.idle();
    },
  };
}
