// KBOX-51, KBOX-17, KBOX-16: the rotation orchestrator. A run is persisted step by step in meta.db and walked
// create -> store -> verify -> push -> redeploy -> check -> promote -> (grace) -> revoke -> confirm. The intent row is written before any
// platform call; a failure at steps 3 to 8 re-pushes the old generation, revokes and confirms the new one and sends ONE notice.
// A revoke is confirmed by the verifier (or the lister), never by its own answer. The old key is never revoked while a destination
// still holds the new one's replacement unconfirmed, and the new one is never revoked while a destination still holds it.
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { IssuedKey } from '../ports/issuer.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { KeyClass, KeyLocation, Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { ApiError } from '../pure/errors.ts';
import { admitDestination } from '../pure/class.ts';
import { intentName, nextStep, retryDelayMs } from '../pure/rotation-machine.ts';
import type { Step } from '../pure/rotation-machine.ts';
import { revokeAndConfirm } from './revoke-confirm.ts';
import type { DestinationKit, PlatformKit, PlatformSource, Point } from './rotation-ports.ts';
import type { DestinationRow, KeyHead, Receipt, RotationStore, RunOrigin, RunRow } from './rotation-store.ts';

const HOUR_MS = 3600_000;
/** The destination kind that is a delivery to the workstation, not an adapter (KBOX-34). */
const WORKSTATION = 'workstation';

export interface NewKey {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects: readonly string[];
  readonly scopeItems: readonly string[];
  readonly class: KeyClass;
  readonly destinations: readonly DestinationRow[];
  readonly rotateEveryDays: number;
  readonly graceHours: number;
  readonly location: KeyLocation;
  readonly markAdmin: boolean;
}

export interface StartInput {
  readonly keyref: string;
  readonly origin: RunOrigin;
  /** A value pasted on the phone (KBOX-12): the run starts at verify, the platform is not asked to issue. */
  readonly value?: Uint8Array;
}

export interface OrchestratorDeps extends PlatformSource {
  readonly store: RotationStore;
  readonly meta: MetaStore;
  readonly vault: Vault;
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly random: Random;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly push: Push;
  /** Where a test stops the process; production passes none. */
  readonly checkpoint?: (point: Point) => void | Promise<void>;
}

export interface Orchestrator {
  /** Opens a run for the key (`not_found` for no such key, `conflict` for a run already open) and works on it in the background. */
  start(input: StartInput): RunRow;
  /** Writes a key's rows and runs its first generation to the end. Answers the status the key ended in. */
  create(key: NewKey, value?: Uint8Array): Promise<{ readonly status: 'works' | 'failed' }>;
  /** After a start: works on every unfinished run again, re-leasing it, except an `issuing` run that stored nothing (reconcile's). */
  resume(): Promise<void>;
  /**
   * Takes up an unleased `issuing` run again (reconcile): continues it when its new generation is stored (KBOX-51: a crash between store and
   * the step's write), else abandons it and opens a new run for its key under a new run id.
   */
  retake(runId: string): RunRow;
  /** True while this process works on a run of the key: reconcile leaves it alone. */
  isLeased(keyref: string): boolean;
  /** Resolves when every run this process works on has finished or is waiting for a clock. */
  idle(): Promise<void>;
}

type Next = 'continue' | 'wait';
type Outcome = { readonly ok: true } | { readonly ok: false; readonly code: string };
interface Fresh {
  readonly id: string;
  readonly value: Lent;
}

const underscored = (kind: string): string => kind.replace(/[^a-z0-9]+/g, '_');
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

export function createOrchestrator(deps: OrchestratorDeps): Orchestrator {
  const { store } = deps;
  const leased = new Set<string>();
  const inflight = new Set<Promise<void>>();
  const timers = new Map<string, () => void>();

  const now = (): number => deps.clock.now();
  const point = async (p: Point): Promise<void> => {
    await deps.checkpoint?.(p);
  };

  // --- running a run ----------------------------------------------------------------------------------------------------

  const launch = (runId: string): void => {
    const job: Promise<void> = drive(runId).catch((error: unknown) => {
      deps.audit.append({ action: 'rotation.drive_failed', subject: store.run(runId)?.keyref ?? 'unknown', at: now(), detail: { run_id: runId, code: error instanceof ApiError ? error.code : 'drive_failed' } });
    });
    inflight.add(job);
    void job.finally(() => inflight.delete(job));
  };

  const later = (runId: string, ms: number): void => {
    timers.get(runId)?.();
    timers.set(
      runId,
      deps.scheduler.after(ms, () => {
        timers.delete(runId);
        launch(runId);
      }),
    );
  };

  async function drive(runId: string): Promise<void> {
    const first = store.run(runId);
    if (first === undefined || leased.has(first.keyref)) return;
    leased.add(first.keyref);
    try {
      for (;;) {
        const run = store.run(runId);
        if (run === undefined || run.state === 'done' || run.state === 'failed' || run.state === 'abandoned') return;
        if ((await step(run)) === 'wait') return;
      }
    } finally {
      leased.delete(first.keyref);
    }
  }

  /** One persisted transition: the next state is written, then the process may stop (a test) with that written. */
  const advance = async (run: RunRow, done: Step, patch: { readonly revokeAt?: number } = {}): Promise<Next> => {
    const state = nextStep(done, { overlap: overlapOf(kitOf(run.keyref)) });
    store.update(run.runId, { state: state === 'done' ? 'done' : state, ...patch });
    await point(done);
    return 'continue';
  };

  const kitOf = (keyref: string): PlatformKit | undefined => {
    const head = store.key(keyref);
    return head === undefined ? undefined : deps.platform(head.platform);
  };
  const overlapOf = (kit: PlatformKit | undefined): boolean => kit?.issuer?.capabilities().overlap ?? true;

  async function step(run: RunRow): Promise<Next> {
    const head = store.key(run.keyref);
    const info = store.keyInfo(run.keyref);
    const kit = head === undefined ? undefined : deps.platform(head.platform);
    if (head === undefined || info === undefined || kit === undefined) return fail(run, run.state === 'rolling_back' ? 'rollback' : run.state, 'no_adapter');
    switch (run.state) {
      case 'issuing':
        return issue(run, head, kit);
      case 'verifying':
        return verifyNew(run, head, kit, 'verifying', 'verify');
      case 'pushing':
        return pushAll(run, head);
      case 'redeploying':
        return redeployAll(run, head);
      case 'checking':
        return verifyNew(run, head, kit, 'checking', 'check');
      case 'promoting':
        return promote(run, head, kit);
      case 'grace':
        return graceWait(run);
      case 'revoking':
        return revokeOld(run, head, kit);
      case 'rolling_back':
        return rollBack(run, head, kit);
      case 'done':
      case 'failed':
      case 'abandoned':
        return 'wait';
    }
  }

  async function attempt(run: RunRow, stepName: string, work: () => Promise<void>, code: string): Promise<Outcome> {
    try {
      await work();
      return { ok: true };
    } catch {
      deps.audit.append({ action: 'rotation.step_failed', subject: run.keyref, at: now(), detail: { run_id: run.runId, step: stepName, code } });
      return { ok: false, code };
    }
  }

  /** A generation the vault no longer lends (retired, never stored) as a result: the caller decides what its absence means. */
  const tryLend = (keyref: string, gen: number): { readonly ok: true; readonly value: Lent } | { readonly ok: false } => {
    try {
      return { ok: true, value: deps.vault.lend(keyref, gen) };
    } catch {
      return { ok: false };
    }
  };
  const lendOrUndefined = (keyref: string, gen: number): Lent | undefined => {
    const lent = tryLend(keyref, gen);
    return lent.ok ? lent.value : undefined;
  };

  // --- steps 3 and 4: create and store ----------------------------------------------------------------------------------------

  /** An `issuing` run whose new generation was never stored: a key its platform made, if any, is an orphan for reconcile. */
  const storedNothing = (run: RunRow): boolean => run.state === 'issuing' && store.gen(run.keyref, run.genNew) === undefined;

  async function issue(run: RunRow, head: KeyHead, kit: PlatformKit): Promise<Next> {
    const issuer = kit.issuer;
    const info = store.keyInfo(run.keyref);
    if (issuer === undefined || info === undefined) return fail(run, 'issuing', 'no_issuer');
    // Stored before the process stopped: the platform key is this generation's, so the run goes on and nothing is issued twice.
    if (!storedNothing(run)) return advance(run, 'issuing');
    const made: { issued?: IssuedKey } = {};
    const created = await attempt(
      run,
      'issuing',
      async () => {
        made.issued = await issuer.issue({ scope: { items: info.scopeItems } }, run.intentName, deps.master(head.platform));
      },
      'issue_failed',
    );
    const issued = made.issued;
    if (!created.ok || issued === undefined) return fail(run, 'issuing', 'issue_failed');
    await point('issued');
    const stored = await attempt(
      run,
      'issuing',
      async () => {
        await issued.value.use((bytes) => {
          deps.vault.put(run.keyref, run.genNew, bytes);
          return Promise.resolve();
        });
        store.putGen({ keyref: run.keyref, gen: run.genNew, status: 'pending', platformKeyId: issued.platformKeyId, location: info.location });
      },
      'store_failed',
    );
    if (!stored.ok) return fail(run, 'issuing', 'store_failed', { id: issued.platformKeyId, value: issued.value });
    await point('stored');
    deps.audit.append({ action: 'key.issued', subject: run.keyref, at: now() });
    return advance(run, 'issuing');
  }

  // --- steps 5 and 8: the verifier on the new key ---------------------------------------------------------------------------------

  async function verifyNew(run: RunRow, head: KeyHead, kit: PlatformKit, stepName: 'verifying' | 'checking', word: 'verify' | 'check'): Promise<Next> {
    const verifier = kit.verifier;
    if (verifier !== undefined) {
      const value = lendOrUndefined(run.keyref, run.genNew);
      if (value === undefined) return fail(run, stepName, `${word}_failed`);
      const verdict = await attempt0(() => verifier.verify(value, { platform: head.platform }));
      if (verdict !== 'ok') return fail(run, stepName, verdict === 'rejected' ? `${word}_rejected` : `${word}_unreachable`);
    }
    return advance(run, stepName);
  }

  async function attempt0<T extends 'ok' | 'rejected' | 'unreachable'>(call: () => Promise<T>): Promise<T | 'unreachable'> {
    try {
      return await call();
    } catch {
      return 'unreachable';
    }
  }

  // --- steps 6 and 7: push and redeploy ---------------------------------------------------------------------------------------------

  const kitFor = (row: DestinationRow): DestinationKit | undefined => deps.destination(row.kind);

  async function pushAll(run: RunRow, head: KeyHead): Promise<Next> {
    const master = deps.master(head.platform);
    const value = lendOrUndefined(run.keyref, run.genNew);
    if (value === undefined) return fail(run, 'pushing', 'push_failed');
    const rows = store.destinationsOf(run.keyref);
    // KBOX-16: every destination is admitted again before anything is pushed, because its properties can change at runtime. The workstation is
    // a delivery that a control token fetches through the API, so it is `api`-readable: an ordinary key only (KBOX-34).
    for (const row of rows) {
      const readableBy = row.kind === WORKSTATION ? 'api' : kitFor(row)?.destination.properties().readableBy;
      if (readableBy === undefined) return fail(run, 'pushing', 'push_failed');
      if (!admitDestination(head.class, readableBy)) return fail(run, 'pushing', 'destination_not_allowed');
    }
    for (const row of rows) {
      // The workstation is offered at promote (deliver), never a generation that may still be rolled back.
      if (row.kind === WORKSTATION) continue;
      const kit = kitFor(row);
      if (kit === undefined) return fail(run, 'pushing', 'push_failed');
      const target = { kind: kit.destination.kind, id: row.target };
      // The intent first: from here the destination may hold the new value, whether the push answers, throws or the process dies.
      store.intendPush(run.runId, row.kind, row.target);
      const made: { version?: string } = {};
      const done = await attempt(
        run,
        'pushing',
        async () => {
          made.version = (await kit.destination.push(target, head.name, value, master)).version;
        },
        'push_failed',
      );
      if (!done.ok || made.version === undefined) return fail(run, 'pushing', 'push_failed');
      await point('pushed');
      store.putReceipt(run.runId, row.kind, row.target, { version: made.version, pushed: true });
      await point('receipt');
    }
    return advance(run, 'pushing');
  }

  /** The workstation destination is a delivery (KBOX-34), offered once the generation is promoted: one row per project, made once per run, the value fetched from the vault later. */
  function deliver(run: RunRow, head: KeyHead): void {
    for (const [i, project] of head.projects.entries()) {
      const deliveryId = `dlv_${run.runId.slice(4)}_${i}`;
      if (store.delivery(deliveryId) !== undefined) continue;
      store.putDelivery({ deliveryId, keyref: run.keyref, project, name: head.name, gen: run.genNew, createdAt: now() });
      deps.events.append('delivery.ready', { delivery_id: deliveryId, keyref: run.keyref, project, name: head.name, gen: run.genNew });
    }
  }

  async function redeployAll(run: RunRow, head: KeyHead): Promise<Next> {
    const master = deps.master(head.platform);
    for (const row of store.destinationsOf(run.keyref)) {
      const kit = row.kind === WORKSTATION ? undefined : kitFor(row);
      if (kit?.redeployer === undefined || !kit.destination.properties().needsRedeploy) continue;
      const redeployer = kit.redeployer;
      const target = { kind: kit.destination.kind, id: row.target };
      const ready = await attempt(
        run,
        'redeploying',
        async () => {
          const ref = await redeployer.redeploy(target, master);
          store.putReceipt(run.runId, row.kind, row.target, { redeployed: true });
          if ((await redeployer.ready(ref)) !== 'ready') throw new RangeError('deploy failed');
        },
        'redeploy_failed',
      );
      if (!ready.ok) return fail(run, 'redeploying', 'redeploy_failed');
    }
    return advance(run, 'redeploying');
  }

  // --- step 9: promote ---------------------------------------------------------------------------------------------------------

  async function promote(run: RunRow, head: KeyHead, kit: PlatformKit): Promise<Next> {
    const overlap = overlapOf(kit);
    store.setGenStatus(run.keyref, run.genNew, 'current');
    if (run.genOld > 0) store.setGenStatus(run.keyref, run.genOld, 'grace');
    store.setStatus(run.keyref, 'works', run.genNew);
    store.markRotated(run.keyref, now());
    if (store.destinationsOf(run.keyref).some((row) => row.kind === WORKSTATION)) deliver(run, head);
    return advance(run, 'promoting', { revokeAt: now() + (overlap && run.genOld > 0 ? head.graceHours * HOUR_MS : 0) });
  }

  async function graceWait(run: RunRow): Promise<Next> {
    const at = run.revokeAt ?? now();
    if (now() < at) {
      later(run.runId, at - now());
      return 'wait';
    }
    return advance(run, 'grace');
  }

  // --- step 10: revoke the old key and confirm it is dead ----------------------------------------------------------------------------

  async function revokeOld(run: RunRow, head: KeyHead, kit: PlatformKit): Promise<Next> {
    if (run.genOld > 0) {
      const old = store.gen(run.keyref, run.genOld);
      const dead = await revokeAndConfirm({ kit, platform: head.platform, id: old?.platformKeyId ?? null, value: lendOrUndefined(run.keyref, run.genOld), master: deps.master(head.platform) });
      if (!dead) return retryRevoke(run);
      store.setGenStatus(run.keyref, run.genOld, 'retired');
      deps.vault.retire(run.keyref, run.genOld);
      deps.audit.append({ action: 'key.revoked', subject: run.keyref, at: now() });
    }
    deps.audit.append({ action: 'rotation.completed', subject: run.keyref, at: now(), detail: { run_id: run.runId, gen: run.genNew } });
    return advance(run, 'revoking');
  }

  /** Not proven dead: the old key stays in grace, one notice, retried with backoff (S-249; 1 minute doubling to 1 hour). */
  function retryRevoke(run: RunRow): Next {
    const attempts = run.attempts + 1;
    store.update(run.runId, { attempts });
    deps.audit.append({ action: 'rotation.revoke_unconfirmed', subject: run.keyref, at: now(), detail: { run_id: run.runId, gen: run.genOld, attempt: attempts } });
    if (!run.stillOnNotified) {
      deps.events.append('rotation.old_key_still_on', { run_id: run.runId, keyref: run.keyref, gen: Math.max(1, run.genOld) });
      store.update(run.runId, { stillOnNotified: true });
    }
    later(run.runId, retryDelayMs(attempts - 1));
    return 'wait';
  }

  // --- failure: the old key stays ---------------------------------------------------------------------------------------------------

  /** One notice for the run, then the rollback. */
  async function fail(run: RunRow, stepName: string, code: string, fresh?: Fresh): Promise<Next> {
    const head = store.key(run.keyref);
    const failed = markFailed(run, head, stepName, code);
    const kit = kitOf(run.keyref);
    return kit === undefined || head === undefined ? settleFailed(failed) : rollBack(failed, head, kit, fresh);
  }

  /**
   * The run turns to rolling back and records that its one notice is sent, THEN the notice goes out: a crash in between may lose the card
   * but never sends a second one (review m1). Answers the run as written.
   */
  function markFailed(run: RunRow, head: KeyHead | undefined, stepName: string, code: string): RunRow {
    const step = underscored(stepName);
    const failed = store.update(run.runId, { state: 'rolling_back', failedStep: step, reasonCode: code, failedNotified: true });
    if (!run.failedNotified) noticeFailed(run, head, step, code);
    if (head !== undefined) store.setStatus(run.keyref, 'failed');
    return failed;
  }

  const settleFailed = (run: RunRow): Next => {
    store.update(run.runId, { state: 'failed' });
    return 'wait';
  };

  /**
   * KBOX-17's one notice per failed run. A create run has no old generation, so its notice claims no old key: the `rotation.failed` event
   * pins `old_key_works: true` (KBOX-31), so a create run sends the Web Push alone (admin and master), and its caller gets the failure as
   * the answer to the create (`POST /api/keys`, the approval's or the paste's execution).
   */
  function noticeFailed(run: RunRow, head: KeyHead | undefined, step: string, code: string): void {
    const pushed = head !== undefined && head.class !== 'ordinary';
    if (run.genOld === 0) {
      if (pushed) deps.push.send({ title: `Adding the key ${run.keyref} failed`, kind: 'rotation_failed' });
      return;
    }
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step, reason_code: code, old_key_works: true });
    if (pushed) deps.push.send({ title: `The key change of ${run.keyref} failed; the old key still works`, kind: 'rotation_failed' });
  }

  /** The second notice KBOX-17 allows, named for the one destination that would not take the rollback. */
  function noticeHeld(run: RunRow, head: KeyHead, receipt: Receipt): void {
    const pushed = head.class !== 'ordinary';
    if (run.genOld === 0) {
      if (pushed) deps.push.send({ title: `The new key of ${run.keyref} could not be removed from ${receipt.target}`, kind: 'rotation_failed' });
    } else {
      deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step: `rollback_${underscored(receipt.kind)}`, reason_code: 'repush_refused', old_key_works: true });
      if (pushed) deps.push.send({ title: `The old key of ${run.keyref} could not be put back in ${receipt.target}`, kind: 'rotation_failed' });
    }
    store.putReceipt(run.runId, receipt.kind, receipt.target, { rollbackNotified: true });
  }

  /**
   * Undoes the run at one destination: the old value pushed back (and redeployed where it was), or, for a create run, the new value removed.
   * False while the destination holds (or may hold) the new value.
   */
  async function undo(run: RunRow, head: KeyHead, receipt: Receipt, old: Lent | undefined, master: Lent): Promise<boolean> {
    const dk = deps.destination(receipt.kind);
    if (dk === undefined) return false;
    const target = { kind: dk.destination.kind, id: receipt.target };
    if (run.genOld === 0) return (await attempt(run, 'rollback', () => dk.destination.remove(target, head.name, master), 'remove_refused')).ok;
    if (old === undefined) return false;
    const back = await attempt(
      run,
      'rollback',
      async () => {
        await dk.destination.push(target, head.name, old, master);
        if (receipt.redeployed && dk.redeployer !== undefined) {
          const ref = await dk.redeployer.redeploy(target, master);
          if ((await dk.redeployer.ready(ref)) !== 'ready') throw new RangeError('deploy failed');
        }
      },
      'repush_refused',
    );
    return back.ok;
  }

  async function rollBack(run: RunRow, head: KeyHead, kit: PlatformKit, fresh?: Fresh): Promise<Next> {
    const master = deps.master(head.platform);
    const old = run.genOld > 0 ? lendOrUndefined(run.keyref, run.genOld) : undefined;
    let held = 0;
    // Every receipt, `maybe` included: a push that threw or never answered may have changed the destination.
    for (const receipt of store.receipts(run.runId)) {
      if (await undo(run, head, receipt, old, master)) continue;
      held += 1;
      if (!receipt.rollbackNotified) noticeHeld(run, head, receipt);
    }
    if (held > 0) {
      const attempts = run.attempts + 1;
      store.update(run.runId, { attempts });
      later(run.runId, retryDelayMs(attempts - 1));
      return 'wait';
    }
    const created = store.gen(run.keyref, run.genNew);
    const id = created?.platformKeyId ?? fresh?.id ?? null;
    // A key the box did not make (pasted) has nothing to revoke here; one it made is revoked and confirmed before the run ends.
    if (id !== null) {
      const dead = await revokeAndConfirm({ kit, platform: head.platform, id, value: fresh?.value ?? lendOrUndefined(run.keyref, run.genNew), master });
      if (!dead) {
        const attempts = run.attempts + 1;
        store.update(run.runId, { attempts });
        later(run.runId, retryDelayMs(attempts - 1));
        return 'wait';
      }
    }
    if (created !== undefined) {
      store.setGenStatus(run.keyref, run.genNew, 'failed');
      deps.vault.retire(run.keyref, run.genNew);
    }
    store.update(run.runId, { state: 'failed' });
    return 'wait';
  }

  // --- starting ----------------------------------------------------------------------------------------------------------------------

  function start(input: StartInput): RunRow {
    const head = store.key(input.keyref);
    if (head === undefined || store.keyInfo(input.keyref) === undefined) throw new ApiError('not_found');
    const genOld = store.gens(input.keyref).find((g) => g.status === 'current')?.gen ?? 0;
    const genNew = store.topGen(input.keyref) + 1;
    const runId = `run_${hex(deps.random.bytes(8))}`;
    const withValue = input.value !== undefined;
    const run = store.openRun({ runId, keyref: input.keyref, state: withValue ? 'verifying' : 'issuing', genOld, genNew, intentName: intentName(input.keyref, genNew, runId), origin: input.origin });
    if (input.value !== undefined) {
      try {
        deps.vault.put(input.keyref, genNew, input.value);
        store.putGen({ keyref: input.keyref, gen: genNew, status: 'pending', platformKeyId: null, location: store.keyInfo(input.keyref)?.location ?? {} });
      } catch {
        store.update(runId, { state: 'failed', failedStep: 'issuing', reasonCode: 'store_failed' });
        deps.audit.append({ action: 'rotation.step_failed', subject: input.keyref, at: now(), detail: { run_id: runId, step: 'issuing', code: 'store_failed' } });
        throw new ApiError('unavailable');
      }
    }
    store.setStatus(input.keyref, 'rotating');
    deps.audit.append({ action: 'rotation.started', subject: input.keyref, at: now(), detail: { run_id: runId, origin: input.origin, gen: genNew } });
    launch(runId);
    return run;
  }

  async function idle(): Promise<void> {
    while (inflight.size > 0) await Promise.all([...inflight]);
  }

  return {
    start,
    async create(key, value) {
      deps.meta.putKey({
        keyref: key.keyref,
        platform: key.platform,
        name: key.name,
        projects: key.projects,
        class: key.class,
        status: 'rotating',
        gen_current: 1,
        schedule: { rotate_every_days: key.rotateEveryDays, grace_hours: key.graceHours, next_due_at: null, expires_at: null },
        coverage: null,
        last_use_at: null,
      });
      for (const d of key.destinations) deps.meta.putDestination(key.keyref, d);
      store.putKeyInfo(key.keyref, { scopeItems: key.scopeItems, location: key.location, rotatedAt: now(), markAdmin: key.markAdmin });
      start({ keyref: key.keyref, origin: 'create', ...(value === undefined ? {} : { value }) });
      await idle();
      return { status: store.key(key.keyref)?.status === 'works' ? 'works' : 'failed' };
    },
    async resume() {
      for (const run of store.activeRuns()) if (!storedNothing(run)) launch(run.runId);
      await idle();
    },
    retake(runId) {
      const old = store.run(runId);
      if (old === undefined) throw new ApiError('not_found');
      if (!storedNothing(old)) {
        launch(runId);
        return old;
      }
      store.update(runId, { state: 'abandoned' });
      const next = start({ keyref: old.keyref, origin: 'reconcile' });
      deps.audit.append({ action: 'rotation.restarted', subject: old.keyref, at: now(), detail: { old_run: runId, new_run: next.runId } });
      return next;
    },
    isLeased: (keyref) => leased.has(keyref),
    idle,
  };
}
