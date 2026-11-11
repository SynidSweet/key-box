// KBOX-51, KBOX-17, KBOX-16: the rotation orchestrator. A run is persisted step by step in meta.db and walked
// create -> store -> verify -> push -> redeploy -> check -> promote -> (grace) -> revoke -> confirm. The intent row is written before any
// platform call; a failure at steps 3 to 8 re-pushes the old generation, revokes and confirms the new one and sends ONE notice.
// A revoke is confirmed by the verifier (or the lister), never by its own answer. The old key is never revoked while a destination
// still holds the new one's replacement unconfirmed, and the new one is never revoked while a destination still holds it.
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { PushOutcome } from '../ports/destination.ts';
import type { EventLog } from '../ports/events.ts';
import type { IssuedKey } from '../ports/issuer.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { KeyClass, KeyLocation, Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { ApiError } from '../pure/errors.ts';
import { admitDestination, mintValue } from '../pure/class.ts';
import { intentName, nextStep, retryDelayMs } from '../pure/rotation-machine.ts';
import type { Step } from '../pure/rotation-machine.ts';
import { revokeAndConfirm } from './revoke-confirm.ts';
import { isPasteSource, overlapOf, setterOf } from './rotation-ports.ts';
import type { DestinationKit, PlatformKit, PlatformSource, Point } from './rotation-ports.ts';
import type { DestinationRow, KeyHead, Receipt, RotationStore, RunOrigin, RunRow } from './rotation-store.ts';

const HOUR_MS = 3600_000;
/** The destination kind that is a delivery to the workstation, not an adapter (KBOX-34). */
const WORKSTATION = 'workstation';
/** The receipt kind of an overlap:false platform taking the new value: its intent is written before the set, and a rollback sets the old one back. */
const PLATFORM_SET = 'platform_set';

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
  /**
   * Opens a run for the key and works on it in the background: `not_found` for no such key, `conflict` for a run already open, `rejected`
   * (`no_issuer`) for a run without a value on a paste-source platform (KBOX-34).
   */
  start(input: StartInput): RunRow;
  /**
   * Writes a key's rows and runs its first generation to the end. Answers the status the key ended in. Without a value the platform issues it;
   * `rejected` (`overlap_needs_paste`) for an `overlap: false` platform, whose keys are added by paste.
   */
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
  /**
   * Ends the process's work on runs for good: cancels every timer a run waits on (a grace, a retry) and starts nothing more. A drive in flight
   * finishes its step; `idle()` then resolves. The runs stay as persisted: the next start's `resume` takes them up.
   */
  stop(): void;
}

type Next = 'continue' | 'wait';
type Outcome = { readonly ok: true } | { readonly ok: false; readonly code: string };
interface Fresh {
  readonly id: string;
  readonly value: Lent;
}

/** The process stopped at a checkpoint (a test's crash): the drive ends there and recovery is the next start's. */
class Stopped extends Error {}

/** The names-only reason of a throw: an ApiError's detail code when it has one (`master_ambiguous`), else its code; anything else `internal`. */
const codeOf = (error: unknown): string => {
  if (!(error instanceof ApiError)) return 'internal';
  return error.detail !== undefined && 'code' in error.detail ? error.detail.code : error.code;
};
const underscored = (kind: string): string => kind.replace(/[^a-z0-9]+/g, '_');
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

export function createOrchestrator(deps: OrchestratorDeps): Orchestrator {
  const { store } = deps;
  const leased = new Set<string>();
  const inflight = new Set<Promise<void>>();
  const timers = new Map<string, () => void>();
  let stopped = false;

  /** Throws of one run's drive since it last went through cleanly: the retry after a fault backs off like any other (S-249). */
  const faults = new Map<string, number>();

  const now = (): number => deps.clock.now();
  /** A checkpoint that throws is the process stopping there (a test): nothing more happens in this process. */
  const point = async (p: Point): Promise<void> => {
    try {
      await deps.checkpoint?.(p);
    } catch (cause: unknown) {
      throw new Stopped(p, { cause });
    }
  };

  // --- running a run ----------------------------------------------------------------------------------------------------

  const launch = (runId: string): void => {
    if (stopped) return;
    const job: Promise<void> = drive(runId).catch((error: unknown) => {
      deps.audit.append({ action: 'rotation.drive_failed', subject: runId, at: now(), detail: { run_id: runId, code: error instanceof Stopped ? 'stopped' : codeOf(error) } });
      recover(runId, error);
    });
    inflight.add(job);
    void job.finally(() => inflight.delete(job));
  };

  /**
   * A throw outside `attempt()` (the master key unreadable, the store refusing a write) is never silent (review M2): launch audits it, a retry
   * timer is kept, and the run gets its one notice: before promote the run fails and rolls back (`rotation.failed`); from promote on, the new
   * key works and the old one stays on (`rotation.old_key_still_on`); while rolling back, the failure's notice was already sent.
   */
  function recover(runId: string, error: unknown): void {
    if (error instanceof Stopped) return;
    const count = (faults.get(runId) ?? 0) + 1;
    faults.set(runId, count);
    later(runId, retryDelayMs(count - 1));
    try {
      const run = store.run(runId);
      if (run !== undefined) noticeStuck(run, codeOf(error));
    } catch {
      // The store refused even this: the timer above tries the whole run again; the audit says so.
      deps.audit.append({ action: 'rotation.drive_failed', subject: runId, at: now(), detail: { run_id: runId, code: 'notice_failed' } });
    }
  }

  function noticeStuck(run: RunRow, code: string): void {
    switch (run.state) {
      case 'issuing':
      case 'verifying':
      case 'pushing':
      case 'redeploying':
      case 'checking':
        if (!run.failedNotified) markFailed(run, store.key(run.keyref), run.state, code);
        return;
      case 'promoting':
      case 'grace':
      case 'revoking':
        noticeStillOn(run);
        return;
      case 'rolling_back':
      case 'done':
      case 'failed':
      case 'abandoned':
        return;
    }
  }

  const later = (runId: string, ms: number): void => {
    if (stopped) return;
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
        if (run === undefined || run.state === 'done' || run.state === 'failed' || run.state === 'abandoned' || (await step(run)) === 'wait') {
          faults.delete(runId);
          return;
        }
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

  async function step(run: RunRow): Promise<Next> {
    const head = store.key(run.keyref);
    const info = store.keyInfo(run.keyref);
    const kit = head === undefined ? undefined : deps.platform(head.platform);
    if (head === undefined || info === undefined || kit === undefined) return fail(run, run.state === 'rolling_back' ? 'rollback' : run.state, 'no_adapter');
    switch (run.state) {
      case 'issuing':
        return overlapOf(kit) ? issue(run, head, kit) : setNew(run, head, kit);
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

  const auditStepFailed = (run: RunRow, stepName: string, code: string): void =>
    deps.audit.append({ action: 'rotation.step_failed', subject: run.keyref, at: now(), detail: { run_id: run.runId, step: stepName, code } });

  async function attempt(run: RunRow, stepName: string, work: () => Promise<void>, code: string): Promise<Outcome> {
    try {
      await work();
      return { ok: true };
    } catch (error: unknown) {
      // The process stopping (a test) is not a failed step: the drive ends there.
      if (error instanceof Stopped) throw error;
      auditStepFailed(run, stepName, code);
      return { ok: false, code };
    }
  }

  /** A push as an outcome: one that threw or timed out is `unknown`, because it may have applied before it failed to answer. */
  async function pushed(call: () => Promise<PushOutcome>): Promise<PushOutcome> {
    try {
      return await call();
    } catch {
      return { outcome: 'unknown' };
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

  /** The master for the key's platform: its own project's preferred (review N5). Throws when there is none or the source cannot choose. */
  const masterOf = (head: KeyHead): Lent => deps.master(head.platform, head.projects);
  /** The master as a result, before a platform call: a run that cannot have one fails naming why (`master_ambiguous`, `no_master`). */
  const masterFor = (head: KeyHead): { readonly ok: true; readonly value: Lent } | { readonly ok: false; readonly code: string } => {
    try {
      return { ok: true, value: masterOf(head) };
    } catch (error: unknown) {
      return { ok: false, code: error instanceof ApiError ? codeOf(error) : 'no_master' };
    }
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
    const master = masterFor(head);
    if (!master.ok) return fail(run, 'issuing', master.code);
    const made: { issued?: IssuedKey } = {};
    const created = await attempt(
      run,
      'issuing',
      async () => {
        made.issued = await issuer.issue({ scope: { items: info.scopeItems } }, run.intentName, master.value);
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

  /**
   * overlap:false (design §5.2: "set new"): the box chooses the value and stores it as generation N+1 BEFORE any platform call, so it is never
   * lost; then the platform takes it and stops taking the old one. The set's intent receipt is written first: a rollback sets the old value
   * back at the platform whatever the set answered. A generation stored before a restart is set again (the set is safe to repeat).
   */
  async function setNew(run: RunRow, head: KeyHead, kit: PlatformKit): Promise<Next> {
    const set = setterOf(kit.issuer);
    const info = store.keyInfo(run.keyref);
    const shape = kit.issuer?.capabilities().shape;
    if (set === undefined || info === undefined || shape === undefined) return fail(run, 'issuing', 'overlap_needs_set');
    if (storedNothing(run)) {
      const stored = await attempt(
        run,
        'issuing',
        () => {
          const bytes = Buffer.from(mintValue(shape, (n) => deps.random.bytes(n)), 'utf8');
          try {
            deps.vault.put(run.keyref, run.genNew, bytes);
          } finally {
            bytes.fill(0);
          }
          store.putGen({ keyref: run.keyref, gen: run.genNew, status: 'pending', platformKeyId: null, location: info.location });
          return Promise.resolve();
        },
        'store_failed',
      );
      if (!stored.ok) return fail(run, 'issuing', 'store_failed');
      await point('stored');
    }
    const value = lendOrUndefined(run.keyref, run.genNew);
    if (value === undefined) return fail(run, 'issuing', 'store_failed');
    const master = masterFor(head);
    if (!master.ok) return fail(run, 'issuing', master.code);
    store.intendPush(run.runId, PLATFORM_SET, head.platform);
    const taken = await attempt(run, 'issuing', () => set(value, info.location, master.value), 'set_failed');
    if (!taken.ok) return fail(run, 'issuing', 'set_failed');
    await point('taken');
    store.putReceipt(run.runId, PLATFORM_SET, head.platform, { pushed: true });
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
    const master = masterOf(head);
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
      const alone = store.intendPush(run.runId, row.kind, row.target);
      const result = await pushed(() => kit.destination.push(target, head.name, value, master));
      if (result.outcome !== 'applied') {
        auditStepFailed(run, 'pushing', 'push_failed');
        // Only a refusal of the one push that could have applied proves the destination holds nothing; any other answer leaves the intent (`maybe`).
        if (result.outcome === 'refused' && alone) store.putReceipt(run.runId, row.kind, row.target, { pushed: 'refused' });
        return fail(run, 'pushing', 'push_failed');
      }
      await point('pushed');
      store.putReceipt(run.runId, row.kind, row.target, { version: result.version, pushed: true });
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
    const master = masterOf(head);
    for (const row of store.destinationsOf(run.keyref)) {
      const kit = row.kind === WORKSTATION ? undefined : kitFor(row);
      if (kit?.redeployer === undefined || !kit.destination.properties().needsRedeploy) continue;
      const redeployer = kit.redeployer;
      const target = { kind: kit.destination.kind, id: row.target };
      // The intent first (review N1): from here the destination may run the new value, whether the redeploy answers, throws or the process dies.
      store.intendRedeploy(run.runId, row.kind, row.target);
      const ready = await attempt(
        run,
        'redeploying',
        async () => {
          const ref = await redeployer.redeploy(target, master);
          await point('redeployed');
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
      const dead = await revokeAndConfirm({ kit, platform: head.platform, id: old?.platformKeyId ?? null, at: old?.location ?? {}, value: lendOrUndefined(run.keyref, run.genOld), master: masterOf(head) });
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
    noticeStillOn(run);
    later(run.runId, retryDelayMs(attempts - 1));
    return 'wait';
  }

  /** The run's one `rotation.old_key_still_on` notice, recorded before it goes out. A create run has no old key to keep on, so it sends none. */
  function noticeStillOn(run: RunRow): void {
    if (run.stillOnNotified || run.genOld === 0) return;
    store.update(run.runId, { stillOnNotified: true });
    deps.events.append('rotation.old_key_still_on', { run_id: run.runId, keyref: run.keyref, gen: run.genOld });
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
    const failed = store.update(run.runId, { state: 'rolling_back', failedStep: step, reasonCode: code, failedNotified: true, failedAt: now() });
    if (!run.failedNotified) noticeFailed(run, head, step, code);
    if (head !== undefined) store.setStatus(run.keyref, 'failed');
    return failed;
  }

  const settleFailed = (run: RunRow): Next => {
    store.update(run.runId, { state: 'failed' });
    return 'wait';
  };

  /**
   * KBOX-17's one notice per failed run: a `rotation.failed` event (mission control raises the desk card) for every class, and a Web Push
   * for admin and master keys. A create run has no old generation, so its event says `old_key_works: false` and its push claims no old key.
   */
  function noticeFailed(run: RunRow, head: KeyHead | undefined, step: string, code: string): void {
    const pushed = head !== undefined && head.class !== 'ordinary';
    const oldKeyWorks = run.genOld > 0;
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step, reason_code: code, old_key_works: oldKeyWorks });
    if (pushed) deps.push.send({ title: oldKeyWorks ? `The key change of ${run.keyref} failed; the old key still works` : `Adding the key ${run.keyref} failed`, kind: 'rotation_failed' });
  }

  /** The second notice KBOX-17 allows, named for the one destination that would not take the rollback. */
  function noticeHeld(run: RunRow, head: KeyHead, receipt: Receipt): void {
    const oldKeyWorks = run.genOld > 0;
    const code = oldKeyWorks ? 'repush_refused' : 'remove_refused';
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step: `rollback_${underscored(receipt.kind)}`, reason_code: code, old_key_works: oldKeyWorks });
    if (head.class !== 'ordinary') {
      deps.push.send({ title: oldKeyWorks ? `The old key of ${run.keyref} could not be put back in ${receipt.target}` : `The new key of ${run.keyref} could not be removed from ${receipt.target}`, kind: 'rotation_failed' });
    }
    store.putReceipt(run.runId, receipt.kind, receipt.target, { rollbackNotified: true });
  }

  /**
   * Undoes the run at one destination: the old value pushed back (and redeployed where it was), or, for a create run, the new value removed.
   * False while the destination holds (or may hold) the new value.
   */
  async function undo(run: RunRow, head: KeyHead, receipt: Receipt, old: Lent | undefined, master: Lent): Promise<boolean> {
    // The destination answered that it applied nothing: there is nothing to put back and nothing it holds.
    if (receipt.pushed === 'refused') return true;
    if (receipt.kind === PLATFORM_SET) {
      // overlap:false: the platform took the new value and dropped the old one; it takes the old one back, which the vault still holds. A
      // first generation has no old value to set, so the platform keeps the new one and the run holds (the value stays in the vault).
      const set = setterOf(deps.platform(head.platform)?.issuer);
      if (set === undefined || old === undefined) return false;
      return (await attempt(run, 'rollback', () => set(old, store.keyInfo(run.keyref)?.location ?? {}, master), 'reset_refused')).ok;
    }
    const dk = deps.destination(receipt.kind);
    if (dk === undefined) return false;
    const target = { kind: dk.destination.kind, id: receipt.target };
    if (run.genOld === 0) {
      // The receipt is the removal's intent: it stays until the run ends, so a removal that threw or a crash after it is removed again.
      const removed = (await attempt(run, 'rollback', () => dk.destination.remove(target, head.name, master), 'remove_refused')).ok;
      if (removed) await point('removed');
      return removed;
    }
    if (old === undefined) return false;
    const back = await attempt(
      run,
      'rollback',
      async () => {
        // Only an applied push puts the old value back; a refusal or a timeout leaves the destination possibly holding the new one.
        if ((await dk.destination.push(target, head.name, old, master)).outcome !== 'applied') throw new RangeError('re-push not applied');
        // Wherever a redeploy was intended, a deploy may run the new value: the old one is deployed and ready before the new key is revoked.
        if (receipt.redeployIntended && dk.redeployer !== undefined) {
          const ref = await dk.redeployer.redeploy(target, master);
          if ((await dk.redeployer.ready(ref)) !== 'ready') throw new RangeError('deploy failed');
        }
      },
      'repush_refused',
    );
    return back.ok;
  }

  async function rollBack(run: RunRow, head: KeyHead, kit: PlatformKit, fresh?: Fresh): Promise<Next> {
    const master = masterOf(head);
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
      const dead = await revokeAndConfirm({ kit, platform: head.platform, id, at: created?.location ?? store.keyInfo(run.keyref)?.location ?? {}, value: fresh?.value ?? lendOrUndefined(run.keyref, run.genNew), master });
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
    // KBOX-34: a paste-source platform cannot issue; its keys change only by a paste (a value), never by an api run.
    if (input.value === undefined && isPasteSource(deps, head.platform)) throw new ApiError('rejected', 'no_issuer');
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
        store.update(runId, { state: 'failed', failedStep: 'issuing', reasonCode: 'store_failed', failedAt: now() });
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
      // A platform that holds one credential is never created by a run: a failed run would have no old value to set back (the owner's law:
      // a failed rotation keeps the old key working). The key is added by paste and then rotated.
      if (value === undefined && !overlapOf(deps.platform(key.platform))) throw new ApiError('rejected', 'overlap_needs_paste');
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
    stop() {
      stopped = true;
      for (const cancel of timers.values()) cancel();
      timers.clear();
    },
  };
}
