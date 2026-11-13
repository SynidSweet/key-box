// KBOX-51, KBOX-17, KBOX-16: the rotation orchestrator. A run is persisted step by step in meta.db and walked
// create -> store -> verify -> push -> redeploy -> check -> promote -> (grace) -> revoke -> confirm. The intent row is written before any
// platform call; a failure at steps 3 to 8 re-pushes the old generation, revokes and confirms the new one and sends ONE notice.
// A revoke is confirmed by the verifier (or the lister), never by its own answer. The old key is never revoked while a destination
// still holds the new one's replacement unconfirmed, and the new one is never revoked while a destination still holds it.
// KBOX-55: a key the box makes itself (its kit has `boxKey`) takes its own path, chosen before anything asks for a master: draw and store
// (pending, published at once), check it opens, wait the publish lead, prove the platform took it, switch, grace, delete the old value.
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { DestinationKit, PushOutcome } from '../ports/destination.ts';
import type { EventLog } from '../ports/events.ts';
import type { IssuedKey } from '../ports/issuer.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { MintedSink } from '../ports/minted.ts';
import type { BoxIdentity, BoxMadeKey } from '../ports/platform.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { KeyClass, KeyLocation, Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { ApiError } from '../pure/errors.ts';
import { admitDestination, mintValue } from '../pure/class.ts';
import { sameLocation } from '../pure/location.ts';
import { ownerEndsLine } from '../pure/words.ts';
import { afterProof, intentName, nextStep, retryDelayMs } from '../pure/rotation-machine.ts';
import type { KeyMachine, ProofVerdict, Step } from '../pure/rotation-machine.ts';
import type { DeletionDriver } from './delete-run.ts';
import { confirmRevoked, enderOf, revokeAndConfirm } from './revoke-confirm.ts';
import type { Ender, RevokeTarget } from './revoke-confirm.ts';
import { isPasteSource, kindOfStored, kitFor, overlapOf, setterOf, storedPlacement, tryLend, verifierFor, verifyTargetOf } from './rotation-ports.ts';
import type { MasterResult, PlatformKit, PlatformSource, Point } from './rotation-ports.ts';
import type { DestinationRow, KeyHead, KeyInfo, Receipt, RotationStore, RunOrigin, RunRow } from './rotation-store.ts';

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
  /** The verify hint the paste chose (KBOX-40), stored with the key before its first verification. */
  readonly verifyHint?: string;
}

export interface StartInput {
  readonly keyref: string;
  readonly origin: RunOrigin;
  /** A value pasted on the phone (KBOX-12): the run starts at verify, the platform is not asked to issue. */
  readonly value?: Uint8Array;
  /** The verify hint the paste chose (KBOX-40), stored once the run is accepted; a run without one keeps the stored choice. */
  readonly verifyHint?: string;
}

/** KBOX-55: what a box-made key's proof is made with: the box's own identity and the scanner's sink for what the proof buys. */
export interface Federation {
  readonly identity: BoxIdentity;
  readonly minted: MintedSink;
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
  /** KBOX-55: none while the box has no identity (no domain or no audience): a box-made key's run then fails `identity_unconfigured`. */
  readonly federation?: Federation;
  /** Where a test stops the process; production passes none. */
  readonly checkpoint?: (point: Point) => void | Promise<void>;
  /** KBOX-62: what a step of a deletion's run (origin `delete`) does; none: such a run throws (`internal`) and is retried. */
  readonly deletion?: DeletionDriver;
}

export interface Orchestrator {
  /**
   * Opens a run for the key and works on it in the background: `not_found` for no such key, `conflict` for a run already open, `rejected`
   * with a location code for a stored location the entry now refuses (KBOX-57), `rejected` (`no_issuer`) for a run without a value on a
   * paste-source platform (KBOX-34).
   */
  start(input: StartInput): RunRow;
  /**
   * Writes a key's rows and runs its first generation to the end. Answers the status the key ended in. Without a value the platform issues it;
   * `rejected` (`overlap_needs_paste`) for an `overlap: false` platform, whose keys are added by paste; `conflict` (`key_exists`) before any
   * write for a reference a `keys` or `rotation_keys` row holds (KBOX-57).
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
  /** KBOX-62: works on a run opened elsewhere (a deletion's) in the background, as `start` does its own. */
  launch(runId: string): void;
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
  /** Where the platform says it made the key (KBOX-57): what a revoke of it is confirmed against. */
  readonly at: KeyLocation;
}

/** The process stopped at a checkpoint (a test's crash): the drive ends there and recovery is the next start's. */
class Stopped extends Error {}

/** The names-only reason of a throw: an ApiError's detail code when it has one, else its code; anything else `internal`. */
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
  const advance = async (run: RunRow, done: Step, patch: { readonly waitUntil?: number } = {}): Promise<Next> => {
    const state = nextStep(done, machineOf(kitOf(run.keyref)));
    store.update(run.runId, { state: state === 'done' ? 'done' : state, ...patch });
    await point(done);
    return 'continue';
  };

  const kitOf = (keyref: string): PlatformKit | undefined => {
    const head = store.key(keyref);
    return head === undefined ? undefined : kitFor(deps, head);
  };

  /** The steps a key's kit walks (KBOX-55: a box-made key has no push and no redeploy). */
  const machineOf = (kit: PlatformKit | undefined): KeyMachine => ({ overlap: overlapOf(kit), boxMade: kit?.boxKey !== undefined });

  async function step(run: RunRow): Promise<Next> {
    if (run.origin === 'delete') {
      if (deps.deletion === undefined) throw new ApiError('internal');
      return deps.deletion.step(run, { later: (ms) => later(run.runId, ms), point });
    }
    const head = store.key(run.keyref);
    const info = store.keyInfo(run.keyref);
    const kit = head === undefined ? undefined : kitFor(deps, head);
    if (head === undefined || info === undefined || kit === undefined) return fail(run, run.state === 'rolling_back' ? 'rollback' : run.state, 'no_adapter');
    // KBOX-55: chosen before any step can ask for a master (a second master of the platform would make every ask `master_ambiguous`).
    if (kit.boxKey !== undefined) return boxStep(run, head, info, kit.boxKey);
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

  const lendOrUndefined = (keyref: string, gen: number): Lent | undefined => {
    const lent = tryLend(deps.vault, keyref, gen);
    return lent.ok ? lent.value : undefined;
  };

  /**
   * KBOX-57: the master for the key, chosen by its platform, its stored location and its stored scope items (never its projects): a step that
   * finds none or two fails naming why (`no_master`, `master_ambiguous`). A key with no stored record has no master to choose.
   */
  const masterFor = (head: KeyHead): MasterResult => {
    const info = store.keyInfo(head.keyref);
    return info === undefined ? { ok: false, code: 'no_master' } : deps.master(head.platform, info.location, info.scopeItems);
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
        made.issued = await issuer.issue({ scope: { items: info.scopeItems }, at: info.location }, run.intentName, master.value);
      },
      'issue_failed',
    );
    const issued = made.issued;
    if (!created.ok || issued === undefined) return fail(run, 'issuing', 'issue_failed');
    await point('issued');
    // KBOX-57: a platform that says it made the key anywhere but the stored location fails the run; the key is revoked where it says it is.
    const at = issued.location ?? info.location;
    if (!sameLocation(at, info.location)) return fail(run, 'issuing', 'location_mismatch', { id: issued.platformKeyId, value: issued.value, at });
    const stored = await attempt(
      run,
      'issuing',
      async () => {
        await issued.value.use((bytes) => {
          deps.vault.put(run.keyref, run.genNew, bytes);
          return Promise.resolve();
        });
        store.putGen({ keyref: run.keyref, gen: run.genNew, status: 'pending', platformKeyId: issued.platformKeyId, location: at });
      },
      'store_failed',
    );
    if (!stored.ok) return fail(run, 'issuing', 'store_failed', { id: issued.platformKeyId, value: issued.value, at });
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

  /** KBOX-58: the verifier that applies to the key by its stored scope and location; none applies, the step passes. */
  async function verifyNew(run: RunRow, head: KeyHead, kit: PlatformKit, stepName: 'verifying' | 'checking', word: 'verify' | 'check'): Promise<Next> {
    const verifier = verifierFor(kit, kindOfStored(store.keyInfo(run.keyref)));
    if (verifier !== undefined) {
      // KBOX-58: a verifier that needs the master gets the one chosen now, before the value is lent (a restart between steps resolves afresh).
      const chosen = verifier.needsMaster === true ? masterFor(head) : undefined;
      if (chosen !== undefined && !chosen.ok) return fail(run, stepName, chosen.code);
      const value = lendOrUndefined(run.keyref, run.genNew);
      if (value === undefined) return fail(run, stepName, `${word}_failed`);
      const at = store.gen(run.keyref, run.genNew)?.location ?? store.keyInfo(run.keyref)?.location ?? {};
      const asked = verifyTargetOf(verifier, { platform: head.platform, at, ...hintOf(run.keyref) }, chosen?.ok === true ? chosen.value : undefined);
      const verdict = await attempt0(() => verifier.verify(value, asked));
      if (verdict !== 'ok') return fail(run, stepName, verdict === 'rejected' ? `${word}_rejected` : `${word}_unreachable`);
    }
    return advance(run, stepName);
  }

  /** The key's stored scope items (KBOX-58: with the location, what decides whether a verifier applies); none stored is none. */
  const scopeItemsOf = (keyref: string): readonly string[] => store.keyInfo(keyref)?.scopeItems ?? [];

  /** The key's stored verify hint as a `VerifyTarget`/`RevokeTarget` member (KBOX-40), or nothing. */
  function hintOf(keyref: string): { readonly hint?: string } {
    const hint = store.keyInfo(keyref)?.verifyHint;
    return hint === undefined ? {} : { hint };
  }

  async function attempt0<T extends 'ok' | 'rejected' | 'unreachable'>(call: () => Promise<T>): Promise<T | 'unreachable'> {
    try {
      return await call();
    } catch {
      return 'unreachable';
    }
  }

  // --- steps 6 and 7: push and redeploy ---------------------------------------------------------------------------------------------

  const destinationKitOf = (row: DestinationRow): DestinationKit | undefined => deps.destination(row.kind);

  async function pushAll(run: RunRow, head: KeyHead): Promise<Next> {
    const chosen = masterFor(head);
    if (!chosen.ok) return fail(run, 'pushing', chosen.code);
    const master = chosen.value;
    const value = lendOrUndefined(run.keyref, run.genNew);
    if (value === undefined) return fail(run, 'pushing', 'push_failed');
    const rows = store.destinationsOf(run.keyref);
    // KBOX-16: every destination is admitted again before anything is pushed, because its properties can change at runtime. The workstation is
    // a delivery that a control token fetches through the API, so it is `api`-readable: an ordinary key only (KBOX-34).
    for (const row of rows) {
      const readableBy = row.kind === WORKSTATION ? 'api' : destinationKitOf(row)?.destination.properties().readableBy;
      if (readableBy === undefined) return fail(run, 'pushing', 'push_failed');
      if (!admitDestination(head.class, readableBy)) return fail(run, 'pushing', 'destination_not_allowed');
    }
    for (const row of rows) {
      // The workstation is offered at promote (deliver), never a generation that may still be rolled back.
      if (row.kind === WORKSTATION) continue;
      const kit = destinationKitOf(row);
      if (kit === undefined) return fail(run, 'pushing', 'push_failed');
      const target = { kind: kit.destination.kind, id: row.target };
      // The intent first: from here the destination may hold the new value, whether the push answers, throws or the process dies.
      const alone = store.intendPush(run.runId, row.kind, row.target);
      const result = await pushed(() => kit.destination.push(target, head.name, value, head.class, master));
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
    const chosen = masterFor(head);
    if (!chosen.ok) return fail(run, 'redeploying', chosen.code);
    const master = chosen.value;
    for (const row of store.destinationsOf(run.keyref)) {
      const kit = row.kind === WORKSTATION ? undefined : destinationKitOf(row);
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
          if ((await redeployer.ready(ref, master)) !== 'ready') throw new RangeError('deploy failed');
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
    return advance(run, 'promoting', { waitUntil: now() + (overlap && run.genOld > 0 ? head.graceHours * HOUR_MS : 0) });
  }

  async function graceWait(run: RunRow): Promise<Next> {
    const at = run.waitUntil ?? now();
    if (now() < at) {
      later(run.runId, at - now());
      return 'wait';
    }
    return advance(run, 'grace');
  }

  // --- step 10: end the old key and hear the platform's word ------------------------------------------------------------------------

  /**
   * KBOX-51 step 10 as amended: ends the key where the box can, then true once the platform's word says it no longer works, or once its proven
   * revoked evidence (KBOX-62) says revoked. A listing may be used: the target is never a master's own current generation.
   */
  const endedAtPlatform = async (target: RevokeTarget): Promise<boolean> => (await revokeAndConfirm(target)) || (await confirmRevoked(target, true));

  async function revokeOld(run: RunRow, head: KeyHead, kit: PlatformKit): Promise<Next> {
    if (run.genOld > 0) {
      const old = store.gen(run.keyref, run.genOld);
      const id = old?.platformKeyId ?? null;
      // Step 10 without a master to end the old key with: not proven dead, so the old key stays in grace and the step retries (one notice).
      const master = masterFor(head);
      if (!master.ok) return retryRevoke(run, head, enderOf(kit, id));
      const ended = await endedAtPlatform({ kit, platform: head.platform, id, at: old?.location ?? {}, scopeItems: scopeItemsOf(run.keyref), value: lendOrUndefined(run.keyref, run.genOld), master: master.value, ...hintOf(run.keyref) });
      if (!ended) return retryRevoke(run, head, enderOf(kit, id));
      // The platform's word ends the run and marks nothing dead: N stays grace, its value kept and watched, until the proof watch proves it.
    }
    deps.audit.append({ action: 'rotation.completed', subject: run.keyref, at: now(), detail: { run_id: run.runId, gen: run.genNew } });
    return advance(run, 'revoking');
  }

  /**
   * Not proven dead: the old key stays in grace, one notice, retried with backoff (S-249; 1 minute doubling to 1 hour). Where only the owner can
   * end it (`owner_ends`) the notice says so in the box's words and the audit row names the reason.
   */
  function retryRevoke(run: RunRow, head: KeyHead, ender: Ender): Next {
    const attempts = run.attempts + 1;
    store.update(run.runId, { attempts });
    const reason = ender === 'owner' ? { reason: 'owner_ends' } : {};
    // A stall of a key the box ends itself (an issuer) is one audit row per run: its retries, hourly at the cap, add nothing the first did not say.
    if (ender !== 'issuer' || attempts === 1) deps.audit.append({ action: 'rotation.revoke_unconfirmed', subject: run.keyref, at: now(), detail: { run_id: run.runId, gen: run.genOld, attempt: attempts, ...reason } });
    noticeStillOn(run, ender === 'owner' ? head : undefined);
    later(run.runId, retryDelayMs(attempts - 1));
    return 'wait';
  }

  /**
   * The run's one `rotation.old_key_still_on` notice, recorded before it goes out. A create run has no old key to keep on, so it sends none; a
   * deletion's run (KBOX-62) sends it for the key's current generation, which it was ending when its step threw.
   * `ownerEnds` is the key's head when the owner must end the old key: an admin or master key then also sends the phone the words (KBOX-17).
   */
  function noticeStillOn(run: RunRow, ownerEnds?: KeyHead): void {
    const deleting = run.origin === 'delete';
    if (run.stillOnNotified || (run.genOld === 0 && !deleting)) return;
    store.update(run.runId, { stillOnNotified: true });
    deps.events.append('rotation.old_key_still_on', { run_id: run.runId, keyref: run.keyref, gen: deleting ? run.genNew : run.genOld });
    if (ownerEnds !== undefined && ownerEnds.class !== 'ordinary') deps.push.send({ title: ownerEndsLine(ownerEnds.platform), kind: 'rotation_owner_ends' });
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
   * for admin and master keys. `old_key_works` is the fact when the notice goes out (spec `rotation.failed`): false for a create run, which has
   * no old generation, and for an overlap:false run whose platform may hold only the new value, since the set back has not been done yet.
   */
  function noticeFailed(run: RunRow, head: KeyHead | undefined, step: string, code: string): void {
    const pushed = head !== undefined && head.class !== 'ordinary';
    const oldKeyWorks = run.genOld > 0 && !platformMayHoldNew(run);
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step, reason_code: code, old_key_works: oldKeyWorks });
    if (pushed) deps.push.send({ title: failedTitle(run, oldKeyWorks), kind: 'rotation_failed' });
  }

  const failedTitle = (run: RunRow, oldKeyWorks: boolean): string => {
    if (run.genOld === 0) return `Adding the key ${run.keyref} failed`;
    return oldKeyWorks ? `The key change of ${run.keyref} failed; the old key still works` : `The key change of ${run.keyref} failed; the old key is being put back`;
  };

  /** An overlap:false platform was asked to take the new value in this run (the set's intent, not refused): until it is set back, it may hold only the new one. */
  const platformMayHoldNew = (run: RunRow): boolean => store.receipts(run.runId).some((r) => r.kind === PLATFORM_SET && r.pushed !== 'refused');

  /**
   * The second notice KBOX-17 allows, named for the one destination that would not take the rollback. `oldKeyWorks` is the fact now: false
   * while an overlap:false platform has not taken the old value back (review N7).
   */
  function noticeHeld(run: RunRow, head: KeyHead, receipt: Receipt, oldKeyWorks: boolean): void {
    const created = run.genOld === 0;
    const code = created ? 'remove_refused' : 'repush_refused';
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step: `rollback_${underscored(receipt.kind)}`, reason_code: code, old_key_works: oldKeyWorks });
    if (head.class !== 'ordinary') {
      deps.push.send({ title: created ? `The new key of ${run.keyref} could not be removed from ${receipt.target}` : `The old key of ${run.keyref} could not be put back in ${receipt.target}`, kind: 'rotation_failed' });
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
      const set = setterOf(kitFor(deps, head)?.issuer);
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
        if ((await dk.destination.push(target, head.name, old, head.class, master)).outcome !== 'applied') throw new RangeError('re-push not applied');
        // Wherever a redeploy was intended, a deploy may run the new value: the old one is deployed and ready before the new key is revoked.
        if (receipt.redeployIntended && dk.redeployer !== undefined) {
          const ref = await dk.redeployer.redeploy(target, master);
          if ((await dk.redeployer.ready(ref, master)) !== 'ready') throw new RangeError('deploy failed');
        }
      },
      'repush_refused',
    );
    return back.ok;
  }

  /** The rollback is not done: it is tried again with backoff (S-249); the run's one notice was already sent. */
  function rollBackLater(run: RunRow): Next {
    const attempts = run.attempts + 1;
    store.update(run.runId, { attempts });
    later(run.runId, retryDelayMs(attempts - 1));
    return 'wait';
  }

  /**
   * Puts every destination back and ends a new key the box made, with the master: true when all is undone, false while something still holds
   * (or may hold) the new value or the new key is not proven dead.
   */
  async function undoEverywhere(run: RunRow, head: KeyHead, kit: PlatformKit, master: Lent, receipts: readonly Receipt[], id: string | null, fresh: Fresh | undefined): Promise<boolean> {
    const old = run.genOld > 0 ? lendOrUndefined(run.keyref, run.genOld) : undefined;
    let held = 0;
    // Every receipt, `maybe` included: a push that threw or never answered may have changed the destination. An overlap:false platform takes
    // the old value back first: until it has, the old key works nowhere, and every card of this pass says so (review N7).
    let oldKeyWorks = run.genOld > 0;
    for (const receipt of [...receipts.filter((r) => r.kind === PLATFORM_SET), ...receipts.filter((r) => r.kind !== PLATFORM_SET)]) {
      const undone = await undo(run, head, receipt, old, master);
      if (receipt.kind === PLATFORM_SET && !undone) oldKeyWorks = false;
      if (undone) continue;
      held += 1;
      if (!receipt.rollbackNotified) noticeHeld(run, head, receipt, oldKeyWorks);
    }
    if (held > 0) return false;
    // A key the box did not make (pasted) has nothing to revoke here; one it made is ended and the platform heard before the run ends.
    if (id === null) return true;
    const created = store.gen(run.keyref, run.genNew);
    return endedAtPlatform({ kit, platform: head.platform, id, at: created?.location ?? fresh?.at ?? store.keyInfo(run.keyref)?.location ?? {}, scopeItems: scopeItemsOf(run.keyref), value: fresh?.value ?? lendOrUndefined(run.keyref, run.genNew), master, ...hintOf(run.keyref) });
  }

  async function rollBack(run: RunRow, head: KeyHead, kit: PlatformKit, fresh?: Fresh): Promise<Next> {
    // KBOX-55: a box-made key's rollback asks for no master: nothing was pushed or issued at a platform.
    if (kit.boxKey !== undefined) return boxRollBack(run);
    const receipts = store.receipts(run.runId);
    const created = store.gen(run.keyref, run.genNew);
    const id = created?.platformKeyId ?? fresh?.id ?? null;
    // KBOX-57: the master is needed only to undo something at a destination or at the platform; a run that failed before it changed anything
    // (no master at its first step) ends at once. Without one when it is needed, the rollback waits and retries (no second notice).
    if (receipts.some((r) => r.pushed !== 'refused') || id !== null) {
      const chosen = masterFor(head);
      if (!chosen.ok) {
        auditStepFailed(run, 'rollback', chosen.code);
        return rollBackLater(run);
      }
      if (!(await undoEverywhere(run, head, kit, chosen.value, receipts, id, fresh))) return rollBackLater(run);
    }
    // KBOX-17 as amended: a new key the platform issued may still work there, so it stays grace (watched) until the proof watch proves it
    // revoked; one it never issued (a pasted value, an overlap:false set) is failed and its value deleted.
    if (created !== undefined && id !== null) store.setGenStatus(run.keyref, run.genNew, 'grace');
    else if (created !== undefined) {
      store.setGenStatus(run.keyref, run.genNew, 'failed');
      deps.vault.retire(run.keyref, run.genNew);
    }
    store.update(run.runId, { state: 'failed' });
    return 'wait';
  }

  // --- KBOX-55: a key the box makes itself -------------------------------------------------------------------------------------------

  /**
   * A run of a box-made key: no platform makes, lists or revokes it, it has no destination, and no step asks for a master (not in rollback,
   * revoking or promote). Publish, wait, prove, switch: the new generation is pending (published) from `issuing`, the run waits the publish
   * lead from `verifying`, and `gen_current` moves only after the platform has taken an assertion signed with it.
   */
  async function boxStep(run: RunRow, head: KeyHead, info: KeyInfo, box: BoxMadeKey): Promise<Next> {
    switch (run.state) {
      case 'issuing':
        return boxIssue(run, info, box);
      case 'verifying':
        return boxVerify(run, box);
      case 'checking':
        return boxCheck(run, box);
      case 'promoting':
        return boxPromote(run, head);
      case 'grace':
        return graceWait(run);
      case 'revoking':
        return boxRevoke(run);
      case 'rolling_back':
        return boxRollBack(run);
      case 'pushing':
      case 'redeploying':
        // Never a step of a box-made key (`stepsFor`): a run found here was not written by this path.
        return fail(run, run.state, 'not_a_box_step');
      case 'done':
      case 'failed':
      case 'abandoned':
        return 'wait';
    }
  }

  /** `issuing`: draw the new value and store it as generation N' `pending`, which the JWKS lists from now on. A value stored before a restart is kept. */
  async function boxIssue(run: RunRow, info: KeyInfo, box: BoxMadeKey): Promise<Next> {
    if (storedNothing(run)) {
      const stored = await attempt(
        run,
        'issuing',
        () => {
          const value = box.generate(deps.random);
          try {
            deps.vault.put(run.keyref, run.genNew, value);
          } finally {
            value.fill(0);
          }
          store.putGen({ keyref: run.keyref, gen: run.genNew, status: 'pending', platformKeyId: null, location: info.location });
          return Promise.resolve();
        },
        'store_failed',
      );
      if (!stored.ok) return fail(run, 'issuing', 'store_failed');
      await point('stored');
      deps.audit.append({ action: 'key.issued', subject: run.keyref, at: now() });
    }
    return advance(run, 'issuing');
  }

  /** `verifying`: the stored value opens as a key of its kind. Leaving it starts the publish lead: the wait time is stored with the step. */
  async function boxVerify(run: RunRow, box: BoxMadeKey): Promise<Next> {
    const value = lendOrUndefined(run.keyref, run.genNew);
    if (value === undefined) return fail(run, 'verifying', 'verify_failed');
    const opened = await attempt0(() => box.check(value));
    if (opened !== 'ok') return fail(run, 'verifying', opened === 'rejected' ? 'verify_rejected' : 'verify_failed');
    return advance(run, 'verifying', { waitUntil: now() + box.publishLeadMs });
  }

  /**
   * `checking`: wait until the stored wait time (a restart re-arms it), then prove with N' at the platform. Refused or unanswered, it is retried
   * with the KBOX-17 backoff until `opened_at` + 2 × the lead; then the run fails (`jwks_not_taken` also sets the current generation unproven
   * again). Proven: N' is marked proven, and only then may the run promote.
   */
  async function boxCheck(run: RunRow, box: BoxMadeKey): Promise<Next> {
    // Written with the step on leaving `verifying`; a row without it waits the lead from the run's opening, when `verifying` ran.
    const at = run.waitUntil ?? run.openedAt + box.publishLeadMs;
    if (now() < at) {
      later(run.runId, at - now());
      return 'wait';
    }
    const federation = deps.federation;
    if (federation === undefined) return fail(run, 'checking', 'identity_unconfigured');
    const pending = lendOrUndefined(run.keyref, run.genNew);
    if (pending === undefined) return fail(run, 'checking', 'pending_missing');
    const proof: { verdict?: ProofVerdict } = {};
    const asked = await attempt(
      run,
      'checking',
      async () => {
        proof.verdict = await box.prove(pending, federation.identity, federation.minted);
      },
      'prove_failed',
    );
    if (!asked.ok || proof.verdict === undefined) return fail(run, 'checking', 'prove_failed');
    const next = afterProof(proof.verdict, { now: now(), openedAt: run.openedAt, leadMs: box.publishLeadMs, attempt: run.attempts });
    switch (next.then) {
      case 'promote':
        store.markProved(run.keyref, run.genNew, now());
        return advance(run, 'checking');
      case 'retry':
        auditStepFailed(run, 'checking', proof.verdict === 'rejected' ? 'proof_rejected' : 'proof_unreachable');
        store.update(run.runId, { attempts: run.attempts + 1 });
        later(run.runId, next.inMs);
        return 'wait';
      case 'fail':
        // KBOX-55 "Due only once proven": a provider that no longer trusts the box is not asked to approve a rotation each day.
        if (next.code === 'jwks_not_taken' && run.genOld > 0) store.clearProved(run.keyref, run.genOld);
        return fail(run, 'checking', next.code);
    }
  }

  /** `promoting`: N' must still be lendable and proven; it becomes current, N goes to grace, and the wait time is the end of grace. */
  async function boxPromote(run: RunRow, head: KeyHead): Promise<Next> {
    if (lendOrUndefined(run.keyref, run.genNew) === undefined) return fail(run, 'promoting', 'pending_missing');
    if ((store.gen(run.keyref, run.genNew)?.provedAt ?? null) === null) return fail(run, 'promoting', 'not_proven');
    store.setGenStatus(run.keyref, run.genNew, 'current');
    if (run.genOld > 0) store.setGenStatus(run.keyref, run.genOld, 'grace');
    store.setStatus(run.keyref, 'works', run.genNew);
    store.markRotated(run.keyref, now());
    return advance(run, 'promoting', { waitUntil: now() + head.graceHours * HOUR_MS });
  }

  /**
   * `revoking`: N's value is deleted, then N is retired, so it leaves the JWKS. The one exception to KBOX-51 step 10: the box is the only
   * holder of the private half and no verifier exists to ask, so deleting the value is the key's death.
   */
  async function boxRevoke(run: RunRow): Promise<Next> {
    if (run.genOld > 0) {
      deps.vault.retire(run.keyref, run.genOld);
      store.setGenStatus(run.keyref, run.genOld, 'retired');
      deps.audit.append({ action: 'key.revoked', subject: run.keyref, at: now() });
    }
    deps.audit.append({ action: 'rotation.completed', subject: run.keyref, at: now(), detail: { run_id: run.runId, gen: run.genNew } });
    return advance(run, 'revoking');
  }

  /** The rollback of a box-made key: N' is marked failed and its value deleted, so it leaves the JWKS at once; N stays current. */
  function boxRollBack(run: RunRow): Next {
    if (store.gen(run.keyref, run.genNew) !== undefined) store.setGenStatus(run.keyref, run.genNew, 'failed');
    deps.vault.retire(run.keyref, run.genNew);
    store.update(run.runId, { state: 'failed' });
    return 'wait';
  }

  // --- starting ----------------------------------------------------------------------------------------------------------------------

  /**
   * A stored key's head and record, once its stored location passes the entry as it is now (KBOX-57): `not_found` for no such key, `rejected`
   * with the refusal code for one the entry declines. Nothing is rewritten, so nothing a caller does after it is undone by a refusal.
   */
  function placedKeyOf(keyref: string): { readonly head: KeyHead; readonly info: KeyInfo } {
    const head = store.key(keyref);
    const info = store.keyInfo(keyref);
    if (head === undefined || info === undefined) throw new ApiError('not_found');
    const placed = storedPlacement(deps, head, info);
    if (placed !== 'ok') throw new ApiError('rejected', placed);
    return { head, info };
  }

  function start(input: StartInput): RunRow {
    const { head, info } = placedKeyOf(input.keyref);
    // KBOX-34: a paste-source platform cannot issue; its keys change only by a paste (a value), never by an api run.
    if (input.value === undefined && isPasteSource(deps, head)) throw new ApiError('rejected', 'no_issuer');
    const genOld = store.gens(input.keyref).find((g) => g.status === 'current')?.gen ?? 0;
    // overlap:false (review N6): the platform's one credential is set to a value the box chose, and a failure sets the current one back; with
    // no current generation there is nothing to set back, and the box would overwrite a credential it never held.
    if (input.value === undefined && genOld === 0 && !overlapOf(kitFor(deps, head))) throw new ApiError('rejected', 'no_current_generation');
    const genNew = store.topGen(input.keyref) + 1;
    const runId = `run_${hex(deps.random.bytes(8))}`;
    const withValue = input.value !== undefined;
    const run = store.openRun({ runId, keyref: input.keyref, state: withValue ? 'verifying' : 'issuing', genOld, genNew, intentName: intentName(input.keyref, genNew, runId), origin: input.origin });
    if (input.value !== undefined) {
      try {
        deps.vault.put(input.keyref, genNew, input.value);
        store.putGen({ keyref: input.keyref, gen: genNew, status: 'pending', platformKeyId: null, location: info.location });
      } catch {
        store.update(runId, { state: 'failed', failedStep: 'issuing', reasonCode: 'store_failed', failedAt: now() });
        deps.audit.append({ action: 'rotation.step_failed', subject: input.keyref, at: now(), detail: { run_id: runId, step: 'issuing', code: 'store_failed' } });
        throw new ApiError('unavailable');
      }
    }
    if (input.verifyHint !== undefined) store.setVerifyHint(input.keyref, input.verifyHint);
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
      // KBOX-57: a key elsewhere is a new key, never this one moved; refused before the first write.
      if (store.keyExists(key.keyref)) throw new ApiError('conflict', 'key_exists');
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
      if (key.verifyHint !== undefined) store.setVerifyHint(key.keyref, key.verifyHint);
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
      // KBOX-57: a stored location the entry now refuses is answered before the run is touched: it stays as it was, never abandoned and lost.
      placedKeyOf(old.keyref);
      store.update(runId, { state: 'abandoned' });
      const next = start({ keyref: old.keyref, origin: 'reconcile' });
      deps.audit.append({ action: 'rotation.restarted', subject: old.keyref, at: now(), detail: { old_run: runId, new_run: next.runId } });
      return next;
    },
    isLeased: (keyref) => leased.has(keyref),
    launch,
    idle,
    stop() {
      stopped = true;
      for (const cancel of timers.values()) cancel();
      timers.clear();
    },
  };
}
