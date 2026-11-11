// A real core store (meta.db and the file vault in a temp directory), a TimedClock, one fake platform with faults planted through its ports,
// two recording destinations and a recording push: the world the rotation tests run in. `build()` makes a fresh orchestrator over the
// same stores, which is how a test plays "the process died and started again". Run directly, this file does nothing.
import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { join } from 'node:path';
import type { Issuer, IssuerCapabilities, IssueRequest, IssuedKey, KeyListing, KeyLister, PlatformKeyInfo, Verifier } from '../../src/ports/issuer.ts';
import type { KeyClass, KeyLocation, Lent, PlatformKeyId, Scope } from '../../src/ports/types.ts';
import type { Vault } from '../../src/ports/vault.ts';
import type { EventLog } from '../../src/ports/events.ts';
import type { EventData, EventKind } from '../../src/pure/schemas.ts';
import { ApiError } from '../../src/pure/errors.ts';
import { createOrchestrator } from '../../src/shell/orchestrator.ts';
import type { NewKey, Orchestrator } from '../../src/shell/orchestrator.ts';
import type { Point } from '../../src/shell/rotation-ports.ts';
import { createReconciler } from '../../src/shell/reconcile.ts';
import type { Reconciler } from '../../src/shell/reconcile.ts';
import { createRotationStore } from '../../src/shell/rotation-store.ts';
import type { RotationStore } from '../../src/shell/rotation-store.ts';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { FakePlatformWorld } from '../fakes/platform.ts';
import { FakePush } from '../fakes/push.ts';
import { RecordingDestination, RecordingRedeployer } from '../fakes/recording-destination.ts';
import type { DestinationCall } from '../fakes/recording-destination.ts';
import { TimedClock, bytesOf, lent, seededRandom, tempDir } from '../kit/index.ts';

export const HOUR = 3600_000;
export const MINUTE = 60_000;

/** Thrown by a checkpoint to stand for the process dying there. Nothing in `src/` knows this class. */
export class Died extends Error {}

export interface Faults {
  /** `issue` throws; `verify` answers rejected on the n-th verification from now (1 = the next); `revoke404` answers absent and revokes nothing. */
  issue: boolean;
  verifyAt: number | undefined;
  revoke404: boolean;
  /** A key that was never revoked still answers ok on the verifier even after revoke. */
  vaultPut: boolean;
  /** The master key cannot be lent (the vault refuses it). */
  master: boolean;
  /** The platform has two master keys that could serve the key and none is its project's: the source refuses to choose (review N5). */
  masterAmbiguous: boolean;
  /** The lister answers a listing of this location whatever it was asked for (a lister that omits the key's region). */
  listerAt: KeyLocation | undefined;
  /** The lister's listing says it is not complete (one page of several). */
  listingIncomplete: boolean;
  /** The next `set` (overlap:false) changes the platform's credential and then answers an error. */
  setThenThrow: boolean;
}

export interface WorldOptions {
  readonly seed?: number;
  /** false: the platform cannot hold two valid keys. */
  readonly overlap?: boolean;
  /** false: the platform has no verifier call, so a revoke is confirmed by the lister. */
  readonly verifier?: boolean;
  readonly klass?: KeyClass;
  /** With `overlap: false`, whether the platform can take a value the box chose (true unless false). */
  readonly settable?: boolean;
}

export interface RotationWorld {
  readonly parts: CoreParts;
  readonly store: RotationStore;
  readonly clock: TimedClock;
  readonly push: FakePush;
  readonly platform: FakePlatformWorld;
  readonly trace: string[];
  readonly faults: Faults;
  /** Told the kind of every event the orchestrator and reconcile append, before it is written. */
  appending: ((kind: EventKind) => void) | undefined;
  readonly destinations: { readonly a: RecordingDestination; readonly redeployer: RecordingRedeployer };
  readonly checkpoints: {
    crashAt: { point: Point; nth: number } | undefined;
    seen: Point[];
    hook: ((point: Point) => Promise<void>) | undefined;
    /** The process dies at the next time the point is reached, counting from now. */
    arm(point: Point, nth?: number): void;
  };
  orch: Orchestrator;
  reconciler: Reconciler;
  /** A fresh orchestrator and reconciler over the same stores: the process started again. */
  build(): void;
  /** The key as the tests create it: two runtime destinations. */
  newKey(over?: Partial<NewKey>): NewKey;
  /** Creates it and lets the run finish. */
  seedKey(over?: Partial<NewKey>): Promise<string>;
  /** The ids of the keys the platform holds. */
  live(): Promise<PlatformKeyId[]>;
  /** The text of generation `gen` of the key in the vault. */
  valueOf(keyref: string, gen: number): Promise<string>;
  /** Moves the clock forward and lets every started run work until it waits again. */
  settle(ms?: number): Promise<void>;
  events(kind: string): readonly { readonly data: Readonly<Record<string, string | number | boolean>> }[];
}

const classifyBy = (scope: Scope): KeyClass => {
  const items = scope['items'];
  const list = Array.isArray(items) ? items : [];
  return list.includes('master') ? 'master' : list.includes('admin') ? 'admin' : 'ordinary';
};

export async function rotationWorld(t: TestContext, options: WorldOptions = {}): Promise<RotationWorld> {
  const stateDir = join(await tempDir(t), 'state');
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(options.seed ?? 5);
  const parts = openCore({ stateDir, clock, scheduler: clock, random });
  t.after(() => parts.close());
  const store = createRotationStore(parts.db, clock, parts.hub);
  const push = new FakePush();
  const platform = new FakePlatformWorld(random);
  const trace: string[] = [];
  const faults: Faults = { issue: false, verifyAt: undefined, revoke404: false, vaultPut: false, master: false, masterAmbiguous: false, listerAt: undefined, listingIncomplete: false, setThenThrow: false };
  const regionOf = new Map<PlatformKeyId, string>();
  const destination = new RecordingDestination(trace);
  const recording = { a: destination, redeployer: new RecordingRedeployer(trace, destination) };

  // KBOX-51, KBOX-17 (review N3): every call that may change what a destination or the platform holds or runs is entered only once an open
  // run's intent receipt for it is written. A call entered without one is recorded here and fails the test that made it.
  const PLATFORM_SET = 'platform_set';
  const missingIntent: string[] = [];
  const intentWritten = (call: DestinationCall | 'set', target: string): boolean =>
    store.activeRuns().some((run) =>
      store
        .receipts(run.runId)
        .some((r) => (call === 'set' ? r.kind === PLATFORM_SET : r.kind !== PLATFORM_SET && r.target === target) && r.pushed !== 'refused' && (call !== 'redeploy' || r.redeployIntended)),
    );
  const requireIntent = (call: DestinationCall | 'set', target: string): void => {
    if (!intentWritten(call, target)) missingIntent.push(`${call}:${target}`);
  };
  recording.a.onEnter(requireIntent);
  recording.redeployer.onEnter(requireIntent);
  t.after(() => assert.deepEqual(missingIntent, [], 'every push, redeploy, set and remove was entered with its intent receipt written'));

  const settable = options.overlap === false && options.settable !== false;
  const issuer: Issuer = {
    platform: 'fake',
    capabilities: (): IssuerCapabilities => ({ ...platform.issuer.capabilities(), overlap: options.overlap ?? true, set: settable ? 'api' : 'none', classify: classifyBy }),
    issue: async (req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> => {
      trace.push('issue');
      const row = store.runs().find((r) => r.intentName === intentName);
      if (row === undefined || row.state !== 'issuing') throw new Error('KBOX-51: no intent row in state issuing existed before the platform was called');
      if (faults.issue) throw new Error('platform refused to create');
      const issued = await platform.issuer.issue(req, intentName, master);
      regionOf.set(issued.platformKeyId, 'eu');
      return issued;
    },
    revoke: async (id: PlatformKeyId, master: Lent) => {
      trace.push('revoke');
      if (faults.revoke404) return 'absent';
      return platform.issuer.revoke(id, master);
    },
    // overlap:false: the platform holds one credential and takes the value the box chose; the one it held before stops working at once.
    ...(settable
      ? {
          set: async (value: Lent, at: KeyLocation, master: Lent): Promise<void> => {
            void at;
            requireIntent('set', 'fake');
            trace.push('set');
            await platform.set(value, master);
            if (faults.setThenThrow) {
              faults.setThenThrow = false;
              throw new Error('timed out after the platform took the value');
            }
          },
        }
      : {}),
  };
  const lister: KeyLister = {
    list: async (master: Lent): Promise<PlatformKeyInfo[]> => (await platform.lister.list(master)).map((k) => ({ ...k, location: { region: regionOf.get(k.platformKeyId) ?? 'eu' } satisfies KeyLocation })),
    listAt: async (at: KeyLocation, master: Lent): Promise<KeyListing> => {
      const where = faults.listerAt ?? at;
      const keys = (await lister.list(master)).filter((k) => k.location?.region === where.region && k.location?.project === where.project);
      return { complete: !faults.listingIncomplete, at: where, keys };
    },
  };
  const verifier: Verifier = {
    verify: async (key, target) => {
      trace.push('verify');
      if (faults.verifyAt !== undefined) {
        faults.verifyAt -= 1;
        if (faults.verifyAt === 0) {
          faults.verifyAt = undefined;
          return 'rejected';
        }
      }
      return platform.verifier.verify(key, target);
    },
  };
  const vault: Vault = {
    put: (ref, gen, v) => {
      if (faults.vaultPut) throw new Error('disk full');
      parts.vault.put(ref, gen, v);
    },
    lend: (ref, gen) => parts.vault.lend(ref, gen),
    retire: (ref, gen) => parts.vault.retire(ref, gen),
  };
  const events: EventLog = {
    head: () => parts.events.head(),
    after: (since) => parts.events.after(since),
    append: <K extends EventKind>(kind: K, data: EventData<K>): number => {
      world.appending?.(kind);
      return parts.events.append(kind, data);
    },
  };
  const counts = new Map<Point, number>();
  const checkpoints: RotationWorld['checkpoints'] = {
    crashAt: undefined,
    seen: [],
    hook: undefined,
    arm(point, nth = 1) {
      checkpoints.crashAt = { point, nth: (counts.get(point) ?? 0) + nth };
    },
  };

  const world: RotationWorld = {
    parts,
    store,
    clock,
    push,
    platform,
    trace,
    faults,
    appending: undefined,
    destinations: recording,
    checkpoints,
    orch: undefined as never,
    reconciler: undefined as never,
    build() {
      const deps = {
        store,
        meta: parts.meta,
        vault,
        platform: () => ({ issuer, lister, ...(options.verifier === false ? {} : { verifier }) }),
        destination: () => ({ destination: recording.a, redeployer: recording.redeployer }),
        master: () => {
          if (faults.master) throw new Error('vault: the master key is unreadable');
          if (faults.masterAmbiguous) throw new ApiError('conflict', 'master_ambiguous');
          return platform.master();
        },
        clock,
        scheduler: clock,
        random,
        audit: parts.audit,
        events,
        push,
        checkpoint: async (point: Point): Promise<void> => {
          checkpoints.seen.push(point);
          const n = (counts.get(point) ?? 0) + 1;
          counts.set(point, n);
          if (checkpoints.hook !== undefined) await checkpoints.hook(point);
          const armed = checkpoints.crashAt;
          if (armed !== undefined && armed.point === point && armed.nth === n) throw new Died(point);
        },
      };
      world.orch = createOrchestrator(deps);
      world.reconciler = createReconciler({ ...deps, orchestrator: world.orch });
    },
    newKey(over = {}) {
      return {
        keyref: 'fake/shop/OPENAI_KEY',
        platform: 'fake',
        name: 'OPENAI_KEY',
        projects: ['shop'],
        scopeItems: options.klass === 'admin' ? ['admin'] : ['read'],
        class: options.klass ?? 'ordinary',
        destinations: [
          { kind: 'vercel_env', target: 'app-a', readable_by: 'runtime' },
          { kind: 'vercel_env', target: 'app-b', readable_by: 'runtime' },
        ],
        rotateEveryDays: 90,
        graceHours: 24,
        location: { region: 'eu' },
        markAdmin: false,
        ...over,
      };
    },
    async seedKey(over = {}) {
      const key = world.newKey(over);
      if (options.overlap === false) {
        // A run never creates the key of a one-credential platform (no old value to set back): it is added by paste, as the owner does.
        const pasted = Buffer.from(`fk-${Buffer.from(random.bytes(16)).toString('hex')}`);
        await platform.set(lent(pasted, 'paste:1'), platform.master());
        await world.orch.create(key, pasted);
      } else {
        await world.orch.create(key);
      }
      return key.keyref;
    },
    async live() {
      return (await platform.lister.list(platform.master())).map((k) => k.platformKeyId);
    },
    async valueOf(keyref, gen) {
      return Buffer.from(await bytesOf(parts.vault.lend(keyref, gen))).toString('utf8');
    },
    async settle(ms = 25 * HOUR) {
      for (let i = 0; i < 12; i += 1) {
        await world.orch.idle();
        if (store.activeRuns().length === 0) return;
        clock.advance(i === 0 ? ms : 2 * HOUR);
      }
      await world.orch.idle();
    },
    events: (kind) => parts.events.after(0).filter((e) => e.kind === kind),
  };
  world.build();
  return world;
}
