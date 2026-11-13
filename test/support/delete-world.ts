// The world the KBOX-62 deletion tests run in: the approval half (approveWorld) with the rotation unit opened beside it over a small
// in-memory platform whose verifier answers HTTP statuses (`answerStatus`) and whose entry declares proven revoked evidence (401). A second,
// paste-only entry (`pasted`) has no issuer and no retirer, so only the owner ends its keys. `restart()` plays "the process died and core
// started again": a fresh approval half (F3), a fresh rotation, the deletion's settle, then resume. Run directly, this file does nothing.
import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import type { Issuer, IssuerCapabilities, KeyListing, KeyLister, PlatformKeyInfo, Verifier } from '../../src/ports/issuer.ts';
import type { BoxMadeKey, PlatformEntry } from '../../src/ports/platform.ts';
import type { KeyClass, KeyShape, Lent, Scope } from '../../src/ports/types.ts';
import type { Action } from '../../src/pure/actions.ts';
import { openApproveCore } from '../../src/shell/approve-core.ts';
import type { ApproveCore } from '../../src/shell/approve-core.ts';
import type { Executor } from '../../src/shell/approvals.ts';
import { deletingKeyrefs } from '../../src/shell/deletion-store.ts';
import type { NewKey } from '../../src/shell/orchestrator.ts';
import { createPlatformSource } from '../../src/shell/platform-source.ts';
import type { PlatformSource, Point } from '../../src/shell/rotation-ports.ts';
import { openRotation } from '../../src/shell/rotation.ts';
import type { Rotation } from '../../src/shell/rotation.ts';
import { readKeyInfo } from '../../src/shell/rotation-store.ts';
import { FAKE_LOCATION } from '../fakes/platform-entry.ts';
import { bytesOf, lent, seededRandom } from '../kit/index.ts';
import { DOMAIN, WORDLIST, approveWorld } from './approve-world.ts';
import type { World } from './approve-world.ts';

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
/** The probe the fake entry's revoked evidence names (KBOX-42, KBOX-62). */
export const EVIDENCE_PROBE = 'fake.revoked-key-answer';
export const PASTED = 'pasted';
const SHAPE: KeyShape = { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };

/** Thrown by a checkpoint to stand for the process dying there. Nothing in `src/` knows this class. */
export class Died extends Error {}

const byItems = (scope: Scope): KeyClass => {
  const items = Array.isArray(scope['items']) ? scope['items'] : [];
  return items.includes('master') ? 'master' : items.includes('admin') ? 'admin' : 'ordinary';
};

const text = async (value: Lent): Promise<string> => Buffer.from(await bytesOf(value)).toString('utf8');

/**
 * The platform: the keys it holds by id (made by `issue`) and the pasted values it accepts. `calls` records every revoke (with the text of
 * the master it was made with) and every status answered, in order. `down` makes revoke and every answer throw; `answer` replaces the status.
 */
export class DeletePlatform {
  readonly live = new Map<string, string>();
  readonly pasted = new Set<string>();
  readonly calls: string[] = [];
  /** Keys every listing shows beside the live ones (a `kbox_` name a reconcile reads). */
  readonly extra: PlatformKeyInfo[] = [];
  down = false;
  answer: number | 'throw' | undefined = undefined;
  #next = 1;
  readonly #random = seededRandom(41);

  value(): string {
    return `fk-${Buffer.from(this.#random.bytes(16)).toString('hex')}`;
  }

  async status(key: Lent): Promise<number> {
    const value = await text(key);
    this.calls.push(`status ${value}`);
    if (this.down || this.answer === 'throw') throw new Error('platform unreachable');
    if (this.answer !== undefined) return this.answer;
    return this.live.has(this.idOf(value) ?? '') || this.pasted.has(value) ? 200 : 401;
  }

  idOf(value: string): string | undefined {
    return [...this.live].find(([, v]) => v === value)?.[0];
  }

  readonly issuer: Issuer = {
    platform: 'fake',
    capabilities: (): IssuerCapabilities => ({
      create: 'api',
      revoke: 'api',
      selfRotate: true,
      overlap: true,
      set: 'none',
      revealOnce: true,
      scopeSchema: { fields: ['items'] },
      shape: SHAPE,
      classify: byItems,
    }),
    issue: () => {
      const platformKeyId = `pk-${this.#next}`;
      this.#next += 1;
      const value = this.value();
      this.live.set(platformKeyId, value);
      return Promise.resolve({ value: lent(Buffer.from(value), platformKeyId), platformKeyId });
    },
    revoke: async (id, master) => {
      this.calls.push(`revoke ${id} with ${await text(master)}`);
      if (this.down) throw new Error('platform unreachable');
      return this.live.delete(id) ? 'revoked' : 'absent';
    },
  };

  readonly lister: KeyLister = {
    listAt: (at): Promise<KeyListing> => Promise.resolve({ complete: true, at, keys: [...[...this.live.keys()].map((platformKeyId) => ({ platformKeyId, name: platformKeyId, location: at })), ...this.extra] }),
  };

  readonly verifier: Verifier = {
    verify: async (key) => {
      try {
        return (await this.status(key)) === 200 ? 'ok' : 'rejected';
      } catch {
        return 'unreachable';
      }
    },
    answerStatus: (key) => this.status(key),
  };
}

export interface DeleteWorldOptions {
  /** The fake entry's evidence probe is still listed as unverified: no evidence counts (KBOX-42, KBOX-62). */
  readonly unproven?: boolean;
  /** Where the process may be stopped: the checkpoint seam rotation is given. */
  readonly checkpoint?: (point: Point) => void | Promise<void>;
  /** The fake entry makes this master itself (KBOX-55). */
  readonly boxKey?: BoxMadeKey;
}

export interface DeleteWorld extends World {
  readonly platform: DeletePlatform;
  readonly registry: readonly PlatformEntry[];
  rotation: Rotation;
  approve: ApproveCore;
  source: PlatformSource;
  /** The process dies at the next time the point is reached. */
  arm(point: Point): void;
  readonly seen: Point[];
  /** `masterThrows`: the platform source's `master` throws (a step that throws, not one that finds no master). */
  readonly flags: { masterThrows: boolean };
  /** A key the platform issued and the box stored (gen 1 current), with no destinations. */
  addKey(over?: Partial<NewKey>): Promise<string>;
  /** A pasted key of the paste-only platform (gen 1 current, no platform key id): the owner ends it. */
  addPasted(name: string): Promise<{ readonly keyref: string; readonly value: string }>;
  /**
   * The masters seeded at the start: `fake/team/MASTER` (platform key id `pk-m1`, the platform holding its value) and `pasted/team/PASTED_MASTER`
   * (a pasted value the platform accepts, no id). Every key a test adds is served by its platform's one.
   */
  readonly masters: { readonly fake: string; readonly pasted: string };
  /** Proposes, then approves on the phone, a delete of the key; the approval id. */
  approveDelete(keyref: string): Promise<string>;
  /** The decided approval's result, or null while it has none. */
  resultOf(approvalId: string): { readonly result: string | null; readonly code: string | null; readonly status: string };
  /** Moves the clock forward in steps, letting every run work until it waits again after each. */
  pass(ms: number, step?: number): Promise<void>;
  /** The process died and core started again on the same files. */
  restart(): Promise<void>;
  audits(action: string): readonly { readonly ref: string; readonly detail: unknown }[];
  events(kind: string): readonly Readonly<Record<string, unknown>>[];
}

export async function deleteWorld(t: TestContext, options: DeleteWorldOptions = {}): Promise<DeleteWorld> {
  let current: Rotation | undefined;
  const late: Executor = (approval) => {
    const executor = current?.executors.delete_key;
    if (executor === undefined) throw new RangeError('rotation is not open');
    return executor(approval);
  };
  const w = await approveWorld(t, { executors: { delete_key: late } });
  const platform = new DeletePlatform();
  const evidence = { verifier: { statuses: [401], probe: EVIDENCE_PROBE } };
  const fake: PlatformEntry = {
    id: 'fake',
    issuer: platform.issuer,
    lister: platform.lister,
    verifier: platform.verifier,
    location: FAKE_LOCATION,
    revokedEvidence: evidence,
    unverified: options.unproven === true ? [EVIDENCE_PROBE] : [],
    ...(options.boxKey === undefined ? {} : { boxKey: options.boxKey }),
  };
  const pasted: PlatformEntry = {
    id: PASTED,
    verifier: platform.verifier,
    shape: SHAPE,
    classify: byItems,
    revokedEvidence: evidence,
    unverified: options.unproven === true ? [EVIDENCE_PROBE] : [],
  };
  const registry = [fake, pasted];
  const seen: Point[] = [];
  let armed: Point | undefined;
  const checkpoint = async (point: Point): Promise<void> => {
    seen.push(point);
    await options.checkpoint?.(point);
    if (armed === point) {
      armed = undefined;
      throw new Died(point);
    }
  };
  const flags = { masterThrows: false };
  const sourceOver = (): PlatformSource => {
    const real = createPlatformSource({ registry, meta: w.parts.meta, vault: w.parts.vault, keyInfo: (keyref) => readKeyInfo(w.parts.db, keyref), deleting: () => deletingKeyrefs(w.parts.db) });
    return {
      ...real,
      master: (...args) => {
        if (flags.masterThrows) throw new Error('the master store failed');
        return real.master(...args);
      },
    };
  };
  const open = (approve: ApproveCore, source: PlatformSource): Rotation =>
    openRotation({ parts: w.parts, approvals: approve.approvals, approvalRecords: approve.approvals, approvers: approve.approvers, push: w.push, clock: w.clock, scheduler: w.clock, random: seededRandom(17), audit: w.parts.audit, source, checkpoint });

  const source = sourceOver();
  const first = open(w.core, source);
  current = first;
  const seedMaster = (on: 'fake' | typeof PASTED, id: string | null, name: string): string => {
    const keyref = `${on}/team/${name}`;
    const value = platform.value();
    if (id === null) platform.pasted.add(value);
    else platform.live.set(id, value);
    w.parts.meta.putKey({ keyref, platform: on, name, projects: ['team'], class: 'master', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
    first.store.putKeyInfo(keyref, { scopeItems: ['master'], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
    w.parts.vault.put(keyref, 1, Buffer.from(value));
    first.store.putGen({ keyref, gen: 1, status: 'current', platformKeyId: id, location: {} });
    return keyref;
  };
  const masters = { fake: seedMaster('fake', 'pk-m1', 'MASTER'), pasted: seedMaster(PASTED, null, 'PASTED_MASTER') };
  const world: DeleteWorld = Object.assign(w, {
    platform,
    registry,
    rotation: first,
    approve: w.core,
    source,
    masters,
    seen,
    flags,
    arm(point: Point) {
      armed = point;
    },
    async addKey(over: Partial<NewKey> = {}) {
      const key: NewKey = {
        keyref: 'fake/shop/FAKE_KEY',
        platform: 'fake',
        name: 'FAKE_KEY',
        projects: ['shop'],
        scopeItems: ['read'],
        class: 'ordinary',
        destinations: [],
        rotateEveryDays: 90,
        graceHours: 24,
        location: { region: 'eu' },
        markAdmin: false,
        ...over,
      };
      const created = await world.rotation.orchestrator.create(key);
      assert.equal(created.status, 'works', `${key.keyref} was added`);
      return key.keyref;
    },
    async addPasted(name: string) {
      const value = platform.value();
      platform.pasted.add(value);
      const keyref = `${PASTED}/shop/${name}`;
      const key: NewKey = { keyref, platform: PASTED, name, projects: ['shop'], scopeItems: ['admin'], class: 'admin', destinations: [], rotateEveryDays: 90, graceHours: 24, location: {}, markAdmin: false };
      const created = await world.rotation.orchestrator.create(key, Buffer.from(value));
      assert.equal(created.status, 'works', `${keyref} was added`);
      return { keyref, value };
    },
    async approveDelete(keyref: string) {
      const proposed = w.propose({ kind: 'delete_key', keyref } satisfies Action);
      const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
      assert.ok(item, 'the delete waits on the phone');
      await w.decide(item.approval_id, 'approve', w.proofFor(item));
      await world.rotation.orchestrator.idle();
      return proposed.approval_id;
    },
    resultOf(approvalId: string) {
      const row = w.parts.db.prepare('SELECT status, result, result_code FROM approvals WHERE approval_id = ?').get(approvalId) as { status: string; result: string | null; result_code: string | null };
      return { status: row.status, result: row.result, code: row.result_code };
    },
    async pass(ms: number, step = MINUTE) {
      for (let done = 0; done < ms; done += step) {
        w.clock.advance(Math.min(step, ms - done));
        await world.rotation.orchestrator.idle();
      }
    },
    async restart() {
      world.rotation.orchestrator.stop();
      await world.rotation.orchestrator.idle();
      world.approve = openApproveCore({ parts: w.parts, approverStore: w.priv, trust: w.trust, push: w.push, clock: w.clock, random: seededRandom(77), domain: DOMAIN, wordlist: WORDLIST, vet: () => 'ok', executors: { delete_key: late } });
      world.source = sourceOver();
      current = open(world.approve, world.source);
      world.rotation = current;
      world.rotation.deletion.settle();
      await world.rotation.orchestrator.resume();
    },
    audits(action: string) {
      return w.parts.audit
        .read(0)
        .entries.filter((r) => r.action === action)
        .map((r) => ({ ref: r.ref, detail: r.detail }));
    },
    events(kind: string) {
      return w.parts.events
        .after(0)
        .filter((e) => e.kind === kind)
        .map((e) => e.data);
    },
  });
  return world;
}
