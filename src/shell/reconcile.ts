// KBOX-51: reconcile, on start and daily. For every platform with a lister it lists the keys the platform holds (a lister with no platform-wide
// `list`: the keys at each distinct stored location of the platform's keys, once per master that covers it). A `kbox_` key that matches
// the intent of an unleased run with no stored generation is an orphan from a crash between create and store: revoked, confirmed, audited, and
// the run goes again under a new run id. A `kbox_` key that matches no intent and no generation raises one notice. A key whose run holds a
// lease is never touched: that run is working on it right now. An unleased `issuing` run that stored nothing goes again only when a
// COMPLETE listing of the key's recorded location lacks its intent key; an incomplete listing keeps it open until the next reconcile.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { PlatformKeyInfo } from '../ports/issuer.ts';
import type { KeyLocation, PlatformId } from '../ports/types.ts';
import type { Orchestrator } from './orchestrator.ts';
import { covers, sameLocation } from '../pure/location.ts';
import { intentAbsent } from '../pure/rotation-machine.ts';
import { revokeAndConfirm } from './revoke-confirm.ts';
import { kitFor, storedPlacement } from './rotation-ports.ts';
import type { MasterResult, PlatformSource } from './rotation-ports.ts';
import type { RotationStore, RunRow } from './rotation-store.ts';

export interface ReconcileDeps extends PlatformSource {
  readonly store: RotationStore;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly clock: Clock;
  readonly orchestrator: Orchestrator;
}

export interface Reconciler {
  run(): Promise<void>;
}

const INTENT_PREFIX = 'kbox_';

export function createReconciler(deps: ReconcileDeps): Reconciler {
  const { store, orchestrator } = deps;

  const auditFailed = (subject: string, runId: string, code: string): void => {
    deps.audit.append({ action: 'rotation.drive_failed', subject, at: deps.clock.now(), detail: { run_id: runId, code } });
  };

  /** Every distinct stored location of the platform's keys that can have an orphan listed there: a key whose kit has a lister and whose stored place still passes its entry. */
  function listableLocations(platform: PlatformId): readonly KeyLocation[] {
    const places: KeyLocation[] = [];
    for (const head of store.keys()) {
      const info = store.keyInfo(head.keyref);
      if (head.platform !== platform || info === undefined || kitFor(deps, head)?.lister === undefined || storedPlacement(deps, head, info) !== 'ok') continue;
      if (!places.some((place) => sameLocation(place, info.location))) places.push(info.location);
    }
    return places;
  }

  /**
   * KBOX-57: what the platform holds, listed once per master row (each master sees its own place); a listing that fails audits `list_failed`
   * for that row only and the others still count. A key two masters both see is listed once. A lister with no platform-wide `list` is asked
   * `listAt` for each distinct stored location of the platform's keys, by each master row that covers it: a `kbox_` key in a place no stored key
   * names is not found.
   */
  async function listed(platform: PlatformId): Promise<readonly PlatformKeyInfo[] | undefined> {
    const lister = deps.platform(platform)?.lister;
    if (lister === undefined) return undefined;
    const seen = new Map<string, PlatformKeyInfo>();
    const read = async (call: () => Promise<readonly PlatformKeyInfo[]>): Promise<void> => {
      try {
        for (const key of await call()) if (!seen.has(key.platformKeyId)) seen.set(key.platformKeyId, key);
      } catch {
        // A listing that failed: one `list_failed` row for the one master (and location) it was asked of; the others still count.
        deps.audit.append({ action: 'rotation.drive_failed', subject: platform, at: deps.clock.now(), detail: { run_id: 'reconcile', code: 'list_failed' } });
      }
    };
    const masters = deps.masters(platform);
    const { list } = lister;
    if (list !== undefined) {
      for (const master of masters) await read(() => list.call(lister, master.value));
      return [...seen.values()];
    }
    for (const place of listableLocations(platform)) {
      for (const master of masters.filter((row) => covers(row.at, place))) await read(async () => (await lister.listAt(place, master.value)).keys);
    }
    return [...seen.values()];
  }

  /** KBOX-57: the master of the key a run is for, by its stored location and scope items (never its projects). */
  const masterOfKey = (platform: PlatformId, keyref: string): MasterResult => {
    const info = store.keyInfo(keyref);
    return info === undefined ? { ok: false, code: 'no_master' } : deps.master(platform, info.location, info.scopeItems);
  };

  async function sweepPlatform(platform: PlatformId, keys: readonly PlatformKeyInfo[]): Promise<void> {
    for (const key of keys) {
      if (!key.name.startsWith(INTENT_PREFIX) || store.generationIdKnown(key.platformKeyId)) continue;
      const run = store.runs().find((r) => r.intentName === key.name);
      if (run === undefined) {
        if (store.firstOrphanNotice(key.platformKeyId)) deps.events.append('box.notice', { code: 'orphan_key', text: 'orphan key found' });
        continue;
      }
      if (orchestrator.isLeased(run.keyref)) continue;
      // KBOX-55: the orphan is revoked with the kit of the key its run is for, never another key's.
      const kit = kitFor(deps, { platform, keyref: run.keyref });
      if (kit === undefined) continue;
      const master = masterOfKey(platform, run.keyref);
      if (!master.ok) {
        auditFailed(run.keyref, run.runId, master.code);
        continue;
      }
      const dead = await revokeAndConfirm({ kit, platform, id: key.platformKeyId, at: key.location ?? {}, scopeItems: store.keyInfo(run.keyref)?.scopeItems ?? [], value: undefined, master: master.value });
      if (!dead) continue;
      deps.audit.append({ action: 'rotation.orphan_revoked', subject: run.keyref, at: deps.clock.now(), detail: { run_id: run.runId } });
      if (run.state === 'issuing') orchestrator.retake(run.runId);
    }
  }

  /**
   * Whether an unleased `issuing` run may go again. One that stored its generation is continued (nothing is lost). One that stored nothing is
   * restarted only when its intent key is proven off the platform: absence counts only from a complete listing of the key's recorded location.
   * An incomplete or failed listing keeps the run open and the next reconcile tries again: the platform may still hold the key.
   */
  async function mayGoAgain(run: RunRow): Promise<boolean> {
    if (store.gen(run.keyref, run.genNew) !== undefined) return true;
    const head = store.key(run.keyref);
    const info = store.keyInfo(run.keyref);
    const lister = head === undefined ? undefined : kitFor(deps, head)?.lister;
    if (head === undefined || info === undefined) return false;
    // No lister: the platform has nothing to list, so no orphan can be found by listing and there is nothing to wait for.
    if (lister === undefined) return true;
    try {
      const master = masterOfKey(head.platform, run.keyref);
      if (!master.ok) {
        auditFailed(run.runId, run.runId, master.code);
        return false;
      }
      return intentAbsent(await lister.listAt(info.location, master.value), info.location, run.intentName);
    } catch {
      auditFailed(run.runId, run.runId, 'list_failed');
      return false;
    }
  }

  return {
    async run() {
      for (const platform of new Set(store.keys().map((k) => k.platform))) {
        const keys = await listed(platform);
        if (keys !== undefined) await sweepPlatform(platform, keys);
      }
      for (const run of store.activeRuns()) {
        if (run.state !== 'issuing' || orchestrator.isLeased(run.keyref)) continue;
        if (await mayGoAgain(run)) orchestrator.retake(run.runId);
        else noticeUnsettled(run);
      }
    },
  };

  /**
   * A run reconcile cannot settle (an incomplete listing, one that never matches the recorded location) would stay open with no word (review
   * N8): the first time, it files the run's one card, recorded before it goes out, and never again. The old key works meanwhile.
   */
  function noticeUnsettled(run: RunRow): void {
    if (run.failedNotified) return;
    store.update(run.runId, { failedNotified: true });
    deps.events.append('rotation.failed', { run_id: run.runId, keyref: run.keyref, step: 'issuing', reason_code: 'reconcile_unsettled', old_key_works: run.genOld > 0 });
  }
}
