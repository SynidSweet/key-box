// KBOX-51: reconcile, on start and daily. For every platform with a lister it lists the keys the platform holds. A `kbox_` key that matches
// the intent of an unleased run with no stored generation is an orphan from a crash between create and store: revoked, confirmed, audited, and
// the run goes again under a new run id. A `kbox_` key that matches no intent and no generation raises one notice. A key whose run holds a
// lease is never touched: that run is working on it right now. An unleased `issuing` run that stored nothing goes again only when a
// COMPLETE listing of the key's recorded location lacks its intent key; an incomplete listing keeps it open until the next reconcile.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { PlatformKeyInfo } from '../ports/issuer.ts';
import type { PlatformId } from '../ports/types.ts';
import type { Orchestrator } from './orchestrator.ts';
import { intentAbsent } from '../pure/rotation-machine.ts';
import { revokeAndConfirm } from './revoke-confirm.ts';
import type { PlatformSource } from './rotation-ports.ts';
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

  async function listed(platform: PlatformId): Promise<readonly PlatformKeyInfo[] | undefined> {
    const lister = deps.platform(platform)?.lister;
    if (lister === undefined) return undefined;
    try {
      return await lister.list(deps.master(platform));
    } catch {
      deps.audit.append({ action: 'rotation.drive_failed', subject: platform, at: deps.clock.now(), detail: { run_id: 'reconcile', code: 'list_failed' } });
      return undefined;
    }
  }

  async function sweepPlatform(platform: PlatformId, keys: readonly PlatformKeyInfo[]): Promise<void> {
    const kit = deps.platform(platform);
    if (kit === undefined) return;
    for (const key of keys) {
      if (!key.name.startsWith(INTENT_PREFIX) || store.generationIdKnown(key.platformKeyId)) continue;
      const run = store.runs().find((r) => r.intentName === key.name);
      if (run === undefined) {
        if (store.firstOrphanNotice(key.platformKeyId)) deps.events.append('box.notice', { code: 'orphan_key', text: 'orphan key found' });
        continue;
      }
      if (orchestrator.isLeased(run.keyref)) continue;
      const dead = await revokeAndConfirm({ kit, platform, id: key.platformKeyId, at: key.location ?? {}, value: undefined, master: deps.master(platform) });
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
    const lister = head === undefined ? undefined : deps.platform(head.platform)?.lister;
    if (head === undefined || info === undefined) return false;
    // No lister: the platform has nothing to list, so no orphan can be found by listing and there is nothing to wait for.
    if (lister === undefined) return true;
    try {
      return intentAbsent(await lister.listAt(info.location, deps.master(head.platform)), info.location, run.intentName);
    } catch {
      deps.audit.append({ action: 'rotation.drive_failed', subject: run.runId, at: deps.clock.now(), detail: { run_id: run.runId, code: 'list_failed' } });
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
        if (run.state === 'issuing' && !orchestrator.isLeased(run.keyref) && (await mayGoAgain(run))) orchestrator.retake(run.runId);
      }
    },
  };
}
