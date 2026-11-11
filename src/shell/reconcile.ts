// KBOX-51: reconcile, on start and daily. For every platform with a lister it lists the keys the platform holds. A `kbox_` key that matches
// the intent of an unleased run with no stored generation is an orphan from a crash between create and store: revoked, confirmed, audited, and
// the run goes again under a new run id. A `kbox_` key that matches no intent and no generation raises one notice. A key whose run holds a
// lease is never touched: that run is working on it right now.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { PlatformKeyInfo } from '../ports/issuer.ts';
import type { PlatformId } from '../ports/types.ts';
import type { Orchestrator } from './orchestrator.ts';
import { revokeAndConfirm } from './revoke-confirm.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { RotationStore } from './rotation-store.ts';

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
      const dead = await revokeAndConfirm({ kit, platform, id: key.platformKeyId, value: undefined, master: deps.master(platform) });
      if (!dead) continue;
      deps.audit.append({ action: 'rotation.orphan_revoked', subject: run.keyref, at: deps.clock.now(), detail: { run_id: run.runId } });
      if (run.state === 'issuing') orchestrator.retake(run.runId);
    }
  }

  return {
    async run() {
      const platforms = [...new Set(store.keys().map((k) => k.platform))];
      const unlisted = new Set<PlatformId>();
      for (const platform of platforms) {
        const keys = await listed(platform);
        if (keys === undefined) {
          if (deps.platform(platform)?.lister !== undefined) unlisted.add(platform);
          continue;
        }
        await sweepPlatform(platform, keys);
      }
      // An unleased issuing run goes again (continued when it stored its generation, else under a new run id), unless its platform could not
      // be listed: an unlisted orphan would be left live.
      for (const run of store.activeRuns()) {
        const platform = store.key(run.keyref)?.platform;
        if (run.state !== 'issuing' || orchestrator.isLeased(run.keyref) || platform === undefined || unlisted.has(platform)) continue;
        orchestrator.retake(run.runId);
      }
    },
  };
}
