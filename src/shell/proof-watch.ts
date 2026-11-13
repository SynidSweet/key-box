// KBOX-51 step 10 as amended (revoke-proof, 2026-11-13): the proof watch, the one exit from `grace` for a rotated generation. A run ends on the
// platform's word, which marks nothing dead; the generation lingers (`grace`, its value kept and watched) until this watch proves it revoked on
// the key's proven evidence (KBOX-62), twice and at least 60 s apart, the second time with no end call. Each sweep ends every lingering
// generation again where the box can, asks the evidence, and retires only what was proven both times, re-read in the transaction that retires
// it. It never imports the orchestrator: it settles generations no run owns.
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { Vault } from '../ports/vault.ts';
import type { DeletionStore } from './deletion-store.ts';
import { confirmRevoked, end, revokeTargetOf } from './revoke-confirm.ts';
import type { RevokeTarget } from './revoke-confirm.ts';
import { kitFor, revokeMasterOf } from './rotation-ports.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { GenRow, RotationStore } from './rotation-store.ts';

/** The least time between the two proven verdicts (the deletion's discipline, KBOX-62). */
export const PROOF_GAP_MS = 60_000;

export interface ProofWatchDeps extends PlatformSource {
  readonly store: Pick<RotationStore, 'lingering' | 'key' | 'keyInfo' | 'retireProven'>;
  readonly ledgers: Pick<DeletionStore, 'isOpen'>;
  readonly vault: Vault;
  readonly audit: Audit;
  readonly clock: Clock;
  readonly scheduler: Scheduler;
}

export interface ProofWatch {
  /**
   * One sweep. A sweep still running is returned, never doubled. A generation that throws is audited (`rotation.drive_failed` `watch_failed`)
   * and the sweep goes on; a throw outside any generation rejects, for the caller to audit.
   */
  run(): Promise<void>;
  /** Ends the watch: a sweep waiting on its gap resolves retiring nothing, and later runs do nothing. */
  stop(): void;
  /** Resolves once no sweep is working: none runs, or the running one waits on its gap (which it never waits out). */
  idle(): Promise<void>;
}

type Tried = { readonly ok: true } | { readonly ok: false };

export function createProofWatch(deps: ProofWatchDeps): ProofWatch {
  const { store, vault } = deps;
  let stopped = false;
  let current: Promise<void> | undefined;
  /** Settles when the sweep's working part ends (its calls and writes, however they end); the gap between the verdicts is not part of it. */
  let working: Promise<void> = Promise.resolve();
  const phase = async <T>(work: () => Promise<T>): Promise<T> => {
    let release = (): void => undefined;
    working = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      return await work();
    } finally {
      release();
    }
  };
  let endGap: (() => void) | undefined;

  /** A generation's work, its throw audited with the key as subject (the adapter's text is dropped: it may hold a key). */
  const tried = async (keyref: string, work: () => Promise<void>): Promise<Tried> => {
    try {
      await work();
      return { ok: true };
    } catch {
      deps.audit.append({ action: 'rotation.drive_failed', subject: keyref, at: deps.clock.now(), detail: { run_id: 'watch', code: 'watch_failed' } });
      return { ok: false };
    }
  };

  /** The generation as the watch asks about it now, or undefined when it is not watched: a deleting, box-made or kit-less key, or no master. */
  const targetNow = (gen: GenRow): RevokeTarget | undefined => {
    const head = store.key(gen.keyref);
    if (head === undefined || deps.ledgers.isOpen(gen.keyref)) return undefined;
    const kit = kitFor(deps, head);
    if (kit === undefined || kit.boxKey !== undefined) return undefined;
    const info = store.keyInfo(gen.keyref);
    const master = revokeMasterOf(deps, vault, head, info);
    return master === undefined ? undefined : revokeTargetOf(vault, head, info, kit, gen, master);
  };

  /** End calls and first verdicts: the lingering generations proven revoked once. */
  const firstVerdicts = async (): Promise<readonly GenRow[]> => {
    const proven: GenRow[] = [];
    for (const gen of store.lingering()) {
      await tried(gen.keyref, async () => {
        const target = targetNow(gen);
        if (target === undefined) return;
        await end(target);
        if (await confirmRevoked(target, true)) proven.push(gen);
      });
    }
    return proven;
  };

  /** Second verdicts, evidence only (no end call): proven again, re-read and retired in one transaction, then its value deleted. */
  const secondVerdicts = async (proven: readonly GenRow[]): Promise<void> => {
    const still = new Set(store.lingering().map((g) => `${g.keyref}\n${g.gen}`));
    for (const gen of proven) {
      await tried(gen.keyref, async () => {
        const target = still.has(`${gen.keyref}\n${gen.gen}`) ? targetNow(gen) : undefined;
        if (target === undefined || !(await confirmRevoked(target, true))) return;
        if (!store.retireProven(gen.keyref, gen.gen)) return;
        vault.retire(gen.keyref, gen.gen);
        deps.audit.append({ action: 'key.revoked', subject: gen.keyref, at: deps.clock.now() });
      });
    }
  };

  /** Waits out the gap through the scheduler; false when the watch was stopped first. */
  const gap = (): Promise<boolean> =>
    new Promise<boolean>((resolve) => {
      const cancel = deps.scheduler.after(PROOF_GAP_MS, () => {
        endGap = undefined;
        resolve(true);
      });
      endGap = () => {
        cancel();
        endGap = undefined;
        resolve(false);
      };
    });

  /** The first half: end calls and first verdicts, then the gap armed inside the same working part, so idle() never resolves before it is. */
  const firstHalf = async (): Promise<{ readonly proven: readonly GenRow[]; readonly waited: Promise<boolean> } | undefined> => {
    const proven = await firstVerdicts();
    return proven.length === 0 || stopped ? undefined : { proven, waited: gap() };
  };

  async function sweep(): Promise<void> {
    const first = await phase(firstHalf);
    if (first === undefined || !(await first.waited)) return;
    await phase(() => secondVerdicts(first.proven));
  }

  return {
    run() {
      if (stopped) return Promise.resolve();
      if (current !== undefined) return current;
      const running = sweep().finally(() => {
        current = undefined;
      });
      current = running;
      return running;
    },
    stop() {
      stopped = true;
      endGap?.();
    },
    async idle() {
      for (let seen = working; ; seen = working) {
        await seen;
        if (seen === working) return;
      }
    },
  };
}
