// KBOX-62: one step of a deletion's run (origin `delete`, state `revoking` for its whole life). The orchestrator owns the lease, the timers,
// resume and the notice of a step that throws; this file owns what a step does: stop the key's use, end the batch where the box can, prove it
// dead twice at least a minute apart on proven evidence only, retire it, and once nothing is live erase the vault files and the rows. Each
// step is safe to repeat; nothing is erased before the confirmation is written.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { Push } from '../ports/push.ts';
import type { Vault } from '../ports/vault.ts';
import { retryDelayMs } from '../pure/rotation-machine.ts';
import { deletePush } from '../pure/words.ts';
import type { Approvals } from './approvals.ts';
import type { DeletionStore, Ledger } from './deletion-store.ts';
import { confirmRevoked, end, enderOf, revokeTargetOf } from './revoke-confirm.ts';
import type { Ender, RevokeTarget } from './revoke-confirm.ts';
import { kitFor, revokeMasterOf } from './rotation-ports.ts';
import type { DeletePoint, PlatformKit, PlatformSource } from './rotation-ports.ts';
import type { GenRow, KeyHead, RotationStore, RunRow } from './rotation-store.ts';

/** The least time between the two dead verdicts (ruling M1: enforced, a restart included). */
export const DEAD_GAP_MS = 60_000;

/** What a deletion step asks of the orchestrator that drives it: a timer for the run, and the checkpoint seam. */
export interface DeletionContext {
  later(ms: number): void;
  point(p: DeletePoint): Promise<void>;
}

export interface DeletionDriver {
  /** `wait`: a timer was set (`later`); `continue`: step again (an erased run is gone, which ends the drive). */
  step(run: RunRow, ctx: DeletionContext): Promise<'continue' | 'wait'>;
}

export interface DeletionRunDeps {
  readonly store: RotationStore;
  readonly ledgers: DeletionStore;
  readonly source: PlatformSource;
  readonly vault: Vault;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly push: Push;
  readonly clock: Clock;
  readonly approvals: Pick<Approvals, 'executed'>;
  /** Expires every pending approval and paste task naming the key (a writer that slipped in is undone). */
  readonly expireNaming: (keyref: string) => void;
}

const isLive = (g: GenRow): boolean => g.status === 'current' || g.status === 'grace';
/** The weakest ender among the live generations: the owner before a retirer before the issuer (who must act for the deletion to go on). */
const WEAKEST: readonly Ender[] = ['owner', 'retirer', 'issuer'];

export function createDeletionDriver(deps: DeletionRunDeps): DeletionDriver {
  const { store, ledgers, vault } = deps;
  const now = (): number => deps.clock.now();

  /** Every generation of the batch proven revoked; a master's own current generation is never confirmed by a listing (its value is what one needs). */
  const allRevoked = async (head: KeyHead, batch: readonly { readonly gen: GenRow; readonly target: RevokeTarget }[]): Promise<boolean> => {
    for (const { gen, target } of batch) {
      if (!(await confirmRevoked(target, !(head.class === 'master' && gen.status === 'current')))) return false;
    }
    return true;
  };

  /** The one notice and push of a deletion, sent with `notified` set first, so a restart sends neither again. */
  const notifyOnce = (run: RunRow, head: KeyHead | undefined, which: 'end' | 'unconfirmed'): void => {
    if (!ledgers.markNotified(run.runId)) return;
    deps.events.append('box.notice', { code: 'delete_waiting', text: 'key deletion waiting' });
    if (head !== undefined) deps.push.send(deletePush(which, head.name, head.platform));
  };

  /** Not proven dead (or no kit or master): the first verdict cleared, one more attempt, the notice once, the audit once per run, the backoff. */
  const unconfirmed = (run: RunRow, ledger: Ledger, head: KeyHead | undefined, kit: PlatformKit | undefined, live: readonly GenRow[], ctx: DeletionContext): 'wait' => {
    if (ledger.deadSeenAt !== null) ledgers.setDeadSeen(run.runId, null);
    const attempts = run.attempts + 1;
    store.update(run.runId, { attempts });
    notifyOnce(run, head, 'unconfirmed');
    if (attempts === 1) {
      const enders = kit === undefined ? ['owner' as const] : live.map((g) => enderOf(kit, g.platformKeyId));
      const ender = WEAKEST.find((e) => enders.includes(e)) ?? 'owner';
      deps.audit.append({ action: 'key.delete_unconfirmed', subject: run.keyref, at: now(), detail: { run_id: run.runId, ender } });
    }
    ctx.later(retryDelayMs(attempts - 1));
    return 'wait';
  };

  /** Every vault file of the key: by its generation rows and by listing the vault (a crash between a put and its row leaves a file with no row). */
  const retireFiles = (keyref: string): void => {
    for (const gen of new Set([...store.gens(keyref).map((g) => g.gen), ...vault.generations(keyref)])) vault.retire(keyref, gen);
  };

  const erase = async (run: RunRow, ledger: Ledger, ctx: DeletionContext): Promise<'continue'> => {
    retireFiles(run.keyref);
    await ctx.point('delete_vault_retired');
    // Again right before the transaction: a generation written between the loop and here has its file deleted too.
    retireFiles(run.keyref);
    const erased = ledgers.erase(run.keyref, run.runId);
    await ctx.point('delete_erased');
    deps.audit.append({ action: 'key.deleted', subject: run.keyref, at: now(), detail: { run_id: run.runId, platform: ledger.platform, gens: erased.gens, destinations: erased.destinations } });
    deps.approvals.executed(ledger.approvalId, 'done', 'ok');
    return 'continue';
  };

  async function step(run: RunRow, ctx: DeletionContext): Promise<'continue' | 'wait'> {
    const ledger = ledgers.ofRun(run.runId);
    if (ledger === undefined) {
      store.update(run.runId, { state: 'abandoned' });
      deps.audit.append({ action: 'rotation.drive_failed', subject: run.keyref, at: now(), detail: { run_id: run.runId, code: 'delete_unlinked' } });
      return 'continue';
    }
    if (ledger.confirmedAt !== null) return erase(run, ledger, ctx);
    ledgers.stopUse(run.keyref);
    deps.expireNaming(run.keyref);

    const live = store.gens(run.keyref).filter(isLive);
    if (live.length === 0) {
      ledgers.confirm(run.runId);
      await ctx.point('delete_confirmed');
      return 'continue';
    }
    const head = store.key(run.keyref);
    const kit = head === undefined ? undefined : kitFor(deps.source, head);
    if (head === undefined || kit === undefined) return unconfirmed(run, ledger, head, kit, live, ctx);
    if (!ledger.notified && live.some((g) => enderOf(kit, g.platformKeyId) === 'owner')) notifyOnce(run, head, 'end');
    const fresh = ledgers.ofRun(run.runId) ?? ledger;

    // Strict order: every live grace generation first (ascending), the current one only when none is left.
    const grace = live.filter((g) => g.status === 'grace').sort((a, b) => a.gen - b.gen);
    const gens = grace.length > 0 ? grace : live;
    const info = store.keyInfo(run.keyref);
    // The master the batch is ended and asked about with: a master key's own current value, any other key its platform's master.
    const master = revokeMasterOf(deps.source, vault, head, info);
    if (master === undefined) return unconfirmed(run, fresh, head, kit, live, ctx);
    const batch = gens.map((gen) => ({ gen, target: revokeTargetOf(vault, head, info, kit, gen, master) }));

    if (fresh.deadSeenAt === null) {
      for (const { target } of batch) await end(target);
      await ctx.point('delete_end_called');
      if (!(await allRevoked(head, batch))) return unconfirmed(run, fresh, head, kit, live, ctx);
      ledgers.setDeadSeen(run.runId, now());
      await ctx.point('delete_dead_seen');
      ctx.later(DEAD_GAP_MS);
      return 'wait';
    }
    const since = now() - fresh.deadSeenAt;
    if (since < DEAD_GAP_MS) {
      ctx.later(DEAD_GAP_MS - since);
      return 'wait';
    }
    // The second verdict asks the evidence only: no second end call.
    if (!(await allRevoked(head, batch))) return unconfirmed(run, fresh, head, kit, live, ctx);
    const last = gens.length === live.length;
    ledgers.retireBatch(run.keyref, run.runId, gens.map((g) => g.gen), last);
    for (let i = 0; i < gens.length; i += 1) deps.audit.append({ action: 'key.revoked', subject: run.keyref, at: now() });
    if (last) await ctx.point('delete_confirmed');
    return 'continue';
  }

  return { step };
}
