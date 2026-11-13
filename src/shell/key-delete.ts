// KBOX-62: the approval half of deleting a key: the one check (at proposal and again at execution), the executor that opens the deletion and
// launches its run, the page's facts, and the start-up settle that records what a crash left. The run itself is `delete-run.ts`'s.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { Vault } from '../ports/vault.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import type { DeletionFacts, PageContext } from '../pure/words.ts';
import type { Approvals, Executor } from './approvals.ts';
import type { DeletionStore } from './deletion-store.ts';
import type { Orchestrator } from './orchestrator.ts';
import { enderOf, revokedPath } from './revoke-confirm.ts';
import { kindOfStored, kitFor, tryLend } from './rotation-ports.ts';
import type { DeletePoint, PlatformKit, PlatformSource } from './rotation-ports.ts';
import type { GenRow, KeyHead, RotationStore, RunRow } from './rotation-store.ts';

export interface KeyDeleteDeps {
  readonly store: RotationStore;
  readonly ledgers: DeletionStore;
  readonly source: PlatformSource;
  readonly vault: Pick<Vault, 'lend'>;
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly approvals: Pick<Approvals, 'executed' | 'interruptOne' | 'waiting'>;
  /** Expires every pending approval and paste task naming the key. */
  readonly expireNaming: (keyref: string) => void;
  readonly orchestrator: Pick<Orchestrator, 'isLeased' | 'launch'>;
  readonly audit: Audit;
  readonly clock: Clock;
  readonly random: Random;
  /** Where a test stops the process; production passes none. */
  readonly checkpoint?: (point: DeletePoint) => void | Promise<void>;
}

export interface KeyDelete {
  /** F2: throws `ApiError` (`rejected`, or `conflict` for an open run) when a `delete_key` must not open, and `key_deleting` for any other kind naming a key being deleted. */
  precheck(action: Action): void;
  readonly executor: Executor;
  /** What the delete page says that the action does not (KBOX-8); nothing for any other kind. */
  pageFacts(action: Action): Pick<PageContext, 'deletion'>;
  /** Start-up, after the approval half opened and before rotation runs: records what a crash or the release before left (see KBOX-62). */
  settle(): void;
}

interface Refusal {
  readonly answer: 'rejected' | 'conflict';
  readonly code: string;
}
interface Cleared {
  readonly head: KeyHead;
  readonly live: readonly GenRow[];
  /** The unleased `grace` or `revoking` run the deletion supersedes. */
  readonly supersede?: RunRow;
}

const SUPERSEDABLE: readonly string[] = ['grace', 'revoking'];
const ENDED: readonly string[] = ['done', 'failed', 'abandoned'];
const isLive = (g: GenRow): boolean => g.status === 'current' || g.status === 'grace';

export function createKeyDelete(deps: KeyDeleteDeps): KeyDelete {
  const { store, ledgers, source } = deps;

  /** KBOX-57: this master serves another stored key of its platform (fail closed on a source that cannot tell). */
  const servesAnother = (head: KeyHead): boolean => {
    if (head.class !== 'master') return false;
    return store.keys().some((other) => {
      if (other.platform !== head.platform || other.keyref === head.keyref) return false;
      const info = store.keyInfo(other.keyref);
      if (info === undefined) return false;
      return source.masterKeyrefOf === undefined || source.masterKeyrefOf(head.platform, info.location, info.scopeItems) === head.keyref;
    });
  };

  /** Every live generation has a proof path on proven evidence; a master's own current generation only by the verifier. */
  const provable = (head: KeyHead, kit: PlatformKit, live: readonly GenRow[]): boolean => {
    const kind = kindOfStored(store.keyInfo(head.keyref));
    return live.every((g) => revokedPath(kit, kind, g.platformKeyId, tryLend(deps.vault, head.keyref, g.gen).ok, !(head.class === 'master' && g.status === 'current')) !== undefined);
  };

  const masterRefusal = (head: KeyHead): Refusal | undefined => {
    if (head.class === 'master') return undefined;
    const info = store.keyInfo(head.keyref);
    if (info === undefined) return { answer: 'rejected', code: 'no_master' };
    const master = source.master(head.platform, info.location, info.scopeItems);
    return master.ok ? undefined : { answer: 'rejected', code: master.code };
  };

  /** The one check, in its order (KBOX-62). At execution `run_exists` is `run_open`, and so is a supersedable run this process works on. */
  const check = (keyref: string, at: 'proposal' | 'execution'): Cleared | Refusal => {
    const head = store.key(keyref);
    if (head === undefined) return { answer: 'rejected', code: 'unknown_key' };
    const kit = kitFor(source, head);
    if (kit?.boxKey !== undefined) return { answer: 'rejected', code: 'box_made' };
    if (kit === undefined) return { answer: 'rejected', code: 'unknown_platform' };
    if (ledgers.isOpen(keyref)) return { answer: 'rejected', code: 'key_deleting' };
    const run = store.activeRunOf(keyref);
    if (run !== undefined && !SUPERSEDABLE.includes(run.state)) return { answer: 'conflict', code: at === 'proposal' ? 'run_exists' : 'run_open' };
    if (run !== undefined && at === 'execution' && deps.orchestrator.isLeased(keyref)) return { answer: 'conflict', code: 'run_open' };
    if (servesAnother(head)) return { answer: 'rejected', code: 'master_in_use' };
    const live = store.gens(keyref).filter(isLive);
    if (!provable(head, kit, live)) return { answer: 'rejected', code: 'cannot_confirm' };
    const noMaster = live.length === 0 ? undefined : masterRefusal(head);
    if (noMaster !== undefined) return noMaster;
    return { head, live, ...(run === undefined ? {} : { supersede: run }) };
  };
  const refused = (found: Cleared | Refusal): found is Refusal => 'answer' in found;

  const precheck: KeyDelete['precheck'] = (action) => {
    if (action.kind === 'delete_key') {
      const found = check(action.keyref, 'proposal');
      if (refused(found)) throw new ApiError(found.answer, found.code);
      return;
    }
    if ('keyref' in action && ledgers.isOpen(action.keyref)) throw new ApiError('rejected', 'key_deleting');
  };

  const executor: Executor = async (approval) => {
    const action = approval.action;
    if (action.kind !== 'delete_key') return { result: 'failed', reason: 'wrong_kind' };
    const found = check(action.keyref, 'execution');
    if (refused(found)) return { result: 'failed', reason: found.code };
    const runId = `run_${Buffer.from(deps.random.bytes(8)).toString('hex')}`;
    try {
      ledgers.open({
        approvalId: approval.approvalId,
        keyref: action.keyref,
        platform: found.head.platform,
        runId,
        gen: found.head.genCurrent,
        intentName: `delete_${runId.slice(4, 12)}`,
        ...(found.supersede === undefined ? {} : { supersede: found.supersede.runId }),
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'conflict') return { result: 'failed', reason: 'run_open' };
      throw error;
    }
    deps.audit.append({
      action: 'key.delete_started',
      subject: action.keyref,
      at: deps.clock.now(),
      detail: { run_id: runId, live_gens: found.live.length, ...(found.supersede === undefined ? {} : { superseded_run: found.supersede.runId }) },
    });
    deps.expireNaming(action.keyref);
    await deps.checkpoint?.('delete_opened');
    deps.orchestrator.launch(runId);
    return { result: 'waiting' };
  };

  const pageFacts: KeyDelete['pageFacts'] = (action) => {
    if (action.kind !== 'delete_key') return {};
    const head = store.key(action.keyref);
    const kit = head === undefined ? undefined : kitFor(source, head);
    if (head === undefined || kit === undefined) return {};
    const live = store.gens(head.keyref).filter(isLive);
    const ends: DeletionFacts['ends'] = live.length === 0 ? 'none' : live.some((g) => enderOf(kit, g.platformKeyId) === 'owner') ? 'owner' : 'box';
    const row = deps.meta.snapshot().keys.find((k) => k.keyref === head.keyref);
    const run = store.activeRunOf(head.keyref);
    const deletion: DeletionFacts = {
      platform: head.platform,
      ends,
      targets: store.destinationsOf(head.keyref).map((d) => (d.target === '' ? d.kind : d.target)),
      grants: (row?.grants.length ?? 0) > 0,
      midChange: run !== undefined && SUPERSEDABLE.includes(run.state),
    };
    return { deletion };
  };

  const settle: KeyDelete['settle'] = () => {
    for (const waiting of deps.approvals.waiting('delete_key')) {
      const ledger = ledgers.ofApproval(waiting.approvalId);
      // Approved, but the executor never opened it (a crash before open), or the repair below already closed it abandoned.
      if (ledger === undefined || ledger.outcome === 'abandoned') deps.approvals.interruptOne(waiting.approvalId);
      else if (ledger.outcome === 'erased') deps.approvals.executed(waiting.approvalId, 'done', 'ok');
    }
    for (const ledger of ledgers.openLedgers()) {
      const run = store.run(ledger.runId);
      if (run !== undefined && !ENDED.includes(run.state)) continue;
      if (store.key(ledger.keyref) !== undefined) {
        // The release before ended the run (its rollback marks it done) or it was abandoned: the key stays stored.
        ledgers.close(ledger.approvalId, 'abandoned');
        deps.approvals.interruptOne(ledger.approvalId);
        continue;
      }
      ledgers.close(ledger.approvalId, 'erased');
      if (deps.approvals.waiting('delete_key').some((w) => w.approvalId === ledger.approvalId)) deps.approvals.executed(ledger.approvalId, 'done', 'ok');
      deps.audit.append({ action: 'rotation.drive_failed', subject: ledger.keyref, at: deps.clock.now(), detail: { run_id: ledger.runId, code: 'delete_ledger_repaired' } });
    }
  };

  return { precheck, executor, pageFacts, settle };
}
