// The approval half of core, wired from the store half's parts: approvers, approvals, machine tokens, their routes and the
// executors of the kinds this unit owns. main-core.ts and the tests wire the same function, so a test runs what the service
// runs. Kept apart from core.ts so the shared test kit (which starts the store half) never reaches the verifier (KBOX-35).
import type { Clock } from '../ports/clock.ts';
import type { ApproverStore } from '../ports/private.ts';
import type { Push, PushSubscriptions } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { TrustPort } from '../ports/trust.ts';
import type { Action, ActionKind, Destination } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { vetWired } from '../pure/proposal-vet.ts';
import { createApprovals } from './approvals.ts';
import type { Approvals, ApprovalsDeps, ExecuteResult, Executor } from './approvals.ts';
import { createApprovers } from './approvers.ts';
import type { Approvers } from './approvers.ts';
import type { CoreParts } from './core.ts';
import type { Route } from './http.ts';
import { approveRoutes } from './routes-approve.ts';
import { createMachineTokens } from './tokens.ts';
import type { MachineTokens } from './tokens.ts';

export interface ApproveCoreDeps {
  readonly parts: CoreParts;
  readonly approverStore: ApproverStore;
  readonly trust: TrustPort;
  readonly push: Push & PushSubscriptions;
  readonly clock: Clock;
  readonly random: Random;
  readonly domain: string;
  readonly wordlist: readonly string[];
  /** Proposal-time checks that need an adapter's profile. With no adapter registered, every kind that needs one is refused. */
  readonly vet: (action: Action) => 'ok' | 'rejected';
  /** true: a kind with no executor in the wiring below (this unit's own and `executors`) is refused at proposal time, whatever `vet` says. */
  readonly refuseUnwired?: true;
  /** Executors of kinds other units own (rotation, update, Vercel). */
  readonly executors?: Partial<Readonly<Record<ActionKind, Executor>>>;
  /** What an install_update changes, for its page (the update unit counts it). */
  readonly updateChanges?: ApprovalsDeps['updateChanges'];
  /** What a page needs of the key it is about (KBOX-60), from the unit that owns the check. */
  readonly pageFacts?: ApprovalsDeps['pageFacts'];
  /** A proposal-time check that needs a platform call (KBOX-24's grant check), run by the proposal route before the proposal is made. */
  readonly precheck?: (action: Action) => Promise<void>;
}

export interface ApproveCore {
  readonly approvals: Approvals;
  readonly approvers: Approvers;
  readonly tokens: MachineTokens;
  /** The kinds that have an executor here: what an approval of that kind can do when it is decided. */
  readonly executorKinds: ReadonlySet<ActionKind>;
  readonly routes: readonly Route[];
}

/**
 * KBOX-60 F3: the kinds whose approval is picked up again by the unit that owns it: the updater resumes an `install_update`; a `rotate_key` or
 * `add_key` that opened its run resumes as a run. Every other kind is recorded `interrupted` if it was cut off, never executed again.
 */
const RESUMES_ITSELF: readonly ActionKind[] = ['install_update', 'rotate_key', 'add_key'];

/** The meta destination row of an action's destination: where the key goes and who can read it there. */
const metaDestination = (d: Destination): { kind: string; target: string; readable_by: 'api' | 'runtime' } => ({
  kind: d.kind,
  target: d.kind === 'workstation' ? 'workstation' : d.target,
  readable_by: d.kind === 'workstation' ? 'api' : 'runtime',
});

/** A metadata write as an execution result: a refusal of the store is a recorded failure, never a thrown request. */
function attempt(write: () => void, reason: string): ExecuteResult {
  try {
    write();
    return { result: 'done' };
  } catch (error) {
    if (error instanceof ApiError && error.code === 'internal') throw error;
    return { result: 'failed', reason };
  }
}

export function openApproveCore(deps: ApproveCoreDeps): ApproveCore {
  const { parts } = deps;
  const approvers = createApprovers({ store: deps.approverStore, trust: deps.trust, push: deps.push, audit: parts.audit, clock: deps.clock, random: deps.random, domain: deps.domain, wordlist: deps.wordlist });
  const own: Partial<Record<ActionKind, Executor>> = {
    grant: (a) => {
      const action = a.action;
      if (action.kind !== 'grant') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      return Promise.resolve(attempt(() => parts.meta.putGrant(action.keyref, action.machine), 'unknown_key'));
    },
    revoke_grant: (a) => {
      const action = a.action;
      if (action.kind !== 'revoke_grant') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      return Promise.resolve(attempt(() => parts.meta.removeGrant(action.keyref, action.machine), 'no_such_grant'));
    },
    add_destination: (a) => {
      const action = a.action;
      if (action.kind !== 'add_destination') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      return Promise.resolve(attempt(() => parts.meta.putDestination(action.keyref, metaDestination(action.destination)), 'unknown_key'));
    },
    remove_destination: (a) => {
      const action = a.action;
      if (action.kind !== 'remove_destination') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      const d = metaDestination(action.destination);
      return Promise.resolve(attempt(() => parts.meta.removeDestination(action.keyref, d.kind, d.target), 'no_such_destination'));
    },
    enrol: (a) => {
      const action = a.action;
      if (action.kind !== 'enrol') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
      return Promise.resolve(attempt(() => parts.meta.addMachine({ label: action.label, scope: 'relay', tokenSha256: action.token_sha256, enrolledAt: deps.clock.now() }), 'label_taken'));
    },
    approver_add: async (a) => {
      const action = a.action;
      if (action.kind !== 'approver_add' || a.proof === undefined) return { result: 'failed', reason: 'wrong_kind' };
      const added = await approvers.add(action, a.proof);
      return added === 'done' ? { result: 'done' } : { result: 'failed', reason: added };
    },
    approver_remove: async (a) => {
      const action = a.action;
      if (action.kind !== 'approver_remove' || a.proof === undefined) return { result: 'failed', reason: 'wrong_kind' };
      return (await approvers.remove(action.approver_id, a.proof)) === 'done' ? { result: 'done' } : { result: 'failed', reason: 'root_refused' };
    },
  };
  const executors: Partial<Record<ActionKind, Executor>> = { ...deps.executors, ...own };
  const executorKinds = new Set(Object.keys(executors) as ActionKind[]);
  const approvals = createApprovals({
    db: parts.db,
    hub: parts.hub,
    clock: deps.clock,
    random: deps.random,
    audit: parts.audit,
    push: deps.push,
    meta: parts.meta,
    approvers,
    vet: deps.refuseUnwired === true ? vetWired(executorKinds, deps.vet) : deps.vet,
    executors,
    ...(deps.updateChanges === undefined ? {} : { updateChanges: deps.updateChanges }),
    ...(deps.pageFacts === undefined ? {} : { pageFacts: deps.pageFacts }),
  });
  // KBOX-60 F3: opening is the start, before anything is served. An approval cut off after it was approved is recorded and never run again.
  approvals.interruptStranded(RESUMES_ITSELF);
  const tokens = createMachineTokens({ meta: parts.meta, events: parts.events, approvals, push: deps.push, audit: parts.audit, clock: deps.clock });
  return { approvals, approvers, tokens, executorKinds, routes: approveRoutes({ approvals, approvers, tokens, meta: parts.meta, push: deps.push, ...(deps.precheck === undefined ? {} : { precheck: deps.precheck }) }) };
}
