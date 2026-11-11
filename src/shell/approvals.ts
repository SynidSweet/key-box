// KBOX-7, KBOX-8, KBOX-9, KBOX-53: proposals, slots, the page words, decisions and execution. A proposal is stored as typed
// data with its digest; the phone signs `approvalChallenge(id, stored digest, nonce)` where the nonce names the approval and
// its revision, so an assertion for one action, one revision or one render can approve nothing else. An approval executes
// by its stored id and stored action, never from a client body.
import type { DatabaseSync } from 'node:sqlite';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventSignal } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { ApprovalProof } from '../ports/trust.ts';
import { parseAction } from '../pure/actions.ts';
import type { Action, ActionKind } from '../pure/actions.ts';
import { actionDigest, approvalChallenge } from '../pure/challenge.ts';
import { ApiError } from '../pure/errors.ts';
import { decideSlot, parseRequester, pushOnOpen, requesterText, slotOf } from '../pure/slots.ts';
import type { Requester, SlotDecision } from '../pure/slots.ts';
import { renderPage, titleOf } from '../pure/words.ts';
import type { Reason } from '../pure/words.ts';
import { inTransaction } from './db.ts';
import { insertEvent } from './events.ts';
import type { Approvers, ProofBytes } from './approvers.ts';

/** Pending proposals expire after 14 days (KBOX-7). */
export const PROPOSAL_TTL_MS = 14 * 24 * 3600_000;

/** Kinds whose approval proof is kept with the approval, because root verifies it again itself (KBOX-6, KBOX-9). */
const PROOF_KEPT: readonly ActionKind[] = ['install_update', 'approver_add', 'approver_remove'];

export type ExecuteResult = { readonly result: 'done' } | { readonly result: 'failed'; readonly reason: string } | { readonly result: 'waiting' };

/** Runs an approved action. Other units add theirs (rotation, update, Vercel); a kind with none is recorded `failed: no_executor`. */
export type Executor = (approval: StoredApproval) => Promise<ExecuteResult>;

export interface StoredApproval {
  readonly approvalId: string;
  readonly revision: number;
  readonly action: Action;
  readonly requester: Requester;
  readonly proof: ApprovalProof | undefined;
}

export interface ApprovalsDeps {
  readonly db: DatabaseSync;
  readonly hub: EventSignal;
  readonly clock: Clock;
  readonly random: Random;
  readonly audit: Audit;
  readonly push: Push;
  readonly meta: MetaStore;
  readonly approvers: Approvers;
  /** Proposal-time checks that need a platform's profile (a `mustDeny` match, an operation the profile does not declare). */
  readonly vet: (action: Action) => 'ok' | 'rejected';
  readonly executors: Partial<Readonly<Record<ActionKind, Executor>>>;
}

export interface Proposed {
  readonly approval_id: string;
  readonly status: 'pending';
  readonly slot: string;
  readonly revision: number;
  readonly replaced: boolean;
}

export interface QueueItem {
  readonly approval_id: string;
  readonly revision: number;
  readonly kind: ActionKind;
  readonly title: string;
  readonly lines: readonly string[];
  readonly digest_b64: string;
  readonly nonce_b64: string;
  readonly expires_at: number;
}

export type DecideOutcome = { readonly decision: 'approved'; readonly execution: ExecuteResult; readonly registrationCode?: string } | { readonly decision: 'denied' };

export interface Approvals {
  propose(input: { readonly action: Action; readonly requester: Requester; readonly reason?: Reason }): Proposed;
  /** The pending approvals, each rendered with a fresh nonce. Viewing the queue marks the coalesced enrol push seen. */
  queue(): readonly QueueItem[];
  decide(approvalId: string, decision: 'approve' | 'deny', proof: ProofBytes): Promise<DecideOutcome>;
  /** The status of the enrol proposal or machine for a token hash; undefined when the box knows nothing of it. */
  enrolStatus(tokenSha256: string): 'pending' | 'approved' | 'denied' | 'expired' | undefined;
  /** The proof kept with an approved install_update, approver_add or approver_remove. */
  storedProof(approvalId: string): ApprovalProof | undefined;
  /** Marks a waiting execution (approver_add) finished. */
  executed(approvalId: string, result: 'done' | 'failed', reason: string): void;
  /** Expires every pending proposal older than 14 days. */
  sweep(): void;
}

interface Row {
  readonly approval_id: string;
  readonly kind: string;
  readonly slot: string;
  readonly opened_at: number;
  readonly expires_at: number;
  readonly status: string;
  readonly revision: number;
  readonly requester: string;
  readonly action_json: string;
  readonly digest_hex: string;
  readonly reason_json: string | null;
  readonly proof_json: string | null;
}

const COLUMNS = 'approval_id, kind, slot, opened_at, expires_at, status, revision, requester, action_json, digest_hex, reason_json, proof_json';

function actionOf(row: Row): Action {
  const parsed = parseAction(JSON.parse(row.action_json));
  if (!parsed.ok) throw new ApiError('internal');
  return parsed.value;
}

function requesterOf(row: Row): Requester {
  const r = parseRequester(row.requester);
  if (r === undefined) throw new ApiError('internal');
  return r;
}

export function createApprovals(deps: ApprovalsDeps): Approvals {
  const { db } = deps;
  let enrolPushUnseen = false;

  const write = <T>(work: () => T): T => {
    const result = inTransaction(db, work);
    deps.hub.notify();
    return result;
  };
  const row = (approvalId: string): Row | undefined => db.prepare(`SELECT ${COLUMNS} FROM approvals WHERE approval_id = ?`).get(approvalId) as Row | undefined;
  const pendingIn = (slot: string): Row | undefined => db.prepare(`SELECT ${COLUMNS} FROM approvals WHERE slot = ? AND status = 'pending'`).get(slot) as Row | undefined;
  const pendingRows = (): Row[] => db.prepare(`SELECT ${COLUMNS} FROM approvals WHERE status = 'pending' ORDER BY opened_at, approval_id`).all() as unknown as Row[];
  const audit = (action: Parameters<Audit['append']>[0]['action'], subject: string, detail: Readonly<Record<string, string | number | boolean>>, actor?: string): void =>
    deps.audit.append({ action, subject, at: deps.clock.now(), detail, ...(actor === undefined ? {} : { actor }) });

  const sweep = (): void => {
    deps.approvers.expire();
    const now = deps.clock.now();
    const stale = db.prepare("SELECT approval_id FROM approvals WHERE status = 'pending' AND expires_at <= ?").all(now) as unknown as { approval_id: string }[];
    if (stale.length === 0) return;
    write(() => {
      for (const { approval_id } of stale) {
        db.prepare("UPDATE approvals SET status = 'expired', decided_at = ? WHERE approval_id = ?").run(now, approval_id);
        insertEvent(db, now, 'approval.decided', { approval_id, decision: 'expired' });
      }
    });
    for (const { approval_id } of stale) audit('approval.decided', approval_id, { decision: 'expired' });
  };

  const coverage = (action: Action): 'windowed' | 'anchored' | 'none' | null | undefined => ('keyref' in action ? deps.meta.coverageOf(action.keyref) : undefined);

  const enrolPush = (): void => {
    const waiting = (db.prepare("SELECT count(*) AS n FROM approvals WHERE status = 'pending' AND kind = 'enrol'").get() as { n: number }).n;
    deps.push.send({ title: 'Machines wait to be enrolled', kind: 'enrol', count: waiting });
    enrolPushUnseen = true;
  };

  const propose: Approvals['propose'] = ({ action, requester, reason }) => {
    sweep();
    if (deps.vet(action) === 'rejected') throw new ApiError('rejected', 'not_allowed');
    if (action.kind === 'approver_remove') {
      const ids = deps.approvers.ids();
      if (!ids.includes(action.approver_id)) throw new ApiError('rejected', 'unknown_approver');
      if (ids.length <= 1) throw new ApiError('rejected', 'last_approver');
    }
    const slot = slotOf(action);
    const title = titleOf(action);
    const digest = Buffer.from(actionDigest(action)).toString('hex');
    const now = deps.clock.now();
    const held = pendingIn(slot);
    const decision: SlotDecision = decideSlot(held === undefined ? undefined : requesterOf(held), requester);
    if (decision === 'taken' && held !== undefined) throw new ApiError('slot_taken', { pending_approval_id: held.approval_id });
    const reasonJson = reason === undefined ? null : JSON.stringify(reason);
    const outcome = write(() => {
      if (held === undefined || decision === 'open') {
        const approvalId = `apr_${Buffer.from(deps.random.bytes(12)).toString('base64url')}`;
        db.prepare(`INSERT INTO approvals (approval_id, kind, title, slot, opened_at, expires_at, status, revision, requester, action_json, digest_hex, reason_json) VALUES (?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?, ?)`).run(
          approvalId,
          action.kind,
          title,
          slot,
          now,
          now + PROPOSAL_TTL_MS,
          requesterText(requester),
          JSON.stringify(action),
          digest,
          reasonJson,
        );
        insertEvent(db, now, 'approval.opened', { approval_id: approvalId, approval_kind: action.kind, title, slot, revision: 1 });
        return { approvalId, revision: 1 };
      }
      const revision = held.revision + 1;
      db.prepare('UPDATE approvals SET kind = ?, title = ?, revision = ?, requester = ?, action_json = ?, digest_hex = ?, reason_json = ? WHERE approval_id = ?').run(
        action.kind,
        title,
        revision,
        requesterText(requester),
        JSON.stringify(action),
        digest,
        reasonJson,
        held.approval_id,
      );
      insertEvent(db, now, 'approval.opened', { approval_id: held.approval_id, approval_kind: action.kind, title, slot, revision });
      return { approvalId: held.approval_id, revision };
    });
    audit('approval.proposed', outcome.approvalId, { kind: action.kind, slot, revision: outcome.revision, decision: decision === 'taken' ? 'open' : decision });
    if (pushOnOpen(decision, action, enrolPushUnseen)) {
      if (action.kind === 'enrol') enrolPush();
      else deps.push.send({ title, kind: action.kind });
    }
    return { approval_id: outcome.approvalId, status: 'pending', slot, revision: outcome.revision, replaced: decision !== 'open' };
  };

  const queue = (): readonly QueueItem[] => {
    sweep();
    enrolPushUnseen = false;
    return pendingRows().map((r) => {
      const action = actionOf(r);
      const reason = r.reason_json === null ? undefined : (JSON.parse(r.reason_json) as Reason);
      const cov = coverage(action);
      const page = renderPage(action, { requester: requesterOf(r), ...(reason === undefined ? {} : { reason }), ...(cov === undefined ? {} : { coverage: cov }) });
      const nonce = deps.approvers.nonce({ kind: 'decide', approvalId: r.approval_id, revision: r.revision });
      return {
        approval_id: r.approval_id,
        revision: r.revision,
        kind: action.kind,
        title: page.title,
        lines: page.lines,
        digest_b64: Buffer.from(r.digest_hex, 'hex').toString('base64url'),
        nonce_b64: Buffer.from(nonce).toString('base64url'),
        expires_at: r.expires_at,
      };
    });
  };

  const executed = (approvalId: string, result: 'done' | 'failed', reason: string): void => {
    write(() => {
      db.prepare('UPDATE approvals SET result = ?, result_code = ? WHERE approval_id = ?').run(result, reason, approvalId);
      insertEvent(db, deps.clock.now(), 'approval.executed', { approval_id: approvalId, result, reason_code: reason });
    });
    audit('approval.executed', approvalId, { result, reason_code: reason });
  };

  const decide: Approvals['decide'] = async (approvalId, decision, proof) => {
    sweep();
    const held = row(approvalId);
    if (held === undefined) throw new ApiError('not_found');
    if (held.status !== 'pending') throw new ApiError('conflict', 'not_pending');
    const digest = Uint8Array.from(Buffer.from(held.digest_hex, 'hex'));
    const verdict = deps.approvers.check({ kind: 'decide', approvalId, revision: held.revision }, (nonce) => approvalChallenge(approvalId, digest, nonce), proof);
    if (!verdict.ok) throw new ApiError('forbidden', 'proof_refused');
    const action = actionOf(held);
    const now = deps.clock.now();
    const kept: ApprovalProof = { approval_id: approvalId, ...verdict.proof };
    const status = decision === 'approve' ? 'approved' : 'denied';
    const changed = write(() => {
      const done = db
        .prepare("UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, proof_json = ? WHERE approval_id = ? AND status = 'pending' AND revision = ? AND digest_hex = ?")
        .run(status, now, verdict.approverId, decision === 'approve' && PROOF_KEPT.includes(action.kind) ? JSON.stringify(kept) : null, approvalId, held.revision, held.digest_hex).changes;
      if (done === 1) insertEvent(db, now, 'approval.decided', { approval_id: approvalId, decision: status });
      return done === 1;
    });
    if (!changed) throw new ApiError('conflict', 'not_pending');
    audit('approval.decided', approvalId, { decision: status }, verdict.approverId);
    if (decision === 'deny') return { decision: 'denied' };

    const stored: StoredApproval = { approvalId, revision: held.revision, action, requester: requesterOf(held), proof: PROOF_KEPT.includes(action.kind) ? kept : undefined };
    if (action.kind === 'approver_add') {
      const registrationCode = deps.approvers.startAdd(kept, (result, reason) => executed(approvalId, result, result === 'done' ? 'ok' : reason));
      return { decision: 'approved', execution: { result: 'waiting' }, registrationCode };
    }
    const executor = deps.executors[action.kind];
    const execution: ExecuteResult = executor === undefined ? { result: 'failed', reason: 'no_executor' } : await executor(stored);
    if (execution.result !== 'waiting') executed(approvalId, execution.result, execution.result === 'done' ? 'ok' : execution.reason);
    return { decision: 'approved', execution };
  };

  return {
    propose,
    queue,
    decide,
    executed,
    sweep,
    enrolStatus(tokenSha256) {
      sweep();
      if (db.prepare('SELECT 1 AS one FROM machines WHERE token_sha256 = ?').get(tokenSha256) !== undefined) return 'approved';
      const rows = db.prepare(`SELECT ${COLUMNS} FROM approvals WHERE kind = 'enrol' ORDER BY opened_at DESC`).all() as unknown as Row[];
      const found = rows.find((r) => {
        const a = actionOf(r);
        return a.kind === 'enrol' && a.token_sha256 === tokenSha256;
      });
      if (found === undefined) return undefined;
      // An approved enrol whose machine could not be added (its label was taken meanwhile) did not enrol anything.
      return found.status === 'pending' ? 'pending' : found.status === 'expired' ? 'expired' : 'denied';
    },
    storedProof(approvalId) {
      const r = row(approvalId);
      return r?.proof_json === null || r === undefined ? undefined : (JSON.parse(r.proof_json) as ApprovalProof);
    },
  };
}
