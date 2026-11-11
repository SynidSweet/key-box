// KBOX-7: slots against approval fatigue. Every proposal sits in one slot named by kind and subject; one proposal is
// pending per slot. Who may replace a pending proposal, and when a push goes out, is decided here and nowhere else.
import type { Action } from './actions.ts';

/** Who asked: a machine token by its label, the box itself (a schedule, a platform expiry), or an unauthenticated enrol. */
export type Requester =
  | { readonly kind: 'token'; readonly label: string }
  | { readonly kind: 'box' }
  | { readonly kind: 'enrol'; readonly address: string }
  | { readonly kind: 'approver'; readonly approverId: string };

/** The slot of an action: kind (or shared kind) and subject. */
export function slotOf(action: Action): string {
  switch (action.kind) {
    case 'add_key':
      return `add_key:${action.platform}`;
    case 'delete_key':
    case 'rotate_key':
    case 'demote':
    case 'set_allow_rules':
    case 'set_schedule':
      return `${action.kind}:${action.keyref}`;
    case 'grant':
    case 'revoke_grant':
      return `grant:${action.keyref}`;
    case 'add_destination':
    case 'remove_destination':
      return `destination:${action.keyref}`;
    case 'enrol':
      return `enrol:${action.address}`;
    case 'vercel_set_domain':
      return `vercel_set_domain:${action.project}:${action.op}`;
    case 'vercel_set_team_setting':
      return `vercel_set_team_setting:${action.setting}`;
    case 'approver_remove':
      return `approver_remove:${action.approver_id}`;
    case 'approver_add':
    case 'install_update':
      return action.kind;
  }
}

/**
 * What a new proposal does to its slot. `open`: the slot was free. `replace`: the same requester asks again, so the pending
 * content is replaced under the same approval id. `takeover`: the box itself takes an occupied slot. `taken`: refused 409.
 */
export type SlotDecision = 'open' | 'replace' | 'takeover' | 'taken';

export function decideSlot(pending: Requester | undefined, incoming: Requester): SlotDecision {
  if (pending === undefined) return 'open';
  if (sameRequester(pending, incoming)) return 'replace';
  return incoming.kind === 'box' ? 'takeover' : 'taken';
}

function sameRequester(a: Requester, b: Requester): boolean {
  if (a.kind === 'token' && b.kind === 'token') return a.label === b.label;
  if (a.kind === 'enrol' && b.kind === 'enrol') return a.address === b.address;
  if (a.kind === 'approver' && b.kind === 'approver') return a.approverId === b.approverId;
  return a.kind === 'box' && b.kind === 'box';
}

/**
 * Whether opening a slot sends a push. A replacement or a takeover sends none (one push per slot). Enrol proposals share one
 * push while any earlier enrol push is unseen; the push then says only how many wait.
 */
export function pushOnOpen(decision: SlotDecision, action: Action, enrolPushUnseen: boolean): boolean {
  if (decision !== 'open') return false;
  return action.kind !== 'enrol' || !enrolPushUnseen;
}

export function requesterText(r: Requester): string {
  switch (r.kind) {
    case 'token':
      return `token:${r.label}`;
    case 'box':
      return 'box';
    case 'enrol':
      return `enrol:${r.address}`;
    case 'approver':
      return `approver:${r.approverId}`;
  }
}

export function parseRequester(s: string): Requester | undefined {
  if (s === 'box') return { kind: 'box' };
  if (s.startsWith('token:')) return { kind: 'token', label: s.slice(6) };
  if (s.startsWith('enrol:')) return { kind: 'enrol', address: s.slice(6) };
  if (s.startsWith('approver:')) return { kind: 'approver', approverId: s.slice(9) };
  return undefined;
}
