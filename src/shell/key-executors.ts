// KBOX-60, KBOX-61: the executors of `set_schedule`, `demote` and `set_allow_rules`, and the one check each kind makes. The proposal runs the check before an approval
// opens (F2); the executor runs the same check again on the state it finds, before it writes (F1): a proposal waits up to 14 days, and
// another approval or an update can change a key meanwhile. A refusal at execution is a recorded `failed` with the proposal's code.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { KeyClass } from '../ports/types.ts';
import type { Action } from '../pure/actions.ts';
import { lowerClass } from '../pure/class.ts';
import { ApiError } from '../pure/errors.ts';
import { classifierOf } from '../pure/platform-shape.ts';
import type { PageContext } from '../pure/words.ts';
import type { Executor } from './approvals.ts';
import { refuseBoxKeyAction } from './box-keys.ts';
import { classOfKey } from './new-key.ts';
import { kitFor } from './rotation-ports.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { KeyHead, RotationStore } from './rotation-store.ts';

/** Any action about one stored key; the kinds this file executes are narrowed by their callers. */
type OnKey = Extract<Action, { readonly keyref: string }>;

/** A check that did not pass: how a proposal answers (`rejected`, or `conflict` for an open run) and the reason code. */
interface Refusal {
  readonly answer: 'rejected' | 'conflict';
  readonly code: string;
}

const isRefusal = (found: unknown): found is Refusal => typeof found === 'object' && found !== null && 'answer' in found;

export interface KeyActionsDeps {
  /** The registry, for the box's own key (KBOX-55). */
  readonly registry: readonly PlatformEntry[];
  /** The platform kits, for the class a key's stored scope makes (KBOX-15). */
  readonly source: PlatformSource;
  readonly store: Pick<RotationStore, 'key' | 'keyInfo' | 'activeRunOf' | 'destinationsOf' | 'setSchedule' | 'demoteKey'>;
  readonly audit: Audit;
  readonly clock: Clock;
}

export interface KeyActions {
  readonly executors: { readonly set_schedule: Executor; readonly demote: Executor };
  /** F2: throws `ApiError` (`rejected`, or `conflict` for an open run) with the reason code when the proposal must not open. Other kinds pass. */
  precheck(action: Action): void;
  /** What the page of this action needs to know that the action does not say (KBOX-8); nothing for any other kind. */
  pageFacts(action: Action): Pick<PageContext, 'fallsTo' | 'runtimeDestination'>;
}

/** The reason code an `ApiError` carries, when it carries one. */
const codeOf = (error: ApiError): string => (error.detail !== undefined && 'code' in error.detail ? error.detail.code : error.code);

/** `run_exists` is what a proposal says of an open run; at execution the run is already there, so the approval says `run_open`. */
const atExecution = (code: string): string => (code === 'run_exists' ? 'run_open' : code);

export function createKeyActions(deps: KeyActionsDeps): KeyActions {
  const { store } = deps;

  /** What both kinds need first: the key exists and is not the box's own (KBOX-55, whose refusal is the one in `refuseBoxKeyAction`). */
  const keyOf = (action: OnKey): KeyHead | Refusal => {
    const head = store.key(action.keyref);
    if (head === undefined) return { answer: 'rejected', code: 'unknown_key' };
    try {
      refuseBoxKeyAction(deps.registry, action);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'rejected') return { answer: 'rejected', code: codeOf(error) };
      throw error;
    }
    return head;
  };

  /** The class a demote lands on: what the stored scope and location make the key without the owner's mark, when that is below its class. */
  const lowered = (head: KeyHead): KeyClass | Refusal => {
    const info = store.keyInfo(head.keyref);
    if (info === undefined) return { answer: 'rejected', code: 'nothing_to_lower' };
    const classify = classifierOf(kitFor(deps.source, { platform: head.platform, keyref: head.keyref }));
    if (classify === undefined) return { answer: 'rejected', code: 'unknown_platform' };
    return lowerClass(head.class, classOfKey(classify, info.scopeItems, info.location, undefined)) ?? { answer: 'rejected', code: 'nothing_to_lower' };
  };

  /** The demote check: the key, then what there is to lower, then whether a run holds the key. The head and the class it falls to, or the refusal. */
  const checkDemotion = (action: OnKey): { readonly head: KeyHead; readonly to: KeyClass } | Refusal => {
    const head = keyOf(action);
    if (isRefusal(head)) return head;
    const to = lowered(head);
    if (isRefusal(to)) return to;
    if (store.activeRunOf(head.keyref) !== undefined) return { answer: 'conflict', code: 'run_exists' };
    return { head, to };
  };

  const precheck: KeyActions['precheck'] = (action) => {
    const found = action.kind === 'set_schedule' ? keyOf(action) : action.kind === 'demote' ? checkDemotion(action) : undefined;
    if (found !== undefined && isRefusal(found)) throw new ApiError(found.answer, found.code);
  };

  const setSchedule: Executor = (approval) => {
    const action = approval.action;
    if (action.kind !== 'set_schedule') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
    const head = keyOf(action);
    if (isRefusal(head)) return Promise.resolve({ result: 'failed', reason: head.code });
    store.setSchedule(action.keyref, action.rotate_every_days, action.grace_hours);
    deps.audit.append({ action: 'key.schedule_set', subject: action.keyref, at: deps.clock.now(), detail: { rotate_every_days: action.rotate_every_days, grace_hours: action.grace_hours } });
    return Promise.resolve({ result: 'done' });
  };

  const demote: Executor = (approval) => {
    const action = approval.action;
    if (action.kind !== 'demote') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
    const found = checkDemotion(action);
    if (isRefusal(found)) return Promise.resolve({ result: 'failed', reason: atExecution(found.code) });
    store.demoteKey(action.keyref, found.to);
    deps.audit.append({ action: 'key.demoted', subject: action.keyref, at: deps.clock.now(), detail: { from: found.head.class, to: found.to } });
    return Promise.resolve({ result: 'done' });
  };

  const pageFacts: KeyActions['pageFacts'] = (action) => {
    if (action.kind === 'set_schedule') {
      return action.grace_hours === 0 && store.destinationsOf(action.keyref).some((d) => d.readable_by === 'runtime') ? { runtimeDestination: true } : {};
    }
    if (action.kind === 'demote') {
      const found = checkDemotion(action);
      return isRefusal(found) ? {} : { fallsTo: found.to };
    }
    return {};
  };

  return { executors: { set_schedule: setSchedule, demote }, precheck, pageFacts };
}

type SetAllowRules = Extract<Action, { readonly kind: 'set_allow_rules' }>;

export interface AllowRuleDeps {
  /** The registry, for each platform's relay profile. */
  readonly registry: readonly PlatformEntry[];
  readonly store: Pick<RotationStore, 'key'>;
  readonly meta: Pick<MetaStore, 'replaceAllowRules'>;
  readonly audit: Audit;
  readonly clock: Clock;
}

export interface AllowRuleActions {
  readonly executor: Executor;
  /** F2: throws `ApiError('rejected', <code>)` when a `set_allow_rules` proposal must not open. Other kinds pass. */
  precheck(action: Action): void;
}

/**
 * KBOX-61: a key's own allow set is a subset of its profile's rules (empty = all of them), so a set is checked against the key and the
 * profile as they are now. The one check behind both the proposal and the execution; the reason code, or nothing when it passes.
 */
export function createAllowRuleActions(deps: AllowRuleDeps): AllowRuleActions {
  const check = (action: SetAllowRules): string | undefined => {
    const head = deps.store.key(action.keyref);
    if (head === undefined) return 'unknown_key';
    if (head.class === 'master') return 'never_relayed';
    const profile = deps.registry.find((e) => e.id === head.platform)?.relay;
    if (profile === undefined) return 'no_profile';
    const seen = new Set<string>();
    for (const rule of action.rules) {
      if (Object.keys(rule.params).length > 0) return 'params_unsupported';
      if (!profile.allow.some((r) => r.id === rule.op)) return 'unknown_op';
      if (seen.has(rule.op)) return 'duplicate_op';
      seen.add(rule.op);
    }
    return undefined;
  };

  const precheck: AllowRuleActions['precheck'] = (action) => {
    const code = action.kind === 'set_allow_rules' ? check(action) : undefined;
    if (code !== undefined) throw new ApiError('rejected', code);
  };

  const executor: Executor = (approval) => {
    const action = approval.action;
    if (action.kind !== 'set_allow_rules') return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
    const code = check(action);
    if (code !== undefined) return Promise.resolve({ result: 'failed', reason: code });
    deps.meta.replaceAllowRules(action.keyref, action.rules.map((r) => r.op));
    deps.audit.append({ action: 'key.allow_rules_set', subject: action.keyref, at: deps.clock.now(), detail: { count: action.rules.length } });
    return Promise.resolve({ result: 'done' });
  };

  return { executor, precheck };
}
