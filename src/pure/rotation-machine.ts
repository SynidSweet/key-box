// KBOX-51, KBOX-17: the pure parts of the rotation state machine: the order of the steps, the intent name written before any
// platform call, the grace default, the retry schedule and what proves an old key dead. No I/O: the orchestrator does the work.
import type { KeyListing } from '../ports/issuer.ts';
import type { KeyLocation, PlatformKeyId } from '../ports/types.ts';

/** The steps of a run, in order. `issuing` covers create and store; `grace` is the wait before the old key is switched off. */
export type Step = 'issuing' | 'verifying' | 'pushing' | 'redeploying' | 'checking' | 'promoting' | 'grace' | 'revoking';
export type RunStep = Step | 'done';

/** What decides a key's steps: whether its platform can hold two valid keys, and whether the box makes the key itself (KBOX-55). */
export interface KeyMachine {
  readonly overlap: boolean;
  readonly boxMade: boolean;
}

/**
 * A platform that cannot hold two valid keys (a database password) skips the grace wait. A key the box makes itself (KBOX-55) has no
 * destination and no deploy: it is never pushed or redeployed, steps that would ask for the platform's master.
 */
export function stepsFor(platform: KeyMachine): readonly Step[] {
  const all: readonly Step[] = ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'grace', 'revoking'];
  return all.filter((s) => (platform.overlap || s !== 'grace') && (!platform.boxMade || (s !== 'pushing' && s !== 'redeploying')));
}

export function nextStep(step: Step, platform: KeyMachine): RunStep {
  const steps = stepsFor(platform);
  return steps[steps.indexOf(step) + 1] ?? 'done';
}

/** 24 h when any destination is a runtime (its code keeps running on the old key), else 1 h. */
export function defaultGraceHours(readableBy: readonly ('api' | 'runtime')[]): number {
  return readableBy.includes('runtime') ? 24 : 1;
}

const INTENT_MAX = 64;

/** `kbox_<ref>_g<N>_<run8>`: lower case, only `[a-z0-9_]`, at most 64 characters; the ref part gives way so the suffix stays whole. */
export function intentName(keyref: string, gen: number, runId: string): string {
  const suffix = `_g${gen}_${runId.slice('run_'.length, 'run_'.length + 8)}`;
  const ref = keyref.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return `kbox_${ref}`.slice(0, INTENT_MAX - suffix.length).replace(/_+$/, '') + suffix;
}

const RETRY_FIRST_MS = 60_000;
const RETRY_CAP_MS = 3600_000;

/** After a failed revoke (S-249; decided here): the first retry after 1 minute, doubling to a cap of 1 hour. */
export function retryDelayMs(attempt: number): number {
  return Math.min(RETRY_CAP_MS, RETRY_FIRST_MS * 2 ** Math.min(attempt, 20));
}

/** KBOX-55: what the token service answered an assertion signed with the new box-made key. */
export type ProofVerdict = 'ok' | 'rejected' | 'unreachable';

/** After a proof: switch to the new key, try again in `inMs`, or fail the run naming the last answer. */
export type ProofNext =
  | { readonly then: 'promote' }
  | { readonly then: 'retry'; readonly inMs: number }
  | { readonly then: 'fail'; readonly code: 'jwks_not_taken' | 'sts_unreachable' };

/**
 * KBOX-55: the proof of a new box-made key, once its publish lead has passed. Accepted: promote. Refused or unanswered: retried with the
 * KBOX-17 backoff (`attempt` failures so far), never past `openedAt + 2 × leadMs`; at or after that time the run fails, `jwks_not_taken`
 * when the service refused, `sts_unreachable` when it did not answer.
 */
export function afterProof(verdict: ProofVerdict, at: { readonly now: number; readonly openedAt: number; readonly leadMs: number; readonly attempt: number }): ProofNext {
  if (verdict === 'ok') return { then: 'promote' };
  const deadline = at.openedAt + 2 * at.leadMs;
  if (at.now >= deadline) return { then: 'fail', code: verdict === 'rejected' ? 'jwks_not_taken' : 'sts_unreachable' };
  return { then: 'retry', inMs: Math.min(retryDelayMs(at.attempt), deadline - at.now) };
}

/** What the box saw after a revoke: the verifier's verdict on the old value, or the platform's listing where the key was recorded. */
export type Evidence =
  | { readonly by: 'verifier'; readonly verdict: 'ok' | 'rejected' | 'unreachable' }
  | { readonly by: 'lister'; readonly id: PlatformKeyId; readonly at: KeyLocation; readonly listing: KeyListing | undefined };

const sameLocation = (a: KeyLocation, b: KeyLocation): boolean => a.region === b.region && a.project === b.project;

/** A listing that reads as "these are all the keys at `at`": complete, and of the region and project asked for. Anything else proves no absence. */
const covers = (listing: KeyListing | undefined, at: KeyLocation): listing is KeyListing => listing !== undefined && listing.complete && sameLocation(listing.at, at);

/**
 * A 404 is not proof. Dead means the verifier rejects the value, or a listing that is complete and of the region and project recorded with
 * the key shows the id absent or disabled. A failed listing, one page of several, or a listing of another location proves nothing.
 */
export function confirmDead(evidence: Evidence): boolean {
  if (evidence.by === 'verifier') return evidence.verdict === 'rejected';
  const { listing, id } = evidence;
  if (!covers(listing, evidence.at)) return false;
  return !listing.keys.some((k) => k.platformKeyId === id && k.disabled !== true);
}

/** Reconcile's absence: the intent name is off the platform only on a listing that covers the key's location (as `confirmDead` reads one) and does not show it. */
export function intentAbsent(listing: KeyListing | undefined, at: KeyLocation, intent: string): boolean {
  return covers(listing, at) && !listing.keys.some((k) => k.name === intent);
}
