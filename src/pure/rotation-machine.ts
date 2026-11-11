// KBOX-51, KBOX-17: the pure parts of the rotation state machine: the order of the steps, the intent name written before any
// platform call, the grace default, the retry schedule and what proves an old key dead. No I/O: the orchestrator does the work.
import type { KeyListing } from '../ports/issuer.ts';
import type { KeyLocation, PlatformKeyId } from '../ports/types.ts';

/** The steps of a run, in order. `issuing` covers create and store; `grace` is the wait before the old key is switched off. */
export type Step = 'issuing' | 'verifying' | 'pushing' | 'redeploying' | 'checking' | 'promoting' | 'grace' | 'revoking';
export type RunStep = Step | 'done';

/** A platform that cannot hold two valid keys (a database password) skips the grace wait. */
export function stepsFor(platform: { readonly overlap: boolean }): readonly Step[] {
  const all: readonly Step[] = ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'grace', 'revoking'];
  return platform.overlap ? all : all.filter((s) => s !== 'grace');
}

export function nextStep(step: Step, platform: { readonly overlap: boolean }): RunStep {
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

/** What the box saw after a revoke: the verifier's verdict on the old value, or the platform's listing where the key was recorded. */
export type Evidence =
  | { readonly by: 'verifier'; readonly verdict: 'ok' | 'rejected' | 'unreachable' }
  | { readonly by: 'lister'; readonly id: PlatformKeyId; readonly at: KeyLocation; readonly listing: KeyListing | undefined };

const sameLocation = (a: KeyLocation, b: KeyLocation): boolean => a.region === b.region && a.project === b.project;

/**
 * A 404 is not proof. Dead means the verifier rejects the value, or a listing that is complete and of the region and project recorded with
 * the key shows the id absent or disabled. A failed listing, one page of several, or a listing of another location proves nothing.
 */
export function confirmDead(evidence: Evidence): boolean {
  if (evidence.by === 'verifier') return evidence.verdict === 'rejected';
  const { listing, id } = evidence;
  if (listing === undefined || !listing.complete || !sameLocation(listing.at, evidence.at)) return false;
  return !listing.keys.some((k) => k.platformKeyId === id && k.disabled !== true);
}
