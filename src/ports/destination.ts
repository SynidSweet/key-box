import type { Lent } from './types.ts';

export type DestinationKind = 'vercel-env' | 'google-secret-manager' | 'supabase-secret';

export interface DestinationTarget {
  readonly kind: DestinationKind;
  readonly id: string;
}

/**
 * What a push did to the destination, as far as the caller can know (review: three outcomes).
 * - `applied`: the destination holds the value; `version` names the object.
 * - `refused`: the destination answered that it applied nothing. Only an answer the adapter is sure of may say so.
 * - `unknown`: the push threw, timed out, or applied and then failed to answer: the destination may hold the value. An adapter may return
 *   it, and a push that throws is read as it.
 */
export type PushOutcome =
  | { readonly outcome: 'applied'; readonly version: string }
  | { readonly outcome: 'refused' }
  | { readonly outcome: 'unknown' };

export type DeployRef = string;

export interface Destination {
  readonly kind: DestinationKind;
  properties(): { readonly readableBy: 'api' | 'runtime'; readonly needsRedeploy: boolean };
  /** "Make it so": safe to repeat. */
  push(t: DestinationTarget, name: string, v: Lent, master: Lent): Promise<PushOutcome>;
  /** Absent counts as done. */
  remove(t: DestinationTarget, name: string, master: Lent): Promise<void>;
}

export interface Redeployer {
  redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef>;
  ready(r: DeployRef): Promise<'ready' | 'failed'>;
}

/** What a platform registers for one destination kind (KBOX-23): the adapter and, for a kind that needs one, its redeployer. */
export interface DestinationKit {
  readonly destination: Destination;
  readonly redeployer?: Redeployer;
}
