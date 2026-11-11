import type { Lent } from './types.ts';

export type DestinationKind = 'vercel-env' | 'google-secret-manager' | 'supabase-secret';

export interface DestinationTarget {
  readonly kind: DestinationKind;
  readonly id: string;
}

export interface PushReceipt {
  readonly version: string;
}

export type DeployRef = string;

export interface Destination {
  readonly kind: DestinationKind;
  properties(): { readonly readableBy: 'api' | 'runtime'; readonly needsRedeploy: boolean };
  /** "Make it so": safe to repeat. */
  push(t: DestinationTarget, name: string, v: Lent, master: Lent): Promise<PushReceipt>;
  /** Absent counts as done. */
  remove(t: DestinationTarget, name: string, master: Lent): Promise<void>;
}

export interface Redeployer {
  redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef>;
  ready(r: DeployRef): Promise<'ready' | 'failed'>;
}
