// What the rotation shell is given: the adapters of a platform and of a destination kind, the master key and the one seam where a
// test stops the process. Adapters register these when they are built (the adapter units).
import type { Destination, Redeployer } from '../ports/destination.ts';
import type { Issuer, KeyLister, Verifier } from '../ports/issuer.ts';
import type { Lent, PlatformId } from '../ports/types.ts';
import type { Step } from '../pure/rotation-machine.ts';

/**
 * A platform's adapters. A paste platform has no issuer: its keys are made on the phone (KBOX-12) and retired by the owner, so
 * the box can only watch the verifier for the old value to stop working. A platform with no verifier call is confirmed by its lister.
 */
export interface PlatformKit {
  readonly issuer?: Issuer;
  readonly lister?: KeyLister;
  readonly verifier?: Verifier;
  /** The platform's own page for making a key, shown on a paste page (never taken from mission control). */
  readonly keyPageUrl?: string;
}

export interface DestinationKit {
  readonly destination: Destination;
  readonly redeployer?: Redeployer;
}

/** Where the process may be stopped in a test: after a key is created and before it is stored, after each step is persisted, after each receipt. */
export type Point = 'issued' | 'receipt' | Step;

export interface PlatformSource {
  /** The adapters of a platform id, or undefined when none is registered. */
  platform(id: PlatformId): PlatformKit | undefined;
  /** The adapters of a destination kind as the metadata names it (`vercel_env`, ...), or undefined. */
  destination(kind: string): DestinationKit | undefined;
  /** The platform's master key, lent. */
  master(platform: PlatformId): Lent;
}
