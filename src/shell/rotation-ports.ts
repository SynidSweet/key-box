// What the rotation shell is given: the adapters of a platform and of a destination kind, the master key and the one seam where a
// test stops the process. Adapters register these when they are built (the adapter units).
import type { Destination, Redeployer } from '../ports/destination.ts';
import type { Issuer, KeyLister, Verifier } from '../ports/issuer.ts';
import type { Lent, PlatformId } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
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

/** A platform whose keys are made on the phone (KBOX-12, KBOX-34): the box cannot issue one, so it never runs an api run for it. */
export function isPasteSource(source: Pick<PlatformSource, 'platform'>, platform: PlatformId): boolean {
  return source.platform(platform)?.issuer?.capabilities().create === 'paste';
}

/** Whether the platform can hold two valid keys at once (true when it says nothing: there is then no one-credential order to follow). */
export const overlapOf = (kit: PlatformKit | undefined): boolean => kit?.issuer?.capabilities().overlap ?? true;

type SetValue =NonNullable<Issuer['set']>;

/**
 * The issuer's `set` when it both declares the capability and has the call (neither alone is trusted), bound to the issuer: what an
 * `overlap: false` platform needs (KBOX-51, design §5.2). Undefined otherwise.
 */
export function setterOf(issuer: Issuer | undefined): SetValue | undefined {
  const set = issuer?.set;
  if (issuer === undefined || set === undefined || issuer.capabilities().set !== 'api') return undefined;
  return (value, at, master) => set.call(issuer, value, at, master);
}

/** A generation the vault no longer lends (retired, never stored) as a result: the caller decides what its absence means. */
export function tryLend(vault: Pick<Vault, 'lend'>, keyref: string, gen: number): { readonly ok: true; readonly value: Lent } | { readonly ok: false } {
  try {
    return { ok: true, value: vault.lend(keyref, gen) };
  } catch {
    return { ok: false };
  }
}

export interface DestinationKit {
  readonly destination: Destination;
  readonly redeployer?: Redeployer;
}

/**
 * Where the process may be stopped in a test: after a key is created and before it is stored (`issued`), after it is stored and before the
 * step is persisted (`stored`), after a push and before its receipt (`pushed`), after each receipt, after an overlap:false platform took the
 * new value and before its receipt (`taken`), after a redeploy started and before it is ready (`redeployed`), after a rollback removed the
 * new value from a destination (`removed`), after each step is persisted.
 */
export type Point = 'issued' | 'stored' | 'pushed' | 'receipt' | 'taken' | 'redeployed' | 'removed' | Step;

export interface PlatformSource {
  /** The adapters of a platform id, or undefined when none is registered. */
  platform(id: PlatformId): PlatformKit | undefined;
  /** The adapters of a destination kind as the metadata names it (`vercel_env`, ...), or undefined. */
  destination(kind: string): DestinationKit | undefined;
  /**
   * The platform's master key, lent: of the master keys whose current generation can be lent, the one of the key's own project (`projects`
   * of the key it serves; none given, no project is preferred). Throws `conflict` (`master_ambiguous`) when two still qualify (review N5).
   */
  master(platform: PlatformId, projects?: readonly string[]): Lent;
}
