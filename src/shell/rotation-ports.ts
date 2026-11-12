// What the rotation shell is given: the adapters of a platform and of a destination kind, the master key and the one seam where a
// test stops the process. Adapters register these when they are built (the adapter units).
import type { DestinationKit } from '../ports/destination.ts';
import type { Issuer, KeyLister, LocationProver, Retirer, Verifier } from '../ports/issuer.ts';
import type { KeyClass, KeyLocation, KeyShape, Lent, LocationSchema, PlatformId, Scope } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import type { Step } from '../pure/rotation-machine.ts';
import { checkLocation } from '../pure/location.ts';
import type { LocationRefusal } from '../pure/location.ts';

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
  /** The key shape a paste-only platform states (no issuer); `shapeOf` reads the one shape of a kit. */
  readonly shape?: KeyShape;
  /** The class a paste-only platform states (no issuer); `classifierOf` reads the one class source of a kit. */
  readonly classify?: (scope: Scope, at: KeyLocation) => KeyClass;
  /** The location fields the entry declares (KBOX-57); none: the platform's keys take no location. */
  readonly location?: LocationSchema;
  /** Proves a host-naming location with the key's master before the key is proposed (KBOX-57). */
  readonly locationProver?: LocationProver;
  /** Ends the live key of a pasted generation at step 10 (KBOX-51); none: the owner ends it. */
  readonly retirer?: Retirer;
  /** The entry's verify hints (KBOX-40); none: the paste page offers no choice. */
  readonly verifyHints?: readonly string[];
}

/** A registered platform whose keys are made on the phone (KBOX-12, KBOX-34), one with no issuer or an issuer that says `paste`: the box cannot issue one, so it never runs an api run for it. */
export function isPasteSource(source: Pick<PlatformSource, 'platform'>, platform: PlatformId): boolean {
  const kit = source.platform(platform);
  return kit !== undefined && (kit.issuer === undefined || kit.issuer.capabilities().create === 'paste');
}

/**
 * KBOX-57: whether a stored key's location still passes its entry's declaration as it is now (`ok`), else the refusal code. Every place that
 * starts work on a stored key asks this one function: a run's start and the schedule's due check.
 */
export const storedPlacement = (
  source: Pick<PlatformSource, 'platform'>,
  head: { readonly platform: PlatformId; readonly class: KeyClass },
  info: { readonly location: KeyLocation; readonly scopeItems: readonly string[] },
): 'ok' | LocationRefusal => checkLocation(source.platform(head.platform)?.location, info.location, head.class, info.scopeItems);


/**
 * KBOX-34: whether a stored key's next value comes by paste, never by a run: a platform whose keys are made on the phone, or a master key
 * whose issuer is not `selfRotate` (no issuer can make another kind's master). The scheduler, `POST /api/rotations`, the `rotate_key`
 * executor and a run's start all ask this one function.
 */
export function rotatesByPaste(source: Pick<PlatformSource, 'platform'>, head: { readonly platform: PlatformId; readonly class: KeyClass }): boolean {
  if (isPasteSource(source, head.platform)) return true;
  const kit = source.platform(head.platform);
  return kit !== undefined && head.class === 'master' && kit.issuer?.capabilities().selfRotate !== true;
}

/** Why a rotation cannot be proposed, opened or started now: a placement refusal (KBOX-57) or, where a run makes the key, no master or two. */
export type RotationRefusal = LocationRefusal | Extract<MasterResult, { ok: false }>['code'];

/**
 * KBOX-57: what a proposal of a rotation of a stored key must clear before anything is proposed or opened: the stored location against the
 * entry as it is now, then, for an admin or master key a run makes (an approval, not a paste), the platform's master chosen by the key's
 * stored location and scope items. `ok` when it may go on. One function for `POST /api/rotations` and the schedule.
 */
export function proposalRefusal(
  source: Pick<PlatformSource, 'platform' | 'master'>,
  head: { readonly platform: PlatformId; readonly class: KeyClass },
  info: { readonly location: KeyLocation; readonly scopeItems: readonly string[] },
): 'ok' | RotationRefusal {
  const placed = storedPlacement(source, head, info);
  if (placed !== 'ok') return placed;
  // Only an issuer makes a key by run: a platform with none registered has no master to ask for.
  if (head.class === 'ordinary' || rotatesByPaste(source, head) || source.platform(head.platform)?.issuer === undefined) return 'ok';
  const master = source.master(head.platform, info.location, info.scopeItems);
  return master.ok ? 'ok' : master.code;
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
   * KBOX-57: the platform's master for a key at `at` with scope `items`, lent: the one candidate row (`masters`) whose stored location covers
   * `at` and that carries the key's items for each of the entry's `masterItems` prefixes. `projects` and row order never take part. None is
   * `no_master`, two or more `master_ambiguous`; never a throw for either.
   */
  master(platform: PlatformId, at: KeyLocation, items: readonly string[]): MasterResult;
  /**
   * KBOX-57: every candidate master row of the platform with its stored location: master class, master by its own classification at its
   * stored location (not only by the KBOX-15 floor), its current generation lendable. Reconcile lists the platform once per row.
   */
  masters(platform: PlatformId): readonly MasterRow[];
}

/** The master chosen for a key, or why there is none to choose (KBOX-57). */
export type MasterResult = { readonly ok: true; readonly value: Lent } | { readonly ok: false; readonly code: 'no_master' | 'master_ambiguous' };

/** A candidate master row: where it is stored and its current value, lent. */
export interface MasterRow {
  readonly at: KeyLocation;
  readonly value: Lent;
}
