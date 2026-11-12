// What the rotation shell is given: the adapters of a platform and of a destination kind, the master key and the one seam where a
// test stops the process. Adapters register these when they are built (the adapter units).
import type { DestinationKit } from '../ports/destination.ts';
import type { Issuer, KeyKind, KeyLister, LocationProver, Retirer, Verifier, VerifyTarget } from '../ports/issuer.ts';
import type { BoxMadeKey } from '../ports/platform.ts';
import type { KeyClass, KeyLocation, KeyShape, Lent, LocationSchema, PlatformId, Scope } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import type { Step } from '../pure/rotation-machine.ts';
import { keyrefOf } from '../pure/class.ts';
import { checkLocation } from '../pure/location.ts';
import type { LocationRefusal } from '../pure/location.ts';

/**
 * A platform's adapters. A paste platform has no issuer: its keys are made on the phone (KBOX-12) and retired by the owner, so
 * the box can only watch the verifier for the old value to stop working. A key no verifier applies to is confirmed by its lister (KBOX-58).
 */
export interface PlatformKit {
  readonly issuer?: Issuer;
  readonly lister?: KeyLister;
  /** Read only through `verifierFor` (KBOX-58: whether it applies to a key), never directly. */
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
  /**
   * KBOX-55: the master the box makes itself. On the platform's kit (`platform`) it says the box makes a master there; the box key's own kit
   * (`kitFor`) holds only it, its shape and its class; every other key's kit leaves it out.
   */
  readonly boxKey?: BoxMadeKey;
}

/** A stored or requested key as the per-key kit is chosen for it (KBOX-55): its platform and its reference. */
export interface KeyOf {
  readonly platform: PlatformId;
  readonly keyref: string;
}

/** KBOX-55: the reference of the key a platform's box-made key is stored under: no project, its own name. */
export const boxKeyrefOf = (platform: PlatformId, box: Pick<BoxMadeKey, 'name'>): string => keyrefOf(platform, [], box.name);

/**
 * KBOX-55: the kit of one key, derived from its platform's kit (so any source that answers `platform` answers this the same way). The
 * box-made key gets `{boxKey, shape, classify: master}` and nothing else, so no issuer, lister, verifier or retirer of the platform ever
 * reaches it; every other key gets the platform's kit without `boxKey`. Everything that works on a stored key asks this; `platform` alone is
 * what a request for a new key (`add_key`, `POST /api/keys`) asks.
 */
export function kitFor(source: Pick<PlatformSource, 'platform'>, key: KeyOf): PlatformKit | undefined {
  const kit = source.platform(key.platform);
  if (kit?.boxKey === undefined) return kit;
  const { boxKey, ...platformKit } = kit;
  if (key.keyref !== boxKeyrefOf(key.platform, boxKey)) return platformKit;
  return { boxKey, shape: boxKey.shape, classify: () => 'master' };
}

/** A platform kit whose keys are made on the phone (KBOX-12, KBOX-34): no issuer, or an issuer that says `paste`. The question `add_key` asks of a platform. */
export const createsByPaste = (kit: PlatformKit | undefined): boolean => kit !== undefined && (kit.issuer === undefined || kit.issuer.capabilities().create === 'paste');

/**
 * A key whose next value is made on the phone (KBOX-12, KBOX-34), by its own kit: its platform has no issuer or an issuer that says `paste`, so
 * the box never runs an api run for it. A box-made key (KBOX-55) never is: no outside party makes it.
 */
export function isPasteSource(source: Pick<PlatformSource, 'platform'>, key: KeyOf): boolean {
  const kit = kitFor(source, key);
  return kit?.boxKey === undefined && createsByPaste(kit);
}

/**
 * KBOX-57: whether a stored key's location still passes its entry's declaration as it is now (`ok`), else the refusal code. Every place that
 * starts work on a stored key asks this one function: a run's start and the schedule's due check.
 */
export const storedPlacement = (
  source: Pick<PlatformSource, 'platform'>,
  head: KeyOf & { readonly class: KeyClass },
  info: { readonly location: KeyLocation; readonly scopeItems: readonly string[] },
): 'ok' | LocationRefusal => checkLocation(kitFor(source, head)?.location, info.location, head.class, info.scopeItems);


/**
 * KBOX-34: whether a stored key's next value comes by paste, never by a run: a key made on the phone, or a master key whose issuer is not
 * `selfRotate` (no issuer can make another kind's master). A box-made key (KBOX-55) is rotated by an approval, never a paste. The scheduler,
 * `POST /api/rotations`, the `rotate_key` executor and a run's start all ask this one function.
 */
export function rotatesByPaste(source: Pick<PlatformSource, 'platform'>, head: KeyOf & { readonly class: KeyClass }): boolean {
  if (isPasteSource(source, head)) return true;
  const kit = kitFor(source, head);
  return kit !== undefined && kit.boxKey === undefined && head.class === 'master' && kit.issuer?.capabilities().selfRotate !== true;
}

/** A verifier whose reach could not be judged (its `appliesTo` threw): it counts as applying and answers `unreachable` without a call. */
const UNJUDGED: Verifier = { verify: () => Promise.resolve('unreachable') };

/**
 * KBOX-58: the platform's verifier when it applies to a key with this stored scope and location, else undefined ("no verifier" means none
 * applies to this key). The one place a kit's verifier is read: every caller asks this (an arch check refuses any other read). A verifier
 * without `appliesTo` applies to every key. A predicate that throws never counts as "none": the verifier counts as applying and answers
 * `unreachable`, so step 10 stays in grace and a paste is refused, and a verifier never confirms dead a key it could not be asked about.
 */
export function verifierFor(kit: Pick<PlatformKit, 'verifier'> | undefined, key: KeyKind): Verifier | undefined {
  const verifier = kit?.verifier;
  if (verifier?.appliesTo === undefined) return verifier;
  try {
    return verifier.appliesTo({ items: key.scopeItems }, key.at) ? verifier : undefined;
  } catch {
    return UNJUDGED;
  }
}

/**
 * KBOX-58: the target a verifier is asked about. The master is added only for a verifier that declares `needsMaster` and only when one was
 * chosen (the member is then present; otherwise it is absent, not undefined): the one place a master reaches a verifier.
 */
export function verifyTargetOf(verifier: Pick<Verifier, 'needsMaster'>, target: VerifyTarget, master: Lent | undefined): VerifyTarget {
  return verifier.needsMaster === true && master !== undefined ? { ...target, master } : target;
}

/** A key with no stored record (`keyInfo` missing): no scope items and no location (KBOX-58). */
export const NO_KIND: KeyKind = { scopeItems: [], at: {} };

/** KBOX-58: a stored key's kind, from its stored record (`keyInfo`); none is `NO_KIND`. */
export const kindOfStored = (info: { readonly scopeItems: readonly string[]; readonly location: KeyLocation } | undefined): KeyKind =>
  info === undefined ? NO_KIND : { scopeItems: info.scopeItems, at: info.location };

/**
 * Why a rotation cannot be proposed, opened or started now: a placement refusal (KBOX-57), where a run makes the key no master or two, and
 * where a paste would, no verifier that applies to the key (KBOX-58).
 */
export type RotationRefusal = LocationRefusal | Extract<MasterResult, { ok: false }>['code'] | 'no_verifier';

/**
 * KBOX-57, KBOX-58: what a proposal of a rotation of a stored key must clear before anything is proposed or opened: the stored location against
 * the entry as it is now; then, for an admin or master key rotated by paste, a verifier that applies to the key (no paste could settle
 * otherwise); for one a run makes (an approval, not a paste), the platform's master chosen by the key's stored location and scope items. `ok`
 * when it may go on. One function for `POST /api/rotations` and the schedule. A key without a stored record is judged on no scope and no place
 * for its verifier, and asks no placement and no master.
 */
export function proposalRefusal(
  source: Pick<PlatformSource, 'platform' | 'master'>,
  head: KeyOf & { readonly class: KeyClass },
  info: { readonly location: KeyLocation; readonly scopeItems: readonly string[] } | undefined,
): 'ok' | RotationRefusal {
  const placed = info === undefined ? 'ok' : storedPlacement(source, head, info);
  if (placed !== 'ok') return placed;
  if (head.class === 'ordinary') return 'ok';
  if (rotatesByPaste(source, head)) return verifierFor(kitFor(source, head), kindOfStored(info)) === undefined ? 'no_verifier' : 'ok';
  // Only an issuer makes a key by run: a key whose kit has none (a box-made key, a platform with none registered) has no master to ask for.
  if (info === undefined || kitFor(source, head)?.issuer === undefined) return 'ok';
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
  /** The adapters of a platform id, or undefined when none is registered: what a request for a new key (`add_key`, `POST /api/keys`) asks. */
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

/** A candidate master row: where it is stored, the scope items it was made with and its current value, lent. */
export interface MasterRow {
  readonly at: KeyLocation;
  /** The stored scope items (the `team:` item of a Vercel master names the team its operations run in, KBOX-26); a source that does not say has none. */
  readonly items?: readonly string[];
  readonly value: Lent;
}
