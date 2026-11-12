import type { KeyClass, KeyLocation, KeyShape, Lent, PlatformId, PlatformKeyId, Scope, ScopeSchema } from './types.ts';

export interface IssuerCapabilities {
  readonly create: 'api' | 'paste';
  readonly revoke: 'api' | 'paste';
  /** Can the master create its own successor. */
  readonly selfRotate: boolean;
  /** Can old and new be valid at once (false: a database password). */
  readonly overlap: boolean;
  /**
   * Can the platform take a value the box chose (`Issuer.set`): what an `overlap: false` platform needs, so a failed run can set the old
   * value back (design §5.2). An `overlap: false` platform without it is refused at configuration (`overlap_needs_set`).
   */
  readonly set: 'api' | 'none';
  /** The value is only in the create response. */
  readonly revealOnce: boolean;
  readonly scopeSchema: ScopeSchema;
  readonly shape: KeyShape;
  /** The class of a key with this scope at this location (KBOX-57: the shell takes the higher of this and the class at `{}`). */
  classify(scope: Scope, at: KeyLocation): KeyClass;
}

export interface IssueRequest {
  readonly scope: Scope;
  /** The key's one stored location (KBOX-57): the only place the issuer reads where to make the key. */
  readonly at: KeyLocation;
}

export interface IssuedKey {
  readonly value: Lent;
  readonly platformKeyId: PlatformKeyId;
  readonly expiresAt?: number;
  /** Where the platform says it made the key, from its answer, never copied from the request; left out only when the answer names no place. */
  readonly location?: KeyLocation;
}

/** A platform that can create keys. */
export interface Issuer {
  readonly platform: PlatformId;
  capabilities(): IssuerCapabilities;
  issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey>;
  /** A 404 is 'absent' and is not proof: the orchestrator confirms. */
  revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'>;
  /**
   * Present exactly when `capabilities().set` is `api`: sets the platform's one credential at `at` to `value`; the value it held before stops
   * working. "Make it so": safe to repeat.
   */
  set?(value: Lent, at: KeyLocation, master: Lent): Promise<void>;
}

export interface PlatformKeyInfo {
  readonly platformKeyId: PlatformKeyId;
  readonly name: string;
  /** Where the platform holds it, when the platform has regions or projects (KBOX-51: a revoke is confirmed against this). */
  readonly location?: KeyLocation;
  /** The platform holds the key switched off: it grants nothing (KBOX-51 counts it as dead). */
  readonly disabled?: true;
}

/** The keys a platform holds at one location, and whether the lister read every page of them. */
export interface KeyListing {
  /** False when any page could not be read: absence from an incomplete listing proves nothing. */
  readonly complete: boolean;
  /** The location the listing is of, as the platform answered it. */
  readonly at: KeyLocation;
  readonly keys: readonly PlatformKeyInfo[];
}

/** Required when `revealOnce` is true. */
export interface KeyLister {
  /** Every key the master can see (reconcile's sweep for `kbox_` names). */
  list(master: Lent): Promise<PlatformKeyInfo[]>;
  /** The keys at one location (region and project), saying whether the listing is complete: what confirms a revoke (KBOX-51 step 10). */
  listAt(at: KeyLocation, master: Lent): Promise<KeyListing>;
}

export interface VerifyTarget {
  readonly platform: PlatformId;
  /** The generation's recorded location (KBOX-57): what the platform answered when it made the key, else the key's stored one. */
  readonly at: KeyLocation;
}

export interface Verifier {
  verify(key: Lent, target: VerifyTarget): Promise<'ok' | 'rejected' | 'unreachable'>;
}

export interface PasteRequest {
  readonly platform: PlatformId;
  readonly name: string;
}

export type PasteTaskId = string;

export interface PasteSource {
  open(req: PasteRequest): Promise<PasteTaskId>;
}

/**
 * KBOX-57: proves a host-naming location before a key is proposed: asks the platform, with the master chosen for the key, whether it can see
 * that place. `unseen` when it cannot; any other answer (a 401, a 5xx) or a failed call throws.
 */
export interface LocationProver {
  prove(at: KeyLocation, master: Lent): Promise<'seen' | 'unseen'>;
}
