import type { KeyClass, KeyLocation, KeyShape, Lent, PlatformId, PlatformKeyId, Scope, ScopeSchema } from './types.ts';

export interface IssuerCapabilities {
  readonly create: 'api' | 'paste';
  readonly revoke: 'api' | 'paste';
  /** Can the master create its own successor. */
  readonly selfRotate: boolean;
  /** Can old and new be valid at once (false: a database password). */
  readonly overlap: boolean;
  /** The value is only in the create response. */
  readonly revealOnce: boolean;
  readonly scopeSchema: ScopeSchema;
  readonly shape: KeyShape;
  classify(scope: Scope): KeyClass;
}

export interface IssueRequest {
  readonly scope: Scope;
}

export interface IssuedKey {
  readonly value: Lent;
  readonly platformKeyId: PlatformKeyId;
  readonly expiresAt?: number;
}

/** A platform that can create keys. */
export interface Issuer {
  readonly platform: PlatformId;
  capabilities(): IssuerCapabilities;
  issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey>;
  /** A 404 is 'absent' and is not proof: the orchestrator confirms. */
  revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'>;
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
