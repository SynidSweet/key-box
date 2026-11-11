import type { KeyClass, KeyShape, Lent, PlatformId, PlatformKeyId, Scope, ScopeSchema } from './types.ts';

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
}

/** Required when `revealOnce` is true. */
export interface KeyLister {
  list(master: Lent): Promise<PlatformKeyInfo[]>;
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
