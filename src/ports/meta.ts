// KBOX-5, KBOX-19, KBOX-30: the metadata port. Every write that changes what GET /api/meta shows appends its event in
// the same transaction, so the snapshot and the event stream never disagree.
import type { KeyClass } from './types.ts';

export type TokenScope = 'control' | 'relay';
export type KeyStatus = 'works' | 'rotating' | 'awaiting_approval' | 'awaiting_paste' | 'failed';
export type Coverage = 'windowed' | 'anchored' | 'none';

export interface MetaDestination {
  readonly kind: string;
  readonly target: string;
  readonly readable_by: 'api' | 'runtime';
}

export interface MetaSchedule {
  readonly rotate_every_days: number;
  readonly grace_hours: number;
  readonly next_due_at: number | null;
  readonly expires_at: number | null;
}

/** A key as GET /api/meta shows it (KBOX-30). */
export interface MetaKey {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects: readonly string[];
  readonly class: KeyClass;
  readonly status: KeyStatus;
  readonly gen_current: number;
  readonly destinations: readonly MetaDestination[];
  readonly schedule: MetaSchedule;
  readonly grants: readonly { readonly machine: string }[];
  readonly allow_rules: readonly string[];
  /** null until measured. */
  readonly coverage: Coverage | null;
  readonly last_use_at: number | null;
}

/** The key's own row; destinations and grants are written one by one. */
export type KeyRow = Omit<MetaKey, 'destinations' | 'grants' | 'allow_rules'>;

export interface MetaMachine {
  readonly label: string;
  readonly scope: TokenScope;
  readonly enrolled_at: number;
  readonly revoked: boolean;
  readonly last_network: string | null;
}

export interface MetaApproval {
  readonly approval_id: string;
  readonly kind: string;
  readonly title: string;
  readonly slot: string;
  readonly opened_at: number;
  readonly expires_at: number;
}

export interface MetaBox {
  readonly release: string;
  readonly share_version: number;
  readonly share_public_key_ed25519_b64: string | null;
  readonly oidc_issuer: string | null;
  readonly epoch: string;
}

export interface MetaSnapshot {
  readonly cursor: number;
  readonly box: MetaBox;
  readonly keys: readonly MetaKey[];
  readonly machines: readonly MetaMachine[];
  readonly approvals: readonly MetaApproval[];
}

export interface NewMachine {
  readonly label: string;
  readonly scope: TokenScope;
  /** Lower-case hex SHA-256 of the token. The token itself is never stored. */
  readonly tokenSha256: string;
  readonly enrolledAt: number;
}

export interface MetaStore {
  /** The epoch chosen when meta.db was created. */
  epoch(): string;
  /** Everything GET /api/meta shows, read in one transaction, with the event cursor of that same moment. */
  snapshot(): MetaSnapshot;
  putKey(key: KeyRow): void;
  putDestination(keyref: string, destination: MetaDestination): void;
  putGrant(keyref: string, machine: string): void;
  /** Removes a grant; `not_found` when there was none. Writes `key.changed`. */
  removeGrant(keyref: string, machine: string): void;
  /** Removes a destination; `not_found` when there was none. Writes `key.changed`. */
  removeDestination(keyref: string, kind: string, target: string): void;
  /** The coverage of a stored key (`null` until measured), or undefined for no such key. */
  coverageOf(keyref: string): Coverage | null | undefined;
  addMachine(machine: NewMachine): void;
  revokeMachine(label: string): void;
  putApproval(approval: MetaApproval): void;
}

export interface TokenRecord {
  readonly label: string;
  readonly scope: TokenScope;
  readonly tokenSha256: string;
  readonly revoked: boolean;
}

export interface TokenStore {
  /** Every enrolled token's hash, so a presented token is compared against all of them. */
  tokens(): readonly TokenRecord[];
  /** Notes where a token was used from. A network different from the last one writes one `token.new_network` event. */
  recordUse(label: string, network: string): void;
}
