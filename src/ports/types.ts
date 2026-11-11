// Closed types and shared shapes of design section 5.1. Later units close the open strings
// (scope fields, notice kinds) when they add the first use.
export type KeyClass = 'ordinary' | 'admin' | 'master';

export type PlatformId = string;
export type PlatformKeyId = string;
export type KeyRef = string;

/** A key value that only ever shows as "[key ref:gen]" and is read through `use`. */
export interface Lent {
  use<T>(fn: (bytes: Uint8Array) => Promise<T>): Promise<T>;
}

export type Alphabet = 'hex' | 'base62' | 'base64' | 'base64url';

export interface KeyShape {
  readonly prefix: string | null;
  readonly alphabet: Alphabet;
  readonly coreLength: { readonly min: number; readonly max: number };
  readonly random: boolean;
}

export type Scope = Readonly<Record<string, string | readonly string[]>>;

export interface ScopeSchema {
  readonly fields: readonly string[];
}
