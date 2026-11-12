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

/** Where a platform holds a key (KBOX-57): the region and project entered once with the key and never changed (names only). */
export interface KeyLocation {
  readonly region?: string;
  readonly project?: string;
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

/** The two fields a location can name (KBOX-57, KBOX-23): an entry declares only these. */
export type LocationField = 'region' | 'project';

/** How an entry takes one location field: a full-match pattern, the classes whose keys must name it, and whether it names an upstream host. */
export interface LocationRule {
  readonly pattern: RegExp;
  readonly requiredFor: readonly KeyClass[];
  readonly namesHost?: true;
}

/** The location fields a registry entry declares (KBOX-57); an entry that declares none takes no location. */
export type LocationSchema = Readonly<Partial<Record<LocationField, LocationRule>>>;
