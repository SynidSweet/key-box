// KBOX-23: one registry line per platform. Adding a platform is one folder `src/platforms/<id>/` plus one entry here; the entry carries
// everything the adapter registers, so no shared wiring changes with it.
import type { DestinationKit } from './destination.ts';
import type { Issuer, KeyLister, LocationProver, Retirer, Verifier } from './issuer.ts';
import type { Clock } from './clock.ts';
import type { AdapterHttp } from './http.ts';
import type { MintedSink } from './minted.ts';
import type { DenyRule, RelayProfile } from './relay-profile.ts';
import type { Random } from './random.ts';
import type { KeyClass, KeyLocation, KeyShape, Lent, LocationSchema, PlatformId, Scope } from './types.ts';

/**
 * KBOX-55: a master the box makes itself (Google's signing key), at core start and by its own rotation. Not an Issuer: no platform call makes,
 * lists or revokes it, so its kit (`PlatformSource.kitFor`) carries none of the platform's issuer, lister, verifier or retirer. Its keyref is
 * `keyrefOf(entry.id, [], name)`.
 */
export interface BoxMadeKey {
  /** The key's env name (`OIDC_SIGNING_KEY`). */
  readonly name: string;
  readonly shape: KeyShape;
  /** How long a new generation is published before the box proves the platform has taken it (`JWKS_PUBLISH_LEAD_MS`). */
  readonly publishLeadMs: number;
  /** A new value: random bytes drawn until they form a valid key, stored exactly as drawn (for Google, 32 bytes as 43 base64url characters). */
  generate(random: Random): Uint8Array;
  /** Whether a stored value opens as a key of this kind. */
  check(value: Lent): Promise<'ok' | 'rejected'>;
  /**
   * Whether the platform has taken a new generation (KBOX-55 `checking`): one exchange signed with `pending` for the box's `identity`. `ok` when
   * the platform accepted it (what it bought is held by `minted` until it expires, then dropped), `rejected` when it refused it, `unreachable`
   * when no usable answer came. An identity the platform could never take is a throw, not an answer.
   */
  prove(pending: Lent, identity: BoxIdentity, minted: MintedSink): Promise<'ok' | 'rejected' | 'unreachable'>;
}

/**
 * KBOX-41: the box's own OIDC identity, from core's configuration: who it says it is (`https://keys.<domain>`) and the audience its
 * assertions are for (the platform's federation, for Google the workload identity provider). The adapter checks the audience's form.
 */
export interface BoxIdentity {
  readonly issuer: string;
  readonly audience: string;
}

/** KBOX-41: the two documents core serves for a platform that trusts the box's own identity, on keys.<domain>. */
export interface IdentityDocuments {
  /** `/.well-known/openid-configuration` for this issuer. */
  discovery(issuer: string): Readonly<Record<string, unknown>>;
  /** `/.well-known/jwks.json`: the public halves of the signing keys core lends it (each live generation of the platform's master keys). */
  jwks(signingKeys: readonly Lent[]): Promise<Readonly<Record<string, unknown>>>;
}

/** A key's stored record as an adapter may read it (KBOX-57): the approved scope items and the location entered with the key. */
export interface StoredKey {
  readonly scopeItems: readonly string[];
  readonly location: KeyLocation;
}

/** The granted key a grant check looks at: its reference and its stored location. */
export interface GrantSubject {
  readonly keyref: string;
  readonly at: KeyLocation;
}

/** `refused` carries a fixed names-only code (`[a-z][a-z0-9_]*`): the permission found, or why the check could not be made. */
export type GrantVerdict = { readonly verdict: 'pass' } | { readonly verdict: 'refused'; readonly code: string };

/** KBOX-24: whether a key may be (or stay) granted. */
export interface GrantCheck {
  /** Whether the check is made for a key with these stored scope items; a key it does not apply to is never checked or suspended. */
  appliesTo(scopeItems: readonly string[]): boolean;
  /** The verdict, with the platform's master lent for the key's stored location and scope. Any failure is a refusal: it fails closed. */
  check(subject: GrantSubject, master: Lent): Promise<GrantVerdict>;
}

export interface PlatformEntry {
  readonly id: PlatformId;
  readonly issuer?: Issuer;
  /** Required when the issuer's `revealOnce` is true. */
  readonly lister?: KeyLister;
  readonly relay?: RelayProfile;
  /** A platform in `relayDenyOnly` (Vercel, ElevenLabs in v1) exports its mustDeny list here and has no relay profile. */
  readonly denyOnly?: readonly DenyRule[];
  /** Read only through `verifierFor` (KBOX-58: whether it applies to a key), never directly. */
  readonly verifier?: Verifier;
  /** The platform's own page for making a key, shown on the paste page (KBOX-12, KBOX-40's `pasteGuide`). */
  readonly keyPageUrl?: string;
  /**
   * The key shape of a platform with no issuer (a paste-only platform, KBOX-40). One source: an entry with an issuer takes its shape from
   * `issuer.capabilities().shape` and leaves this out; the registry check refuses both and neither.
   */
  readonly shape?: KeyShape;
  /**
   * The class of a key of a platform with no issuer, from the scope it was asked with (KBOX-40: a key that can create keys is `master`,
   * an ordinary key is not the box's business). One source, like `shape`: an entry with an issuer leaves this out; the registry check
   * refuses both and neither.
   */
  readonly classify?: (scope: Scope, at: KeyLocation) => KeyClass;
  /**
   * The location fields the platform's keys take (KBOX-57): each with a full-match pattern, the classes that must name it and whether it names
   * an upstream host. An entry that declares none takes no location.
   */
  readonly location?: LocationSchema;
  /** Proves a host-naming location before a key is proposed (KBOX-57); the registry check requires it of an entry with such a field. */
  readonly locationProver?: LocationProver;
  /**
   * Ends the live key of a pasted generation (no platform key id) at step 10 (KBOX-51): the box never recorded its id, so the retirer finds it
   * by the old value. An entry without one leaves the ending to the owner (`owner_ends`).
   */
  readonly retirer?: Retirer;
  /**
   * The scope-item prefixes that decide a master's authority (KBOX-57; Vercel `team:`): a master serves a key only when it carries the same
   * items with each prefix as the key. Each ends in `:` (the registry check).
   */
  readonly masterItems?: readonly string[];
  /** The destination adapters this platform provides; the kind of each is its `destination.kind`. A kind has at most one provider. */
  readonly destinations?: readonly DestinationKit[];
  /**
   * The exact hosts the adapter's own calls reach (its management API, token service, ...): lower-case DNS names, no wildcard, port or path.
   * The egress gate lets caller `adapter` reach these and the relay profiles' hosts; caller `relay` reaches relay-profile hosts only.
   */
  readonly hosts?: readonly string[];
  /** The read calls a pasted key may be verified with, by name (KBOX-40): the paste page offers them, `VerifyTarget.hint` names one. Unique `[a-z0-9_]{1,32}` (the registry check). */
  readonly verifyHints?: readonly string[];
  /** KBOX-41: the box's OIDC documents, for a platform that trusts the box's own identity (Google). At most one entry has them. */
  readonly identity?: IdentityDocuments;
  /** KBOX-24: the check core runs when a grant of one of this platform's keys is proposed, and daily on granted keys. */
  readonly grantCheck?: GrantCheck;
  /** KBOX-55: the master this platform's keys depend on that the box makes itself; it never reads `issuer`, nor `issuer` it. */
  readonly boxKey?: BoxMadeKey;
  /** The probe ids (KBOX-42) that `docs/probes/<id>.md` still marks STILL UNVERIFIED. */
  readonly unverified: readonly string[];
}

/** What an adapter is handed when its entry is built: the one way to reach its platform, and time. */
export interface RegistryDeps {
  readonly http: AdapterHttp;
  readonly clock: Clock;
  /** KBOX-41: the box's own identity; core passes it once the domain and the federation's audience are configured, the relay never. */
  readonly identity?: BoxIdentity;
  /** KBOX-14: where an adapter registers what it mints inside core, so the scanner holds it; core passes it, the relay never. */
  readonly minted?: MintedSink;
  /**
   * KBOX-41: a key's stored record by keyref (undefined while there is none); core passes it, the relay never. Only the Google minter reads it
   * (the arch check `key info reads`): every other adapter is handed a location or a stored id by core, never a keyref.
   */
  readonly keyInfo?: (keyref: string) => StoredKey | undefined;
  /**
   * KBOX-55: told the keyref of the box-made key a mint's exchange was signed with, each time the platform accepted it; core marks that key's
   * current generation proven. A rotation's proof (`BoxMadeKey.prove`) is not reported here: the run marks the generation it proved. The
   * relay passes none.
   */
  readonly onExchanged?: (keyref: string) => void;
}
