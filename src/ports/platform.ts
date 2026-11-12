// KBOX-23: one registry line per platform. Adding a platform is one folder `src/platforms/<id>/` plus one entry here; the entry carries
// everything the adapter registers, so no shared wiring changes with it.
import type { DestinationKit } from './destination.ts';
import type { Issuer, KeyLister, LocationProver, Verifier } from './issuer.ts';
import type { Clock } from './clock.ts';
import type { AdapterHttp } from './http.ts';
import type { DenyRule, RelayProfile } from './relay-profile.ts';
import type { KeyClass, KeyLocation, KeyShape, LocationSchema, PlatformId, Scope } from './types.ts';

export interface PlatformEntry {
  readonly id: PlatformId;
  readonly issuer?: Issuer;
  /** Required when the issuer's `revealOnce` is true. */
  readonly lister?: KeyLister;
  readonly relay?: RelayProfile;
  /** A platform in `relayDenyOnly` (Vercel, ElevenLabs in v1) exports its mustDeny list here and has no relay profile. */
  readonly denyOnly?: readonly DenyRule[];
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
  /** The probe ids (KBOX-42) that `docs/probes/<id>.md` still marks STILL UNVERIFIED. */
  readonly unverified: readonly string[];
}

/** What an adapter is handed when its entry is built: the one way to reach its platform, and time. */
export interface RegistryDeps {
  readonly http: AdapterHttp;
  readonly clock: Clock;
}
