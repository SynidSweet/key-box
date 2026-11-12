// KBOX-23: one registry line per platform. Adding a platform is one folder `src/platforms/<id>/` plus one entry here; the entry carries
// everything the adapter registers, so no shared wiring changes with it.
import type { DestinationKit } from './destination.ts';
import type { Issuer, KeyLister, Verifier } from './issuer.ts';
import type { DenyRule, RelayProfile } from './relay-profile.ts';
import type { KeyClass, KeyShape, PlatformId, Scope } from './types.ts';

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
  readonly classify?: (scope: Scope) => KeyClass;
  /** The destination adapters this platform provides; the kind of each is its `destination.kind`. A kind has at most one provider. */
  readonly destinations?: readonly DestinationKit[];
  /** The probe ids (KBOX-42) that `docs/probes/<id>.md` still marks STILL UNVERIFIED. */
  readonly unverified: readonly string[];
}
