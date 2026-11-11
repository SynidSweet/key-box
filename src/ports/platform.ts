// KBOX-23: one registry line per platform. Adding a platform is one folder `src/platforms/<id>/` plus one entry here.
import type { Issuer, KeyLister } from './issuer.ts';
import type { DenyRule, RelayProfile } from './relay-profile.ts';
import type { PlatformId } from './types.ts';

export interface PlatformEntry {
  readonly id: PlatformId;
  readonly issuer?: Issuer;
  /** Required when the issuer's `revealOnce` is true. */
  readonly lister?: KeyLister;
  readonly relay?: RelayProfile;
  /** A platform in `relayDenyOnly` (Vercel, ElevenLabs in v1) exports its mustDeny list here and has no relay profile. */
  readonly denyOnly?: readonly DenyRule[];
}
