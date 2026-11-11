// KBOX-23: the platform registry. Adding a platform is one folder `src/platforms/<id>/` plus one line here. The platform
// units add their entries; until then no key has a relay profile, so the relay forwards nothing.
import type { PlatformEntry } from '../ports/platform.ts';

export const REGISTRY: readonly PlatformEntry[] = [];
