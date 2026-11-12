// KBOX-23: the platform registry. It is built, not listed: each platform folder `src/platforms/<id>/` exports `create<Name>Entry(deps)` and
// `createRegistry` calls it on one line. The entry carries everything the adapter registers, so no shared wiring changes with it.
import type { Clock } from '../ports/clock.ts';
import type { AdapterHttp } from '../ports/http.ts';
import { refusingAdapterHttp } from '../ports/http.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import { createVercelEntry } from './vercel/index.ts';

/** What an adapter is handed when its entry is built: the one way to reach its platform, and time. */
export interface RegistryDeps {
  readonly http: AdapterHttp;
  readonly clock: Clock;
}

export function createRegistry(deps: RegistryDeps): readonly PlatformEntry[] {
  return [createVercelEntry(deps)];
}

/** The registry as a process that makes no adapter calls sees it: every call is refused and time stands at 0. For structure checks only. */
export const REGISTRY: readonly PlatformEntry[] = createRegistry({ http: refusingAdapterHttp, clock: { now: () => 0 } });
