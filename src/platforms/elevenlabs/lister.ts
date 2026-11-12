// KBOX-39, KBOX-51: the keys the master's workspaces hold, each tagged with its region. A key switched off is listed `disabled`.
import type { AdapterHttp } from '../../ports/http.ts';
import type { KeyLister, KeyListing, PlatformKeyInfo } from '../../ports/issuer.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import { ElevenLabsError } from './api.ts';
import { inEachRegion, readServiceAccounts } from './directory.ts';
import { REGIONS, isRegion } from './regions.ts';
import type { Region } from './regions.ts';

/** `{ region }` asks for one region; no region asks for both, which is what a key recorded without a region needs (the box cannot know which holds it). */
function regionsAt(at: KeyLocation): readonly Region[] {
  if (at.region === undefined) return REGIONS;
  if (!isRegion(at.region)) throw new ElevenLabsError('bad_scope');
  return [at.region];
}

async function keysIn(http: AdapterHttp, regions: readonly Region[], master: Lent): Promise<{ readonly keys: PlatformKeyInfo[]; readonly complete: boolean }> {
  const { read, complete } = await inEachRegion(regions, (region) => readServiceAccounts(http, region, master));
  const keys = read.flatMap(({ region, value }) =>
    value.flatMap((account) => account.keys.map((k): PlatformKeyInfo => ({ platformKeyId: k.keyId, name: k.name, location: { region }, ...(k.disabled ? { disabled: true as const } : {}) }))),
  );
  return { keys, complete };
}

export function createLister(http: AdapterHttp): KeyLister {
  return {
    // The port's plain list has no completeness: it is what the regions that answered hold, and a region that refused the master is left out
    // (the sweep that reads it only acts on what it sees). `listAt` says whether every region answered.
    list: async (master: Lent): Promise<PlatformKeyInfo[]> => (await keysIn(http, REGIONS, master)).keys,
    async listAt(at: KeyLocation, master: Lent): Promise<KeyListing> {
      // The service-account list is one document, with no pages (UNVERIFIED, elevenlabs.service-account-list): a region that answered is read
      // whole, and a region that refused the master leaves the listing incomplete.
      return { at, ...(await keysIn(http, regionsAt(at), master)) };
    },
  };
}
