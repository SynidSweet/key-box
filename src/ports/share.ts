// KBOX-33: where the share writer reads the keys it fingerprints. The source holds the values behind the vault port; the writer
// never sees a vault path. Every current and retired generation of every admin and master key comes back, one entry each.
import type { ShareKey } from '../pure/share-build.ts';

export interface ShareSource {
  keys(): Promise<readonly ShareKey[]>;
}
