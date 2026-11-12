// KBOX-40, KBOX-51 step 10: the Anthropic key lister, over the admin key. A key the platform holds switched off (inactive, archived,
// expired) is `disabled`: KBOX-51 counts it as dead.
import type { AdapterHttp } from '../../ports/http.ts';
import type { KeyLister, PlatformKeyInfo } from '../../ports/issuer.ts';
import { DEFAULT_PAGE_SIZE, readKeys } from './keys.ts';
import type { ListedKey } from './keys.ts';

export interface ListerOptions {
  readonly pageSize?: number;
}

const infoOf = (key: ListedKey): PlatformKeyInfo => ({ platformKeyId: key.id, name: key.name, ...(key.status === 'active' ? {} : { disabled: true as const }) });

export function createAnthropicLister(http: AdapterHttp, options: ListerOptions = {}): KeyLister {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  return {
    async list(master) {
      return (await this.listAt({}, master)).keys.filter((k) => k.disabled !== true);
    },
    async listAt(at, master) {
      const pages = await readKeys(http, master, { pageSize });
      return { complete: pages.complete, at, keys: pages.keys.map(infoOf) };
    },
  };
}
