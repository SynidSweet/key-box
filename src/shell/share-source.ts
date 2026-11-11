// KBOX-33: the share source over the box's own metadata and vault. For every admin and master key row it reads the current
// generation's value through the vault port (lent, never returned) and pairs it with the adapter's shape for the key's platform.
// A key that has no shape yet (no adapter registered), no value in the vault, or a value that is not UTF-8 text is listed with no
// value and so is not watched. Retired generations and "box generated" arrive with the rotate unit: until then every value is
// `pasted`, which holds it to the strict shape check.
import type { MetaStore } from '../ports/meta.ts';
import type { ShareSource } from '../ports/share.ts';
import type { KeyShape } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { VaultError } from '../pure/errors.ts';
import type { ShareKey } from '../pure/share-build.ts';

export interface MetaShareSourceDeps {
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Vault;
  /** The adapter's `shape` for a platform, or undefined while none is registered. */
  shapeOf(platform: string): KeyShape | undefined;
}

/** The project a key with no project is listed under. */
const NO_PROJECT = '-';

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** The value as text, '' when the vault has none or it is not UTF-8 (such a value has no tier). Other vault failures are fixed errors. */
async function valueOf(vault: Vault, keyref: string, gen: number): Promise<string> {
  try {
    return await vault.lend(keyref, gen).use((bytes) => {
      try {
        return Promise.resolve(utf8.decode(bytes));
      } catch {
        return Promise.resolve('');
      }
    });
  } catch (error) {
    if (error instanceof VaultError && error.failure === 'unknown_key') return '';
    throw error;
  }
}

export function createMetaShareSource(deps: MetaShareSourceDeps): ShareSource {
  return {
    async keys() {
      const out: ShareKey[] = [];
      for (const key of deps.meta.snapshot().keys) {
        if (key.class === 'ordinary') continue;
        const shape = deps.shapeOf(key.platform);
        const value = shape === undefined ? '' : await valueOf(deps.vault, key.keyref, key.gen_current);
        const projects = key.projects.length === 0 ? [NO_PROJECT] : key.projects;
        for (const project of projects) out.push({ project, name: key.name, gen: key.gen_current, retired: false, shape, origin: 'pasted', value });
      }
      return out;
    },
  };
}
