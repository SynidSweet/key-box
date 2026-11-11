// The rotation shell's view of the platform registry (KBOX-23): the adapters of a registered platform and its master key. The registry
// holds issuers and listers only; each adapter unit that adds a verifier, a key page or a destination kind extends `PlatformEntry` and the
// two lines here that read it.
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import type { PlatformKit, PlatformSource } from './rotation-ports.ts';

export interface PlatformSourceDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Pick<Vault, 'lend'>;
}

const kitOf = (entry: PlatformEntry): PlatformKit => ({
  ...(entry.issuer === undefined ? {} : { issuer: entry.issuer }),
  ...(entry.lister === undefined ? {} : { lister: entry.lister }),
});

export function createPlatformSource(deps: PlatformSourceDeps): PlatformSource {
  return {
    platform: (id) => {
      const entry = deps.registry.find((e) => e.id === id);
      return entry === undefined ? undefined : kitOf(entry);
    },
    // No destination adapter exists yet: a destination kind has a kit once an adapter unit registers one.
    destination: () => undefined,
    // The platform's master key is the current generation of its master-class key row (the owner pastes it once, KBOX-36).
    master: (platform): Lent => {
      const row = deps.meta.snapshot().keys.find((k) => k.class === 'master' && k.platform === platform);
      if (row === undefined) throw new RangeError(`no master key for platform ${platform}`);
      return deps.vault.lend(row.keyref, row.gen_current);
    },
  };
}
