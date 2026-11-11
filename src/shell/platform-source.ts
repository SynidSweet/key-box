// The rotation shell's view of the platform registry (KBOX-23): the adapters of a registered platform and its master key. The registry
// holds issuers and listers only; each adapter unit that adds a verifier, a key page or a destination kind extends `PlatformEntry` and the
// two lines here that read it.
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { ApiError } from '../pure/errors.ts';
import { tryLend } from './rotation-ports.ts';
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
    // The platform's master key is the current generation of a master-class key row (the owner pastes it once, KBOX-36). A row whose current
    // generation the vault cannot lend (a failed create leaves its row) does not qualify; the key's own project's row wins over others; two
    // that still qualify are refused, never chosen by row order (review N5).
    master: (platform, projects = []): Lent => {
      const qualified = deps.meta
        .snapshot()
        .keys.filter((k) => k.class === 'master' && k.platform === platform)
        .flatMap((row) => {
          const lent = tryLend(deps.vault, row.keyref, row.gen_current);
          return lent.ok ? [{ projects: row.projects, value: lent.value }] : [];
        });
      const own = qualified.filter((m) => m.projects.some((p) => projects.includes(p)));
      const pool = own.length > 0 ? own : qualified;
      const [only, second] = pool;
      if (only === undefined) throw new RangeError(`no master key for platform ${platform}`);
      if (second !== undefined) throw new ApiError('conflict', 'master_ambiguous');
      return only.value;
    },
  };
}
