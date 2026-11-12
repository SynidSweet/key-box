// The rotation shell's view of the platform registry (KBOX-23): the kit of a registered platform (issuer, lister, verifier, key page, shape), the
// destination kit of a kind, and the platform's master key for a key (KBOX-57). An adapter unit adds only its registry entry; nothing here
// changes with it.
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { KeyLocation, PlatformId } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { adapterKindOf } from '../pure/destination-kind.ts';
import { covers } from '../pure/location.ts';
import { classifierOf } from '../pure/platform-shape.ts';
import { tryLend } from './rotation-ports.ts';
import type { MasterResult, MasterRow, PlatformKit, PlatformSource } from './rotation-ports.ts';
import type { KeyInfo } from './rotation-store.ts';

export interface PlatformSourceDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Pick<Vault, 'lend'>;
  /** A key row's stored scope items and location (`readKeyInfo` over meta.db): what decides whether a master row serves a key. */
  readonly keyInfo: (keyref: string) => Pick<KeyInfo, 'scopeItems' | 'location'> | undefined;
}

const kitOf = (entry: PlatformEntry): PlatformKit => ({
  ...(entry.issuer === undefined ? {} : { issuer: entry.issuer }),
  ...(entry.lister === undefined ? {} : { lister: entry.lister }),
  ...(entry.verifier === undefined ? {} : { verifier: entry.verifier }),
  ...(entry.keyPageUrl === undefined ? {} : { keyPageUrl: entry.keyPageUrl }),
  ...(entry.shape === undefined ? {} : { shape: entry.shape }),
  ...(entry.classify === undefined ? {} : { classify: entry.classify }),
  ...(entry.location === undefined ? {} : { location: entry.location }),
  ...(entry.locationProver === undefined ? {} : { locationProver: entry.locationProver }),
  ...(entry.retirer === undefined ? {} : { retirer: entry.retirer }),
});

/** A candidate master row with the scope items its authority is read from. */
interface Candidate extends MasterRow {
  readonly items: readonly string[];
}

/** The distinct items with this prefix, in one order: what a master and a key must share for each `masterItems` prefix. */
const itemsWith = (items: readonly string[], prefix: string): readonly string[] => [...new Set(items.filter((i) => i.startsWith(prefix)))].sort();
const sameItems = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

export function createPlatformSource(deps: PlatformSourceDeps): PlatformSource {
  const entryOf = (id: PlatformId): PlatformEntry | undefined => deps.registry.find((e) => e.id === id);

  /**
   * KBOX-57: the platform's master rows that can serve at all: master class; master by the entry's own classification of the row's stored
   * scope at its stored location (a row raised to master only by the KBOX-15 floor, a Vercel project token, is none); a current generation the
   * vault lends (a failed create leaves its row). A row without a stored record, or a platform without a registered classification, has none.
   */
  const candidates = (platform: PlatformId): readonly Candidate[] => {
    const entry = entryOf(platform);
    const classify = entry === undefined ? undefined : classifierOf(kitOf(entry));
    if (classify === undefined) return [];
    return deps.meta
      .snapshot()
      .keys.filter((k) => k.class === 'master' && k.platform === platform)
      .flatMap((row) => {
        const info = deps.keyInfo(row.keyref);
        if (info === undefined || classify({ items: info.scopeItems }, info.location) !== 'master') return [];
        const lent = tryLend(deps.vault, row.keyref, row.gen_current);
        return lent.ok ? [{ at: info.location, items: info.scopeItems, value: lent.value }] : [];
      });
  };

  return {
    platform: (id) => {
      const entry = entryOf(id);
      return entry === undefined ? undefined : kitOf(entry);
    },
    // The kit of the one entry that registered this kind (the registry check refuses two); the workstation and unknown text have none.
    destination: (kind) => {
      const adapterKind = adapterKindOf(kind);
      return adapterKind === undefined ? undefined : deps.registry.flatMap((e) => e.destinations ?? []).find((k) => k.destination.kind === adapterKind);
    },
    // KBOX-57: by platform and stored location (plus the entry's masterItems), never by `projects` or row order; two are refused, never guessed.
    master: (platform: PlatformId, at: KeyLocation, items: readonly string[]): MasterResult => {
      const prefixes = entryOf(platform)?.masterItems ?? [];
      const serving = candidates(platform).filter((c) => covers(c.at, at) && prefixes.every((p) => sameItems(itemsWith(c.items, p), itemsWith(items, p))));
      const [only, second] = serving;
      if (only === undefined) return { ok: false, code: 'no_master' };
      if (second !== undefined) return { ok: false, code: 'master_ambiguous' };
      return { ok: true, value: only.value };
    },
    masters: (platform) => candidates(platform).map(({ at, value }) => ({ at, value })),
  };
}
