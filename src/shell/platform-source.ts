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
import { kitFor, tryLend } from './rotation-ports.ts';
import type { MasterResult, MasterRow, PlatformKit, PlatformSource, RevokedProof } from './rotation-ports.ts';
import type { KeyInfo } from './rotation-store.ts';

export interface PlatformSourceDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Pick<Vault, 'lend'>;
  /** A key row's stored scope items and location (`readKeyInfo` over meta.db): what decides whether a master row serves a key. */
  readonly keyInfo: (keyref: string) => Pick<KeyInfo, 'scopeItems' | 'location'> | undefined;
  /** KBOX-62: the keyrefs with an open deletion; none is a master candidate. Absent: no key is being deleted. */
  readonly deleting?: () => ReadonlySet<string>;
}

/**
 * KBOX-62: the entry's revoked evidence that counts: a part whose probe the entry no longer lists as unverified, and whose call the entry has
 * (`answerStatus` for the statuses, a lister for the listing). None counts: undefined.
 */
function revokedOf(entry: PlatformEntry): RevokedProof | undefined {
  const declared = entry.revokedEvidence;
  if (declared === undefined) return undefined;
  const proven = (probe: string): boolean => !entry.unverified.includes(probe);
  const statuses = declared.verifier !== undefined && entry.verifier?.answerStatus !== undefined && proven(declared.verifier.probe) ? declared.verifier.statuses : undefined;
  const lister = declared.lister !== undefined && entry.lister !== undefined && proven(declared.lister.probe);
  if (statuses === undefined && !lister) return undefined;
  return { ...(statuses === undefined ? {} : { statuses }), ...(lister ? { lister: true as const } : {}) };
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
  ...(entry.verifyHints === undefined ? {} : { verifyHints: entry.verifyHints }),
  ...(entry.boxKey === undefined ? {} : { boxKey: entry.boxKey }),
  ...revokedPart(entry),
});

/** The kit's `revoked` member, present only when some evidence counts. */
const revokedPart = (entry: PlatformEntry): Pick<PlatformKit, 'revoked'> => {
  const revoked = revokedOf(entry);
  return revoked === undefined ? {} : { revoked };
};

/** A candidate master row with the scope items its authority is read from. */
interface Candidate extends MasterRow {
  readonly items: readonly string[];
  readonly keyref: string;
}

/** The distinct items with this prefix, in one order: what a master and a key must share for each `masterItems` prefix. */
const itemsWith = (items: readonly string[], prefix: string): readonly string[] => [...new Set(items.filter((i) => i.startsWith(prefix)))].sort();
const sameItems = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

export function createPlatformSource(deps: PlatformSourceDeps): PlatformSource {
  const entryOf = (id: PlatformId): PlatformEntry | undefined => deps.registry.find((e) => e.id === id);

  const platformKit = (id: PlatformId): PlatformKit | undefined => {
    const entry = entryOf(id);
    return entry === undefined ? undefined : kitOf(entry);
  };

  /**
   * KBOX-57: the platform's master rows that can serve at all: master class; master by its own kit's classification (`kitFor`, KBOX-55: the
   * box-made key is master by its kit) of the row's stored scope at its stored location (a row raised to master only by the KBOX-15 floor, a
   * Vercel project token, is none); a current generation the vault lends (a failed create leaves its row). A row without a stored record, or
   * whose kit has no registered classification, has none.
   */
  const candidates = (platform: PlatformId): readonly Candidate[] => {
    const deleting = deps.deleting?.() ?? new Set<string>();
    return deps.meta
      .snapshot()
      .keys.filter((k) => k.class === 'master' && k.platform === platform && !deleting.has(k.keyref))
      .flatMap((row) => {
        const classify = classifierOf(kitFor({ platform: platformKit }, { platform, keyref: row.keyref }));
        const info = deps.keyInfo(row.keyref);
        if (classify === undefined || info === undefined || classify({ items: info.scopeItems }, info.location) !== 'master') return [];
        const lent = tryLend(deps.vault, row.keyref, row.gen_current);
        return lent.ok ? [{ at: info.location, items: info.scopeItems, value: lent.value, keyref: row.keyref }] : [];
      });
  };

  /** KBOX-57: the candidates that serve a key here: covering its location and sharing each `masterItems` prefix's items. */
  const serving = (platform: PlatformId, at: KeyLocation, items: readonly string[]): readonly Candidate[] => {
    const prefixes = entryOf(platform)?.masterItems ?? [];
    return candidates(platform).filter((c) => covers(c.at, at) && prefixes.every((p) => sameItems(itemsWith(c.items, p), itemsWith(items, p))));
  };

  return {
    platform: platformKit,
    // The kit of the one entry that registered this kind (the registry check refuses two); the workstation and unknown text have none.
    destination: (kind) => {
      const adapterKind = adapterKindOf(kind);
      return adapterKind === undefined ? undefined : deps.registry.flatMap((e) => e.destinations ?? []).find((k) => k.destination.kind === adapterKind);
    },
    // KBOX-57: by platform and stored location (plus the entry's masterItems), never by `projects` or row order; two are refused, never guessed.
    master: (platform: PlatformId, at: KeyLocation, items: readonly string[]): MasterResult => {
      const [only, second] = serving(platform, at, items);
      if (only === undefined) return { ok: false, code: 'no_master' };
      if (second !== undefined) return { ok: false, code: 'master_ambiguous' };
      return { ok: true, value: only.value };
    },
    masters: (platform) => candidates(platform).map(({ at, items, value }) => ({ at, items, value })),
    masterKeyrefOf: (platform, at, items) => {
      const [only, second] = serving(platform, at, items);
      return second === undefined ? only?.keyref : undefined;
    },
  };
}
