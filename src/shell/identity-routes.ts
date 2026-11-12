// KBOX-41, KBOX-55: the box's OIDC documents on keys.<domain>, open to anyone (Google's STS fetches them): the discovery document and the JWKS.
// The JWKS lists the box-made signing key's generations by their status: the one waiting to become current (`pending`), the current one and
// the one before it while it is still kept (`grace`), never by arithmetic on `gen_current`, so a failed generation is never published and a
// pending one after it always is (KBOX-22 names these documents as places that hold a URL to the box).
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { VaultError } from '../pure/errors.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';
import { kitFor } from './rotation-ports.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { GenRow } from './rotation-store.ts';

export interface IdentityRoutesDeps {
  readonly registry: readonly PlatformEntry[];
  /** Which stored key is the platform's box-made key (KBOX-55): only its generations are published. */
  readonly source: Pick<PlatformSource, 'platform'>;
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Pick<Vault, 'lend'>;
  /** The generations the rotation store holds for a key, read at each request. */
  readonly generations: (keyref: string) => readonly Pick<GenRow, 'gen' | 'status'>[];
  /** `https://keys.<domain>`. */
  readonly issuer: string;
}

/** The statuses a published generation has: about to be current, current, or kept in grace. */
const PUBLISHED: ReadonlySet<GenRow['status']> = new Set(['pending', 'current', 'grace']);

/** The two routes, or none when no platform trusts the box's identity. Two platforms that both would are refused: one issuer, one key set. */
export function identityRoutes(deps: IdentityRoutesDeps): readonly Route[] {
  const entries = deps.registry.filter((e) => e.identity !== undefined);
  const [entry, second] = entries;
  if (second !== undefined) throw new RangeError('two platforms register the box identity documents');
  const documents = entry?.identity;
  if (entry === undefined || documents === undefined) return [];

  /** Each published generation of the box-made key, newest first; one the vault does not hold (never stored, or deleted) is not listed. */
  const signingKeys = (): readonly Lent[] => {
    const keys: Lent[] = [];
    for (const row of deps.meta.snapshot().keys.filter((k) => k.platform === entry.id && kitFor(deps.source, k)?.boxKey !== undefined)) {
      const gens = deps.generations(row.keyref).filter((g) => PUBLISHED.has(g.status)).map((g) => g.gen).sort((a, b) => b - a);
      for (const gen of gens) {
        try {
          keys.push(deps.vault.lend(row.keyref, gen));
        } catch (error) {
          if (error instanceof VaultError && error.failure === 'unknown_key') continue;
          throw error;
        }
      }
    }
    return keys;
  };

  return [
    route({ method: 'GET', path: '/.well-known/openid-configuration', surface: 'phone', handle: () => ({ json: documents.discovery(deps.issuer) }) }),
    route({ method: 'GET', path: '/.well-known/jwks.json', surface: 'phone', handle: async () => ({ json: await documents.jwks(signingKeys()) }) }),
  ];
}
