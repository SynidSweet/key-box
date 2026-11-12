// KBOX-41: the box's OIDC documents on keys.<domain>, open to anyone (Google's STS fetches them): the discovery document and the JWKS. The
// JWKS lists every live generation of the identity platform's master keys: the one waiting to become current, the current one and the one
// before it while it is still kept (KBOX-22 names these documents as places that hold a URL to the box).
import type { MetaStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';
import { VaultError } from '../pure/errors.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';

export interface IdentityRoutesDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly vault: Pick<Vault, 'lend'>;
  /** `https://keys.<domain>`. */
  readonly issuer: string;
}

/** The two routes, or none when no platform trusts the box's identity. Two platforms that both would are refused: one issuer, one key set. */
export function identityRoutes(deps: IdentityRoutesDeps): readonly Route[] {
  const entries = deps.registry.filter((e) => e.identity !== undefined);
  const [entry, second] = entries;
  if (second !== undefined) throw new RangeError('two platforms register the box identity documents');
  const documents = entry?.identity;
  if (entry === undefined || documents === undefined) return [];

  /** Each live generation, newest first; a generation the vault does not hold (never stored, or retired and deleted) is not listed. */
  const signingKeys = (): readonly Lent[] => {
    const keys: Lent[] = [];
    for (const row of deps.meta.snapshot().keys.filter((k) => k.platform === entry.id && k.class === 'master')) {
      for (const gen of [row.gen_current + 1, row.gen_current, row.gen_current - 1].filter((g) => g >= 1)) {
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
