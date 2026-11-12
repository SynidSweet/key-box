// KBOX-40: the Anthropic verifier. An ordinary key is tried on `GET /v1/models?limit=1`, an admin key on the organization key list.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Verifier } from '../../ports/issuer.ts';
import { call } from './call.ts';
import { AnthropicError } from './errors.ts';
import { ANTHROPIC_ADMIN_PREFIX } from './shape.ts';

export function createAnthropicVerifier(http: AdapterHttp): Verifier {
  return {
    async verify(key) {
      // UNVERIFIED (anthropic.models-verify): `GET /v1/models?limit=1` is the cheapest authenticated call and answers 200 for a live ordinary key.
      // UNVERIFIED (anthropic.revoked-key-answer): a revoked key is assumed to answer 401, like a key never issued.
      // UNVERIFIED (anthropic.key-list-status-filter): an admin key is assumed to be refused on /v1/models, so it is tried on the key list.
      const isAdmin = await key.use((bytes) => Promise.resolve(Buffer.from(bytes).toString('utf8').startsWith(ANTHROPIC_ADMIN_PREFIX)));
      try {
        const answer = await call(http, key, 'GET', isAdmin ? '/v1/organizations/api_keys?limit=1' : '/v1/models?limit=1');
        if (answer === undefined) return 'rejected';
        if (answer.status === 200) return 'ok';
        if (answer.status === 401 || answer.status === 403) return 'rejected';
        return 'unreachable';
      } catch (error) {
        if (error instanceof AnthropicError) return 'unreachable';
        throw error;
      }
    },
  };
}
