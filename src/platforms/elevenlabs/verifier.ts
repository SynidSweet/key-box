// KBOX-39: is this key alive. `GET /v1/user` as the key, on each region in turn; one 2xx is `ok`.
// UNVERIFIED (elevenlabs.verifier-call): a fake key got 401 on /v1/user, but a revoked key's answer, and the answer to a live key that lacks
// `user_read`, were not observed. Assumed: a revoked key is 401 and a live restricted key is 200 or a 403; both 401 and 403 read as rejected.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Verifier, VerifyTarget } from '../../ports/issuer.ts';
import type { Lent } from '../../ports/types.ts';
import { ElevenLabsError, call, isRefusal } from './api.ts';
import { REGIONS } from './regions.ts';
import type { Region } from './regions.ts';

type Outcome = 'ok' | 'rejected' | 'unreachable';

async function verifyIn(http: AdapterHttp, region: Region, key: Lent): Promise<Outcome> {
  try {
    const answer = await call(http, region, 'GET', '/v1/user', key);
    if (answer.status >= 200 && answer.status < 300) return 'ok';
    // Any other status than a refusal (a 5xx, a 429, a 404) says nothing about the key.
    return isRefusal(answer) ? 'rejected' : 'unreachable';
  } catch (e) {
    if (e instanceof ElevenLabsError && e.code === 'unreachable') return 'unreachable';
    throw e;
  }
}

export function createVerifier(http: AdapterHttp): Verifier {
  return {
    async verify(key: Lent, target: VerifyTarget): Promise<Outcome> {
      void target;
      const outcomes: Outcome[] = [];
      for (const region of REGIONS) outcomes.push(await verifyIn(http, region, key));
      if (outcomes.includes('ok')) return 'ok';
      return outcomes.includes('unreachable') ? 'unreachable' : 'rejected';
    },
  };
}
