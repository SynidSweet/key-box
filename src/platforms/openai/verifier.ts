// KBOX-38, KBOX-35: the OpenAI verifier. `GET /v1/models` with the key as bearer: 2xx the key works, 401 or 403 it is refused, anything else
// (a 5xx, a 429, a dropped connection) says nothing about the key.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Verifier, VerifyTarget } from '../../ports/issuer.ts';
import type { Lent } from '../../ports/types.ts';
import { OpenAiError, failureOfStatus, send } from './client.ts';

export function createOpenAiVerifier(http: AdapterHttp): Verifier {
  return {
    async verify(key: Lent, target: VerifyTarget): Promise<'ok' | 'rejected' | 'unreachable'> {
      void target;
      try {
        // UNVERIFIED (openai.verifier-call): what a REVOKED real key gets was never observed (a made-up key got 401, code invalid_api_key);
        // the adapter assumes 401, and takes 403 as refused too. A restricted key lacking model access would also look refused.
        const answer = await send(http, key, { method: 'GET', target: '/v1/models' });
        if (answer.status >= 200 && answer.status < 300) return 'ok';
        return failureOfStatus(answer.status) === 'rejected' ? 'rejected' : 'unreachable';
      } catch (thrown) {
        if (thrown instanceof OpenAiError) return 'unreachable';
        throw thrown;
      }
    },
  };
}
