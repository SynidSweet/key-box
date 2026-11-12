// KBOX-37, KBOX-58: the verifier of the master, a personal access token. It applies to a key whose scope items include `access-token` and to no
// project key: a secret or publishable key can be tested only at `<ref>.supabase.co`, a host adapter egress never reaches. The call is
// `GET https://api.supabase.com/v1/projects` with the value under test as the bearer (UNVERIFIED supabase.pat-verify). A value that is not of the
// token's shape is never sent. Only the platform's own refusal is proof of death: a 401 carrying its JSON error object; a 403 (a WAF or an edge
// block answers 403 too), any other 401 and every other answer are `unreachable`, never `rejected` (so `errors.ts` `failureOf` is not used here).
import type { Verifier } from '../../ports/issuer.ts';
import type { Lent } from '../../ports/types.ts';
import { matchesShape } from '../../pure/class.ts';
import type { Parsed } from '../../pure/schemas.ts';
import { SupabaseError } from './errors.ts';
import { isRecord } from './management.ts';
import type { Answer, Management } from './management.ts';
import { isAccessToken } from './scope.ts';
import { PAT_SHAPE } from './shape.ts';

/** The platform's error object (`{message}`, the body of every refusal the probe saw): what makes a 401 the platform's own answer. */
const isErrorObject = (json: Parsed<unknown>): boolean => json.ok && isRecord(json.value) && typeof json.value['message'] === 'string';

/** The shape guard, inside `use(...)`: the value is read there and never copied out. */
const tokenShaped = (key: Lent): Promise<boolean> => key.use((bytes) => Promise.resolve(matchesShape(PAT_SHAPE, Buffer.from(bytes).toString('utf8'))));

function verdictOf(answer: Answer): 'ok' | 'rejected' | 'unreachable' {
  if (answer.status === 200) return answer.json.ok && Array.isArray(answer.json.value) ? 'ok' : 'unreachable';
  if (answer.status === 401) return isErrorObject(answer.json) ? 'rejected' : 'unreachable';
  return 'unreachable';
}

export function createVerifier(call: Management): Verifier {
  return {
    appliesTo: (scope) => isAccessToken(scope),
    async verify(key) {
      if (!(await tokenShaped(key))) return 'unreachable';
      try {
        return verdictOf(await call(key, { method: 'GET', path: '/v1/projects' }));
      } catch (error) {
        // A transport failure: no answer, so no verdict but `unreachable`. Anything else is not ours to name and goes on.
        if (error instanceof SupabaseError && error.code === 'unreachable') return 'unreachable';
        throw error;
      }
    },
  };
}
