// KBOX-36: the Vercel verifier. A master (team-wide) token reads its own user, `GET /v2/user` (VERIFIED path). A project-scoped token cannot,
// so a 401 or 403 there is not yet a verdict: the token reads itself (`GET /v5/user/tokens/current`) to learn its project and then reads that
// project (`GET /v9/projects/{id}`). Only an answer that says the key is refused is `rejected`; a transport failure, a 5xx, a 429 or an answer
// that is not what the call expects is `unreachable` (no verdict).
import type { Verifier, VerifyTarget } from '../../ports/issuer.ts';
import type { Lent } from '../../ports/types.ts';
import { recordOf, segment, textOf } from './api.ts';
import type { ApiAnswer, VercelApi } from './api.ts';
import { VercelError, isSuccess } from './errors.ts';

type Verdict = 'ok' | 'rejected' | 'unreachable';

const refused = (answer: ApiAnswer): boolean => answer.status === 401 || answer.status === 403;

/** The platform saying the token is invalid: a 401, or a 403 whose error carries `invalidToken: true` (probe, vercel.verifier-user-path). Any other 403 may be a live token refused a permission. */
const saysInvalid = (answer: ApiAnswer): boolean => answer.status === 401 || (answer.status === 403 && recordOf(recordOf(answer.json)?.['error'])?.['invalidToken'] === true);

/** What one call says of the key: `ok` on 2xx, `rejected` on 401/403, else no verdict. */
const readVerdict = (answer: ApiAnswer): Verdict => (isSuccess(answer.status) ? 'ok' : refused(answer) ? 'rejected' : 'unreachable');

async function verifyOnce(api: VercelApi, key: Lent): Promise<Verdict> {
  const user = await api.call({ method: 'GET', path: '/v2/user' }, key);
  if (!refused(user)) return readVerdict(user);
  // UNVERIFIED (vercel.verifier-project-token): that a project token's own record is readable at `tokens/current` and names its `projectId`,
  // and that `GET /v9/projects/{id}` answers 200 to it. A live project token refused there is not told from a dead one by a bare 403, so only
  // the platform's own invalid-token answer is `rejected`; any other refusal is no verdict.
  const self = await api.call({ method: 'GET', path: '/v5/user/tokens/current' }, key);
  if (!isSuccess(self.status)) return saysInvalid(self) ? 'rejected' : 'unreachable';
  const token = recordOf(recordOf(self.json)?.['token']);
  if (token === undefined) return 'unreachable';
  const projectId = textOf(token['projectId']);
  if (projectId === undefined) return 'ok';
  const project = await api.call({ method: 'GET', path: `/v9/projects/${segment(projectId)}` }, key);
  // A project the token cannot find is a token that does not work for it.
  return project.status === 404 ? 'rejected' : readVerdict(project);
}

export function createVercelVerifier(api: VercelApi): Verifier {
  return {
    async verify(key: Lent, target: VerifyTarget): Promise<Verdict> {
      void target;
      try {
        return await verifyOnce(api, key);
      } catch (error) {
        if (!(error instanceof VercelError)) throw error;
        // A value that cannot be a header is no token the platform issued.
        return error.code === 'bad_key' ? 'rejected' : 'unreachable';
      }
    },
  };
}
