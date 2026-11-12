// KBOX-36: the Vercel issuer. A token is `POST /v3/user/tokens` (name, optional projectId); its value is in that response only, so
// `revealOnce` is true and the lister is required. Revoke is `DELETE /v3/user/tokens/{id}`; a 404 is `absent` and is not proof.
import type { IssuedKey, Issuer, IssuerCapabilities, IssueRequest } from '../../ports/issuer.ts';
import type { Lent, PlatformKeyId } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { encodeJson, recordOf, segment, textOf } from './api.ts';
import type { VercelApi } from './api.ts';
import { VercelError, requireSuccess } from './errors.ts';
import { classifyScope, parseTokenScope } from './scope.ts';
import { VERCEL_SHAPE } from './shape.ts';

const CAPABILITIES: IssuerCapabilities = {
  create: 'api',
  revoke: 'api',
  selfRotate: true,
  overlap: true,
  set: 'none',
  revealOnce: true,
  scopeSchema: { fields: ['projectId', 'teamId'] },
  shape: VERCEL_SHAPE,
  classify: classifyScope,
};

export function createVercelIssuer(api: VercelApi): Issuer {
  return {
    platform: 'vercel',
    capabilities: () => CAPABILITIES,
    async issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> {
      const scope = parseTokenScope(req.scope);
      // UNVERIFIED (vercel.cli-project-token): a project token made here is delivered to agents for `vercel deploy` and `vercel env pull`;
      // the CLI source supports that and no live call has shown it.
      const body = encodeJson({ name: intentName, ...(scope.projectId === undefined ? {} : { projectId: scope.projectId }) });
      const answer = await api.call({ method: 'POST', path: '/v3/user/tokens', ...(scope.teamId === undefined ? {} : { query: `teamId=${encodeURIComponent(scope.teamId)}` }), body }, master);
      requireSuccess(answer.status);
      const reply = recordOf(answer.json);
      const value = textOf(reply?.['bearerToken']);
      const id = textOf(recordOf(reply?.['token'])?.['id']);
      if (value === undefined || id === undefined) throw new VercelError('malformed');
      return { value: makeLent('vercel:issued', () => Buffer.from(value)), platformKeyId: id };
    },
    async revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> {
      const answer = await api.call({ method: 'DELETE', path: `/v3/user/tokens/${segment(id)}` }, master);
      if (answer.status === 404) return 'absent';
      requireSuccess(answer.status);
      return 'revoked';
    },
  };
}
