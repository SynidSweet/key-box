// KBOX-39: the ElevenLabs issuer. A key is made in a service account of the master's workspace, shown once in the create answer, and
// revoked by `DELETE`. The master and every created key are Lent: used inside `use(...)`, never copied, never in an error.
import type { AdapterHttp } from '../../ports/http.ts';
import type { IssuedKey, IssueRequest, Issuer, IssuerCapabilities } from '../../ports/issuer.ts';
import type { KeyLocation, Lent, PlatformKeyId } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { ElevenLabsError, call, expectJson, isRecord, isRefusal, segment } from './api.ts';
import { locateKey, readServiceAccounts } from './directory.ts';
import { isRegion } from './regions.ts';
import type { Region } from './regions.ts';
import { classifyScope, parseScope } from './scope.ts';
import { ELEVENLABS_SHAPE } from './shape.ts';

/** KBOX-57: the region is the key's stored location, and only it; no region, or one the platform does not have, is refused before any call. */
function regionAt(at: KeyLocation): Region {
  if (at.region === undefined || !isRegion(at.region)) throw new ElevenLabsError('bad_scope');
  return at.region;
}

/** The service account a key is made in: the scope's own, else the workspace's only one. */
async function serviceAccountFor(http: AdapterHttp, region: Region, asked: string | undefined, master: Lent): Promise<string> {
  if (asked !== undefined) return asked;
  const accounts = await readServiceAccounts(http, region, master);
  const [only] = accounts;
  if (accounts.length !== 1 || only === undefined) throw new ElevenLabsError('service_account_unclear');
  return only.id;
}

export function createIssuer(http: AdapterHttp): Issuer {
  return {
    platform: 'elevenlabs',
    capabilities: (): IssuerCapabilities => ({
      create: 'api',
      revoke: 'api',
      selfRotate: true,
      overlap: true,
      set: 'none',
      revealOnce: true,
      scopeSchema: { fields: ['items'] },
      shape: ELEVENLABS_SHAPE,
      classify: classifyScope,
    }),
    async issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> {
      const scope = parseScope(req.scope);
      const region = regionAt(req.at);
      const account = await serviceAccountFor(http, region, scope.serviceAccount, master);
      const answer = await call(http, region, 'POST', `/v1/service-accounts/${segment(account)}/api-keys`, master, { name: intentName, permissions: scope.permissions });
      const body = expectJson(answer);
      const value = isRecord(body) ? body['xi-api-key'] : undefined;
      const keyId = isRecord(body) ? body['key_id'] : undefined;
      if (typeof value !== 'string' || value === '' || typeof keyId !== 'string' || keyId === '') throw new ElevenLabsError('malformed');
      const kept = Buffer.from(value);
      return { value: makeLent(`elevenlabs:${keyId}`, () => Uint8Array.from(kept)), platformKeyId: keyId };
    },
    async revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> {
      const found = await locateKey(http, id, master);
      if (found === undefined) return 'absent';
      const answer = await call(http, found.region, 'DELETE', `/v1/service-accounts/${segment(found.serviceAccount)}/api-keys/${segment(id)}`, master);
      if (answer.status === 404) return 'absent';
      if (answer.status >= 200 && answer.status < 300) return 'revoked';
      throw new ElevenLabsError(isRefusal(answer) ? 'rejected' : 'platform_error', answer.status);
    },
  };
}
