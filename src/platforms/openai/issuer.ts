// KBOX-38, KBOX-51: the OpenAI issuer. An ordinary key is a service-account key in a project: the account is found (or made) by the stem of the
// intent name, and each rotation adds a key to the same account with a platform expiry. Revoke deletes the key by project and id.
import type { AdapterHttp } from '../../ports/http.ts';
import type { IssuedKey, IssueRequest, Issuer, IssuerCapabilities } from '../../ports/issuer.ts';
import type { Lent, PlatformKeyId } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { OpenAiError, failureOfStatus, idOf, isRecord, jsonOf, readAll, send, sendOk } from './client.ts';
import { OPENAI_SHAPE, accountNameOf, classify, keyIdOf, parseKeyId, projectOf } from './scope.ts';

/** Platform expiry set on every key the box makes (the platform allows 1 to 31536000 seconds). Decided here: 90 days, a long rotation interval's margin. */
export const KEY_LIFETIME_SECONDS = 90 * 86_400;

const capabilities: IssuerCapabilities = {
  create: 'api',
  revoke: 'api',
  // The organization admin key can create its successor on the platform, but this adapter only issues project service-account keys: a master is pasted (KBOX-34).
  selfRotate: false,
  overlap: true,
  set: 'none',
  revealOnce: true,
  scopeSchema: { fields: ['items'] },
  shape: OPENAI_SHAPE,
  classify,
};

const projectPath = (project: string): string => `/v1/organization/projects/${project}`;

export function createOpenAiIssuer(http: AdapterHttp): Issuer {
  /** The id of the account named `name` in `project`, made when there is none. */
  async function accountFor(project: string, name: string, master: Lent): Promise<string> {
    const found = await readAll(http, master, `${projectPath(project)}/service_accounts`);
    if (found.failure !== undefined) throw found.failure;
    const existing = found.rows.map((row) => (row['name'] === name ? idOf(row['id']) : undefined)).find((id) => id !== undefined);
    if (existing !== undefined) return existing;
    const made = jsonOf(await sendOk(http, master, { method: 'POST', target: `${projectPath(project)}/service_accounts`, body: { name } }));
    const id = isRecord(made) ? idOf(made['id']) : undefined;
    if (id === undefined) throw new OpenAiError('bad_response');
    // The platform makes a key with every account, without an expiry. The box asks for its own, so this one goes at once.
    const first = isRecord(made) && isRecord(made['api_key']) ? idOf(made['api_key']['id']) : undefined;
    if (first !== undefined) await sendOk(http, master, { method: 'DELETE', target: `${projectPath(project)}/api_keys/${first}` });
    return id;
  }

  return {
    platform: 'openai',
    capabilities: () => capabilities,
    async issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> {
      const project = projectOf(req.scope, req.at);
      const account = await accountFor(project, accountNameOf(intentName), master);
      // UNVERIFIED (openai.create-key-body): the body fields `name`, `expires_in_seconds` and the answer fields `value`, `id`, `expires_at` are read from
      // the platform's published description; the request path itself was seen answering 401 for a bad key and 404 for a made-up sibling.
      const answer = jsonOf(await sendOk(http, master, { method: 'POST', target: `${projectPath(project)}/service_accounts/${account}/api_keys`, body: { name: intentName, expires_in_seconds: KEY_LIFETIME_SECONDS } }));
      const key = isRecord(answer) ? idOf(answer['id']) : undefined;
      const value = isRecord(answer) ? answer['value'] : undefined;
      if (key === undefined || typeof value !== 'string' || value === '') throw new OpenAiError('bad_response');
      const platformKeyId = keyIdOf(project, key);
      const bytes = new TextEncoder().encode(value);
      const expires = isRecord(answer) ? answer['expires_at'] : undefined;
      return { value: makeLent(`openai:${platformKeyId}`, () => Uint8Array.from(bytes)), platformKeyId, ...(typeof expires === 'number' ? { expiresAt: expires * 1000 } : {}) };
    },
    async revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> {
      const parsed = parseKeyId(id);
      if (parsed === undefined) return 'absent';
      const answer = await send(http, master, { method: 'DELETE', target: `${projectPath(parsed.project)}/api_keys/${parsed.key}` });
      if (answer.status >= 200 && answer.status < 300) return 'revoked';
      if (answer.status === 404) return 'absent';
      throw new OpenAiError(failureOfStatus(answer.status), answer.status);
    },
  };
}
