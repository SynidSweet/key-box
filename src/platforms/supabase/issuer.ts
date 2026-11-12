// KBOX-37: the Supabase key issuer. `POST /v1/projects/{ref}/api-keys?reveal=true` makes a key and, with `reveal`, answers its value; what
// `reveal` returns on a later read is UNVERIFIED, so every create is treated as `revealOnce` and the lister is how the box finds a key again.
// The project is the key's stored location (`at`, KBOX-57) and nothing else: no scope item, no project list, no sole-project guess.
import type { IssuedKey, IssueRequest, Issuer, IssuerCapabilities } from '../../ports/issuer.ts';
import type { Lent, PlatformKeyId } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { failureOf, SupabaseError } from './errors.ts';
import { isRecord } from './management.ts';
import type { Management } from './management.ts';
import { classify, isAccessToken, issueTypeOf, projectAt } from './scope.ts';
import { keyIdOf, PAT_SHAPE, SECRET_SHAPE, splitKeyId } from './shape.ts';

export const PLATFORM = 'supabase';

const CAPABILITIES: IssuerCapabilities = {
  create: 'api',
  revoke: 'api',
  selfRotate: false,
  overlap: true,
  // The database password has a `set` call (password.ts), but rotating it is deferred with the CI destination (design 13): the key
  // issuer does not offer it, so no run is ever driven as `overlap: false` on this platform.
  set: 'none',
  // UNVERIFIED (supabase.reveal-on-create, supabase.reveal-on-get): assumed that the value is shown only in the create response.
  revealOnce: true,
  scopeSchema: { fields: ['items'] },
  shape: SECRET_SHAPE,
  // KBOX-58: the master (a personal access token) has its own shape; every project key has `SECRET_SHAPE`.
  shapeFor: (scope) => (isAccessToken(scope) ? PAT_SHAPE : undefined),
  classify,
};

export function createIssuer(call: Management): Issuer {
  async function revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> {
    const parts = splitKeyId(id);
    if (parts === undefined) return 'absent';
    const answer = await call(master, { method: 'DELETE', path: `/v1/projects/${parts.ref}/api-keys/${parts.id}` });
    if (answer.status === 404) return 'absent';
    if (answer.status !== 200 && answer.status !== 204) throw failureOf(answer.status);
    return 'revoked';
  }

  return {
    platform: PLATFORM,
    capabilities: () => CAPABILITIES,
    async issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> {
      const type = issueTypeOf(req.scope);
      const ref = projectAt(req.at);
      const answer = await call(master, { method: 'POST', path: `/v1/projects/${ref}/api-keys`, query: { reveal: 'true' }, body: { type, name: intentName } });
      if (answer.status !== 200 && answer.status !== 201) throw failureOf(answer.status);
      const body = answer.json.ok ? answer.json.value : undefined;
      const id = isRecord(body) ? body['id'] : undefined;
      if (typeof id !== 'string' || splitKeyId(keyIdOf(ref, id)) === undefined) throw new SupabaseError('bad_answer');
      const value = isRecord(body) ? body['api_key'] : undefined;
      const platformKeyId = keyIdOf(ref, id);
      if (typeof value !== 'string' || value === '') {
        // The platform made a key whose value the box never saw: it is revoked here, and the failure says whether that worked.
        try {
          await revoke(platformKeyId, master);
        } catch {
          throw new SupabaseError('no_key_value_not_cleaned');
        }
        throw new SupabaseError('no_key_value');
      }
      const bytes = new TextEncoder().encode(value);
      // No `location`: the create answer names no project (KBOX-57: left out when the answer names no place; the call path fixed it).
      return { value: makeLent(platformKeyId, () => Uint8Array.from(bytes)), platformKeyId };
    },
    revoke,
  };
}
