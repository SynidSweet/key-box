// KBOX-57 Proof: before a Supabase key is proposed, the platform confirms, with the master chosen for the key (a personal access token), that it
// can see the key's project, the field that names the relay host. `GET /v1/projects/{ref}`: 200 naming that project is `seen`; 403 and 404 are
// `unseen`; every other answer (401, 429, 5xx, any other status, a transport failure, a body that is not a project or names another one) throws,
// so the proposal is `unavailable` and never proceeds on a doubt.
// UNVERIFIED (supabase.project-get-shape): the 200, 403 and 404 answers of this call are read from the platform's published description, never
// observed with a real token.
import type { LocationProver } from '../../ports/issuer.ts';
import { failureOf, SupabaseError } from './errors.ts';
import { isRecord } from './management.ts';
import type { Management } from './management.ts';
import { projectAt } from './scope.ts';

/** The project a project read names: its `ref`, or on older answers its `id`. */
function namedRef(body: unknown): unknown {
  if (!isRecord(body)) return undefined;
  return body['ref'] ?? body['id'];
}

export function createProver(call: Management): LocationProver {
  return {
    async prove(at, master) {
      const ref = projectAt(at);
      const answer = await call(master, { method: 'GET', path: `/v1/projects/${ref}` });
      if (answer.status === 403 || answer.status === 404) return 'unseen';
      if (answer.status !== 200) throw failureOf(answer.status);
      if (!answer.json.ok || namedRef(answer.json.value) !== ref) throw new SupabaseError('bad_answer');
      return 'seen';
    },
  };
}
