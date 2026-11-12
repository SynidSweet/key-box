// KBOX-59, KBOX-58: the Google API-key verifier. It needs the master (its calls are made with the admin token of the key's stored project), and it
// applies only to a key with a stored project and no `sa:` item. A value that is not of the API-key shape is never sent. Rows, in order:
//   1 no master was handed: unreachable (a rule of the box)              6 the lookup names nothing: unreachable (UNVERIFIED)
//   2 the stored project is no project id: unreachable (box rule)         7 the name is not the stored project's: unreachable (UNVERIFIED)
//   3 the value is not of the shape, never sent: unreachable (box rule)   8 the key read is there, not deleted: ok (UNVERIFIED)
//   4 the admin token cannot be minted: unreachable (box rule)            9 the key read has a deleteTime: unreachable (UNVERIFIED)
//   5 the lookup fails or is no object: unreachable (UNVERIFIED)         10 the key read answers anything else: unreachable (UNVERIFIED)
// Every UNVERIFIED row is probe `google.apikey-verify-call`. THIS VERIFIER NEVER ANSWERS `rejected`: until that probe shows what Google answers
// for a key that is dead, no answer is proof of death (KBOX-58), so step 10 of a rotation stays in grace and retries. The value is only in the
// lookup's query: no URL, query or value enters an error (adapter-http drops URLs from a transport failure).
import type { Verifier } from '../../ports/issuer.ts';
import type { Lent } from '../../ports/types.ts';
import { matchesShape } from '../../pure/class.ts';
import { APIKEYS_ORIGIN, recordOf, withAdmin } from './admin.ts';
import type { Admin, AdminDeps } from './admin.ts';
import { GoogleError } from './errors.ts';
import { storedIdOf } from './key-name.ts';
import { API_KEY_SHAPE, GOOGLE_ID, actsAs, itemsOf } from './scope.ts';

type Verdict = 'ok' | 'unreachable';

/** The shape guard, inside `use(...)`: the value is read there and never copied out. */
const shaped = (value: Lent): Promise<boolean> => value.use((bytes) => Promise.resolve(matchesShape(API_KEY_SHAPE, Buffer.from(bytes).toString('utf8'))));

/** Rows 5 to 10, once the admin token is there: the lookup, then the key it names, read at the stored project. */
async function lookedUp(admin: Admin, value: Lent, stored: string): Promise<Verdict> {
  const lookup = await value.use((bytes) => admin.call({ method: 'GET', url: `${APIKEYS_ORIGIN}/keys:lookupKey?keyString=${encodeURIComponent(Buffer.from(bytes).toString('utf8'))}` }));
  const found = lookup.status === 200 ? recordOf(lookup.json) : undefined;
  if (found === undefined) return 'unreachable';
  const id = await storedIdOf(found['name'], stored, admin.numberOf);
  if (id === undefined) return 'unreachable';
  const read = await admin.call({ method: 'GET', url: `${APIKEYS_ORIGIN}/${id}` });
  const key = read.status === 200 ? recordOf(read.json) : undefined;
  if (key === undefined) return 'unreachable';
  const deleteTime = key['deleteTime'];
  return deleteTime === undefined || deleteTime === '' ? 'ok' : 'unreachable';
}

export function createVerifier(deps: AdminDeps): Verifier {
  return {
    needsMaster: true,
    appliesTo: (scope, at) => at.project !== undefined && !actsAs(itemsOf(scope)),
    async verify(value, target) {
      const { master } = target;
      const stored = target.at.project;
      if (master === undefined || stored === undefined || !GOOGLE_ID.test(stored) || !(await shaped(value))) return 'unreachable';
      try {
        return await withAdmin(deps, master, stored, (admin) => lookedUp(admin, value, stored));
      } catch (error) {
        // A mint that failed, no answer, an answer of no use: no verdict but `unreachable`. Anything else is not ours to name and goes on.
        if (error instanceof GoogleError) return 'unreachable';
        throw error;
      }
    },
  };
}
