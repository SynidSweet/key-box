// KBOX-59: the Google API-key issuer. `POST .../v2/projects/<project>/locations/global/keys` answers an Operation, polled until it is done; the
// key's value is only at `GET .../<id>/keyString` (all of this UNVERIFIED, `google.apikeys-create-answer`). The project of every call is the
// stored project of the request (`at`, KBOX-57): the id is composed from it and the key id the answer gives (`key-name.ts`), and an answer that
// names any other place is never used to name a call: nothing is deleted by an id built from it, and the key Google made there is left. Every call
// is made with the admin token of the stored project (KBOX-41), from the master the box chose. No error here carries Google's text or a value.
import type { Clock } from '../../ports/clock.ts';
import type { IssuedKey, IssueRequest, Issuer, IssuerCapabilities } from '../../ports/issuer.ts';
import type { Lent, PlatformKeyId } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { matchesShape } from '../../pure/class.ts';
import { APIKEYS_ORIGIN, failureOf, recordOf, withAdmin } from './admin.ts';
import type { Admin, AdminDeps } from './admin.ts';
import { GoogleError } from './errors.ts';
import { KEY_ID, composeId, parseAnsweredName, parseStoredId, storedIdOf } from './key-name.ts';
import { API_KEY_SHAPE, GOOGLE_ID, apiServicesOf } from './scope.ts';

/** Time between two reads of an Operation that is not done. */
export const OPERATION_POLL_MS = 2_000;
/** How long the issuer waits for an Operation before it gives up (`unreachable`; no key id is known, so nothing is deleted). */
export const OPERATION_WAIT_MS = 60_000;
/** The longest `displayName` sent: the intent name cut to it. UNVERIFIED (`google.apikeys-create-answer`): the documented limit is assumed to be 63. */
export const DISPLAY_NAME_MAX = 63;

const OPERATION_NAME = /^operations\/[A-Za-z0-9._~-]{1,256}$/;

const CAPABILITIES: IssuerCapabilities = {
  create: 'api',
  revoke: 'api',
  selfRotate: false,
  overlap: true,
  set: 'none',
  // The value is only in the create flow's `keyString` read; the lister is how the box finds a key it made again (KBOX-51).
  revealOnce: true,
  scopeSchema: { fields: ['items'] },
  shape: API_KEY_SHAPE,
  // A key made here is restricted to the services the owner approved: ordinary. The signing key's class is its own (`kitFor`).
  classify: () => 'ordinary',
};

export interface IssuerDeps extends AdminDeps {
  readonly clock: Clock;
  /** Waits `ms` between two reads of an Operation: the shell's timer in production, the test's own in tests. */
  readonly pause: (ms: number) => Promise<void>;
}

export function createIssuer(deps: IssuerDeps): Issuer {
  /** The finished Operation: done within `OPERATION_WAIT_MS` by the injected clock, else `unreachable`. */
  async function finished(admin: Admin, created: Record<string, unknown>): Promise<Record<string, unknown>> {
    const name = created['name'];
    if (typeof name !== 'string' || !OPERATION_NAME.test(name)) throw new GoogleError('bad_answer');
    const startedAt = deps.clock.now();
    let operation = created;
    for (let reads = 0; operation['done'] !== true; reads += 1) {
      // Read at once, then wait between reads until the deadline: an Operation not done by then leaves a key no one holds the id of.
      if (reads > 0) {
        if (deps.clock.now() - startedAt >= OPERATION_WAIT_MS) throw new GoogleError('unreachable');
        await deps.pause(OPERATION_POLL_MS);
      }
      const answer = await admin.call({ method: 'GET', url: `${APIKEYS_ORIGIN}/${name}` });
      if (answer.status !== 200) throw failureOf(answer.status);
      const body = recordOf(answer.json);
      if (body === undefined) throw new GoogleError('bad_answer');
      operation = body;
    }
    return operation;
  }

  /** The name of the key a finished Operation made: its `error` is Google's refusal, its `response.name` the key. */
  function keyNameOf(operation: Record<string, unknown>): unknown {
    if (operation['error'] !== undefined) throw new GoogleError('apikeys_refused');
    const response = operation['response'];
    return typeof response === 'object' && response !== null && !Array.isArray(response) ? (response as Record<string, unknown>)['name'] : undefined;
  }

  /** Ends a key the box made and cannot use. A DELETE that fails (`left`) is not the error: the next reconcile sweep finds the `kbox_` key. */
  async function end(admin: Admin, id: PlatformKeyId): Promise<'ended' | 'left'> {
    try {
      await admin.call({ method: 'DELETE', url: `${APIKEYS_ORIGIN}/${id}` });
      return 'ended';
    } catch (error) {
      if (error instanceof GoogleError) return 'left';
      throw error;
    }
  }

  /** The value of the key `id`, read once, when it is of the API-key shape; otherwise the key is ended and the answer is `bad_answer`. */
  async function valueOf(admin: Admin, id: PlatformKeyId): Promise<Lent> {
    const answer = await admin.call({ method: 'GET', url: `${APIKEYS_ORIGIN}/${id}/keyString` });
    const keyString = answer.status === 200 ? recordOf(answer.json)?.['keyString'] : undefined;
    if (typeof keyString !== 'string' || !matchesShape(API_KEY_SHAPE, keyString)) {
      await end(admin, id);
      throw new GoogleError('bad_answer');
    }
    const bytes = new TextEncoder().encode(keyString);
    return makeLent(id, () => Uint8Array.from(bytes));
  }

  async function issue(req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> {
    const project = req.at.project;
    if (project === undefined || !GOOGLE_ID.test(project)) throw new GoogleError('bad_location');
    const services = apiServicesOf(req.scope);
    return withAdmin(deps, master, project, async (admin) => {
      const body = { displayName: intentName.slice(0, DISPLAY_NAME_MAX), restrictions: { apiTargets: services.map((service) => ({ service })) } };
      const created = await admin.call({ method: 'POST', url: `${APIKEYS_ORIGIN}/projects/${project}/locations/global/keys`, body });
      if (created.status !== 200) throw failureOf(created.status);
      const operation = recordOf(created.json);
      if (operation === undefined) throw new GoogleError('bad_answer');
      const name = keyNameOf(await finished(admin, operation));
      const answered = parseAnsweredName(name);
      if (answered === undefined || !KEY_ID.test(answered.keyId)) throw new GoogleError('bad_answer');
      // An answer that names another place is believed of nothing: no call is made with an id built from it, and the key stays where Google made it.
      const id = await storedIdOf(name, project, admin.numberOf);
      if (id === undefined) throw new GoogleError('location_unconfirmed');
      return { value: await valueOf(admin, id), platformKeyId: id, location: { project } };
    });
  }

  async function revoke(id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> {
    const stored = parseStoredId(id);
    if (stored === undefined) throw new GoogleError('bad_key_id');
    return withAdmin(deps, master, stored.project, async (admin) => {
      const answer = await admin.call({ method: 'DELETE', url: `${APIKEYS_ORIGIN}/${composeId(stored.project, stored.keyId)}` });
      if (answer.status === 404) return 'absent';
      if (answer.status !== 200) throw failureOf(answer.status);
      return 'revoked';
    });
  }

  return { platform: 'google', capabilities: () => CAPABILITIES, issue, revoke };
}
