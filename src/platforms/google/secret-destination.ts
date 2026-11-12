// KBOX-59, KBOX-16: Secret Manager as a destination: `POST https://secretmanager.googleapis.com/v1/projects/<project>/secrets/<secret>:addVersion`
// with `{payload: {data: <base64>}}` (path and method VERIFIED, `google.secretmanager-addversion`; the body is documentation only). The target is
// `projects/<project>/secrets/<secret>`; the call is made with the admin token of that project, from the master the box chose. A secret's value can
// be read back by an API call, so the destination is `readableBy: 'api'`: an ordinary key only (KBOX-16); an admin or master key is refused here
// too, before any call. A receipt names the version Google answered (names and digits) and holds nothing of the value (KBOX-2).
import type { Destination, DestinationTarget, PushOutcome } from '../../ports/destination.ts';
import { recordOf, withAdmin } from './admin.ts';
import type { AdminDeps } from './admin.ts';
import { GoogleError } from './errors.ts';
import { GOOGLE_ID } from './scope.ts';

export const SECRET_MANAGER_HOST = 'secretmanager.googleapis.com';
const KIND = 'google-secret-manager';
const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
const VERSION_NAME = /^projects\/[0-9A-Za-z-]{1,64}\/secrets\/[A-Za-z0-9_-]{1,255}\/versions\/[0-9]{1,20}$/;
/** Statuses that say Google applied nothing: it understood the request and refused it. Anything else may have been applied. */
const REFUSED = new Set([400, 401, 403, 404]);

/** The project and secret of a target, or `bad_secret_target`: the whole target must be `projects/<project id>/secrets/<secret id>`. */
function targetOf(t: DestinationTarget): { readonly project: string; readonly secret: string } {
  const [projects, project, secrets, secret, extra] = t.id.split('/');
  if (t.kind !== KIND || projects !== 'projects' || secrets !== 'secrets' || extra !== undefined || project === undefined || secret === undefined || !GOOGLE_ID.test(project) || !SECRET_ID.test(secret)) {
    throw new GoogleError('bad_secret_target');
  }
  return { project, secret };
}

export function createSecretDestination(deps: AdminDeps): Destination {
  return {
    kind: KIND,
    properties: () => ({ readableBy: 'api', needsRedeploy: false }),
    async push(t, _name, v, klass, master): Promise<PushOutcome> {
      const { project, secret } = targetOf(t);
      if (klass !== 'ordinary') return { outcome: 'refused' };
      return withAdmin(deps, master, project, (admin) =>
        v.use(async (bytes): Promise<PushOutcome> => {
          try {
            const answer = await admin.call({ method: 'POST', url: `https://${SECRET_MANAGER_HOST}/v1/projects/${project}/secrets/${secret}:addVersion`, body: { payload: { data: Buffer.from(bytes).toString('base64') } } });
            if (answer.status === 200) {
              const version = recordOf(answer.json)?.['name'];
              // An answer that names no version of the secret says nothing: the value may be there.
              return typeof version === 'string' && VERSION_NAME.test(version) ? { outcome: 'applied', version } : { outcome: 'unknown' };
            }
            return REFUSED.has(answer.status) ? { outcome: 'refused' } : { outcome: 'unknown' };
          } catch (error) {
            // A push that could not be answered may have been applied: `unknown`, never `refused`.
            if (error instanceof GoogleError && error.code === 'unreachable') return { outcome: 'unknown' };
            throw error;
          }
        }),
      );
    },
    remove(): Promise<void> {
      // `addVersion` answers a version, and `remove` is told only the target and the key's name: it cannot tell the value the box added from
      // another version of the secret, and deleting the secret would delete the owner's. So it fails closed: a rollback that needs it waits.
      return Promise.reject(new GoogleError('remove_unsupported'));
    },
  };
}
