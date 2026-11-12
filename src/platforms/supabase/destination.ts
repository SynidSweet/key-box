// KBOX-37, KBOX-16: edge-function secrets, `POST|GET|DELETE /v1/projects/{ref}/secrets` (VERIFIED). The `GET` schema has a required `value`,
// so the destination is `readableBy: 'api'` (ordinary keys only) until a probe shows it holds a digest. A secret is stored the same way for every
// class: the platform has no write-only kind.
import type { Destination, DestinationTarget, PushOutcome } from '../../ports/destination.ts';
import { failureOf, SupabaseError } from './errors.ts';
import type { Management } from './management.ts';
import { PROJECT_REF, SECRET_NAME } from './shape.ts';

const KIND = 'supabase-secret';

function checked(t: DestinationTarget, name: string): string {
  if (t.kind !== KIND || !PROJECT_REF.test(t.id)) throw new SupabaseError('bad_project');
  if (!SECRET_NAME.test(name)) throw new SupabaseError('bad_secret_name');
  return t.id;
}

/**
 * The receipt of a write names the secret alone, `<ref>/<name>`: a project holds one secret per name, so it finds the object again, and it holds
 * nothing of the value, not even a digest of it (KBOX-2).
 */
const receipt = (ref: string, name: string): string => `${ref}/${name}`;

/** A statement that the platform applied nothing: its own refusal of the request (auth, validation), never a timeout or a server fault. */
const REFUSED = new Set([400, 401, 403, 404, 422]);

export function createDestination(call: Management): Destination {
  return {
    kind: KIND,
    // UNVERIFIED (supabase.edge-secrets-get-value): the GET schema has a required `value`, so the platform is assumed to hand the value back.
    properties: () => ({ readableBy: 'api', needsRedeploy: false }),
    async push(t, name, v, _klass, master): Promise<PushOutcome> {
      const ref = checked(t, name);
      return v.use(async (bytes) => {
        const value = Buffer.from(bytes).toString('utf8');
        try {
          const answer = await call(master, { method: 'POST', path: `/v1/projects/${ref}/secrets`, body: [{ name, value }] });
          if (answer.status === 200 || answer.status === 201) return { outcome: 'applied', version: receipt(ref, name) };
          return REFUSED.has(answer.status) ? { outcome: 'refused' } : { outcome: 'unknown' };
        } catch (error) {
          // A push that could not be answered may have been applied: that is `unknown`, never `refused`.
          if (error instanceof SupabaseError && error.code === 'unreachable') return { outcome: 'unknown' };
          throw error;
        }
      });
    },
    async remove(t, name, master): Promise<void> {
      const ref = checked(t, name);
      const answer = await call(master, { method: 'DELETE', path: `/v1/projects/${ref}/secrets`, body: [name] });
      if (answer.status === 404) return;
      if (answer.status !== 200 && answer.status !== 204) throw failureOf(answer.status);
    },
  };
}
