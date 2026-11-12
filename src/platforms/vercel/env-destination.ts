// KBOX-36, KBOX-16: the `vercel-env` destination. A value is always written as a SENSITIVE variable (production and preview, the only targets
// Vercel allows for it): write-only once created, so no API read can return it and `readableBy` is `runtime` for every class of key. The
// `encrypted` type, which the API reads back, is never sent. (The spec's `encrypted` for an ordinary key needs the key's class at push time,
// which the port does not carry; see the unit report.) One variable per name: the push is an upsert.
import { createHash } from 'node:crypto';
import type { Destination, DestinationTarget, PushOutcome } from '../../ports/destination.ts';
import type { Lent } from '../../ports/types.ts';
import { encodeJson, recordOf, segment, textOf } from './api.ts';
import type { ApiAnswer, VercelApi } from './api.ts';
import { VercelError, isSuccess, requireSuccess } from './errors.ts';

const TARGETS = ['production', 'preview'] as const;

/** Statuses that say the platform applied nothing: the push was understood and refused. Anything else may have been applied. */
const REFUSED = new Set([400, 401, 403, 404, 409, 422]);

/** The receipt of a push: the variable's id and a digest of the value, so a different value is a different receipt and the value is not in it. */
const receipt = (id: string, value: Uint8Array): string => `${id}:${createHash('sha256').update(value).digest('hex').slice(0, 16)}`;

function outcomeOf(answer: ApiAnswer, value: Uint8Array): PushOutcome {
  if (isSuccess(answer.status)) {
    // UNVERIFIED (vercel.env-upsert): that `upsert=true` answers 200 with `created.id` for an existing key, with no duplicate. An answer
    // that names no variable is unknown: the variable may exist.
    const id = textOf(recordOf(recordOf(answer.json)?.['created'])?.['id']);
    return id === undefined ? { outcome: 'unknown' } : { outcome: 'applied', version: receipt(id, value) };
  }
  return REFUSED.has(answer.status) ? { outcome: 'refused' } : { outcome: 'unknown' };
}

const projectPath = (t: DestinationTarget): string => `/v10/projects/${segment(t.id)}/env`;

export function createVercelEnvDestination(api: VercelApi): Destination {
  return {
    kind: 'vercel-env',
    properties: () => ({ readableBy: 'runtime', needsRedeploy: true }),
    push: (t, name, v, master) =>
      v.use(async (valueBytes) => {
        const body = encodeJson({ key: name, value: Buffer.from(valueBytes).toString('utf8'), type: 'sensitive', target: TARGETS });
        try {
          return outcomeOf(await api.call({ method: 'POST', path: projectPath(t), query: 'upsert=true', body }, master), valueBytes);
        } catch (error) {
          if (!(error instanceof VercelError)) throw error;
          return { outcome: 'unknown' };
        }
      }),
    async remove(t: DestinationTarget, name: string, master: Lent): Promise<void> {
      const listed = await api.call({ method: 'GET', path: projectPath(t) }, master);
      if (listed.status === 404) return;
      requireSuccess(listed.status);
      const rows = recordOf(listed.json)?.['envs'];
      if (!Array.isArray(rows)) throw new VercelError('malformed');
      const ids = rows.flatMap((row: unknown) => {
        const record = recordOf(row);
        const id = textOf(record?.['id']);
        return id !== undefined && record?.['key'] === name ? [id] : [];
      });
      for (const id of ids) {
        // UNVERIFIED (vercel.env-delete): `DELETE /v9/projects/{p}/env/{id}` answers 200 for a sensitive variable. A 404 here is a variable
        // that went away between the list and the delete: done.
        const gone = await api.call({ method: 'DELETE', path: `/v9/projects/${segment(t.id)}/env/${segment(id)}` }, master);
        if (gone.status !== 404) requireSuccess(gone.status);
      }
    },
  };
}
