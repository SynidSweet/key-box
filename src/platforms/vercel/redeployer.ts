// KBOX-36: the Vercel redeployer. A redeploy starts from the project's newest ready production deployment (`POST /v13/deployments?forceNew=1`
// with its `deploymentId`), which takes the project's current environment variables. `ready` polls that deployment until it settles.
// `ready(ref)` has no master parameter, so the redeployer holds the master's Lent handle (never its bytes) from `redeploy` until `ready`
// returns: a handle re-lends from the vault each time it is used.
import type { DeployRef, DestinationTarget, Redeployer } from '../../ports/destination.ts';
import type { Clock } from '../../ports/clock.ts';
import type { Lent } from '../../ports/types.ts';
import { encodeJson, recordOf, segment, textOf } from './api.ts';
import type { VercelApi } from './api.ts';
import { VercelError, requireSuccess } from './errors.ts';

/** Time between two reads of a deploy that has not settled. */
export const REDEPLOY_POLL_MS = 5_000;
/** How long `ready` waits for a deploy to settle before it says `failed`: a build that long is not one the rotation waits on. */
export const REDEPLOY_DEADLINE_MS = 15 * 60_000;

const PENDING = new Set(['QUEUED', 'INITIALIZING', 'BUILDING']);
const FAILED = new Set(['ERROR', 'CANCELED', 'DELETED']);

export interface RedeployerDeps {
  readonly api: VercelApi;
  readonly clock: Clock;
  /** Waits `ms`; the shell's timer in production, the test's own in tests. */
  readonly pause: (ms: number) => Promise<void>;
}

interface Started {
  readonly master: Lent;
  readonly startedAt: number;
}

export function createVercelRedeployer(deps: RedeployerDeps): Redeployer {
  const { api, clock, pause } = deps;
  const started = new Map<DeployRef, Started>();

  async function newestReady(t: DestinationTarget, master: Lent): Promise<{ readonly id: string; readonly name: string }> {
    // UNVERIFIED (vercel.redeploy): the list query and its `uid`/`name` fields come from the OpenAPI document, not from a live call.
    const query = `projectId=${encodeURIComponent(t.id)}&target=production&state=READY&limit=1`;
    const listed = await api.call({ method: 'GET', path: '/v6/deployments', query }, master);
    requireSuccess(listed.status);
    const rows = recordOf(listed.json)?.['deployments'];
    if (!Array.isArray(rows)) throw new VercelError('malformed');
    const first = recordOf(rows[0]);
    const id = textOf(first?.['uid']);
    const name = textOf(first?.['name']);
    if (rows.length === 0) throw new VercelError('no_deployment');
    if (id === undefined || name === undefined) throw new VercelError('malformed');
    return { id, name };
  }

  return {
    async redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef> {
      const from = await newestReady(t, master);
      // UNVERIFIED (vercel.redeploy): that `deploymentId` with `name` and `target` is enough, and that the new deploy takes the new env values.
      const body = encodeJson({ name: from.name, deploymentId: from.id, target: 'production' });
      const answer = await api.call({ method: 'POST', path: '/v13/deployments', query: 'forceNew=1', body }, master);
      requireSuccess(answer.status);
      const ref = textOf(recordOf(answer.json)?.['id']);
      if (ref === undefined) throw new VercelError('malformed');
      started.set(ref, { master, startedAt: clock.now() });
      return ref;
    },
    async ready(ref: DeployRef): Promise<'ready' | 'failed'> {
      const run = started.get(ref);
      if (run === undefined) throw new VercelError('unknown_deploy');
      try {
        for (;;) {
          const answer = await api.call({ method: 'GET', path: `/v13/deployments/${segment(ref)}` }, run.master);
          if (answer.status === 404) return 'failed';
          requireSuccess(answer.status);
          const state = textOf(recordOf(answer.json)?.['readyState']);
          if (state === 'READY') return 'ready';
          if (state === undefined || !(PENDING.has(state) || FAILED.has(state))) throw new VercelError('malformed');
          if (FAILED.has(state) || clock.now() - run.startedAt >= REDEPLOY_DEADLINE_MS) return 'failed';
          await pause(REDEPLOY_POLL_MS);
        }
      } finally {
        started.delete(ref);
      }
    },
  };
}
