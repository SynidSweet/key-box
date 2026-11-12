// KBOX-36: the Vercel adapter. `create<Name>Entry` is what the registry line calls. Master = a classic team-scoped token pasted once
// (`selfRotate`). A key's project is its stored location (KBOX-57); under the KBOX-15 floor a project token classes master too and enters by
// paste until a rule lets a confirmed project lower it. No relay profile in v1: only the deny list.
import type { PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import { createVercelApi, VERCEL_HOST } from './api.ts';
import { VERCEL_MUST_DENY } from './deny.ts';
import { createVercelEnvDestination } from './env-destination.ts';
import { createVercelIssuer } from './issuer.ts';
import { createVercelLister } from './lister.ts';
import { createVercelRedeployer } from './redeployer.ts';
import { PLAIN_ID } from './scope.ts';
import { createVercelVerifier } from './verifier.ts';

/** What the registry hands every adapter (`RegistryDeps`), and the optional pause. */
export interface VercelDeps extends RegistryDeps {
  /** Waits `ms` between two reads of a deploy; the real timer when absent. */
  readonly pause?: (ms: number) => Promise<void>;
}

const realPause = (ms: number): Promise<void> => new Promise((resolve) => void setTimeout(resolve, ms));

/**
 * The probe ids `docs/probes/vercel.md` marks STILL UNVERIFIED, and where the code leans on each:
 * cli-project-token (issuer), env-upsert, env-delete and env-list-pagination (env-destination), redeploy (redeployer), verifier-project-token (verifier),
 * vcp-core-length (shape). `env-update` is not used: the push is an upsert. `team-settings` is relied on by the KBOX-26 unit, not here.
 */
const UNVERIFIED = ['vercel.cli-project-token', 'vercel.env-upsert', 'vercel.env-update', 'vercel.env-delete', 'vercel.env-list-pagination', 'vercel.redeploy', 'vercel.verifier-project-token', 'vercel.vcp-core-length', 'vercel.team-settings'] as const;

export function createVercelEntry(deps: VercelDeps): PlatformEntry {
  const api = createVercelApi(deps.http);
  return {
    id: 'vercel',
    issuer: createVercelIssuer(api),
    lister: createVercelLister(api),
    denyOnly: VERCEL_MUST_DENY,
    verifier: createVercelVerifier(api),
    keyPageUrl: 'https://vercel.com/account/tokens',
    destinations: [{ destination: createVercelEnvDestination(api), redeployer: createVercelRedeployer({ api, clock: deps.clock, pause: deps.pause ?? realPause }) }],
    // KBOX-57: the project a token belongs to is the key's one stored location, required of no class (a team-wide token names none).
    location: { project: { pattern: PLAIN_ID, requiredFor: [] } },
    hosts: [VERCEL_HOST],
    unverified: UNVERIFIED,
  };
}
