// KBOX-41, KBOX-24, KBOX-55, KBOX-59: the `google` registry entry. It registers the box's own identity toward Google Cloud (the OIDC documents core
// serves, the grant check, and the box's signing key, which the box makes itself: `boxKey`, with its own class and shape through `kitFor`) and the
// API-key adapter: the issuer, its lister and verifier, the Secret Manager destination and the relay profile. The adapters are built with
// `{http, minter}` only, never RegistryDeps, so none can read a stored key's record; each mints the admin token of its call's stored project.
import type { BoxIdentity, BoxMadeKey, PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import type { MintedSink } from '../../ports/minted.ts';
import type { Lent } from '../../ports/types.ts';
import { GoogleError } from './errors.ts';
import type { GoogleErrorCode } from './errors.ts';
import { APIKEYS_HOST } from './admin.ts';
import { createGrantCheck, RESOURCE_MANAGER_HOST } from './grant-check.ts';
import { createIssuer } from './issuer.ts';
import { createLister } from './lister.ts';
import { createMinter, IAM_CREDENTIALS_HOST, STS_HOST } from './minter.ts';
import type { Minter } from './minter.ts';
import { JWKS_PUBLISH_LEAD_MS, discoveryDocument, jwksDocument } from './oidc.ts';
import { googleRelayProfile } from './relay.ts';
import { SECRET_MANAGER_HOST, createSecretDestination } from './secret-destination.ts';
import { GOOGLE_ID } from './scope.ts';
import { SIGNING_KEYREF, SIGNING_KEY_NAME, SIGNING_KEY_SHAPE, checkSigningKey, generateSigningKey } from './signing-key.ts';
import { createVerifier } from './verifier.ts';

/** The ids docs/probes/google.md still marks STILL UNVERIFIED (KBOX-42). */
const UNVERIFIED = [
  'google.generateaccesstoken-scope',
  'google.apikeys-patch-restrictions',
  'google.jwks-cache-duration',
  'google.gocspx-length',
  'google.aiza-length',
  'google.must-deny-discovery',
  'google.apikeys-admin-scope',
  'google.apikeys-create-answer',
  'google.apikey-verify-call',
] as const;

/**
 * KBOX-55: whether Google has taken a new signing key: one STS exchange signed with it. The federated token it buys is held by the scanner
 * until it expires and used for nothing. A 4xx is Google refusing the assertion (`rejected`: its JWKS copy lacks the key); a 5xx, no answer
 * or an answer without a token is `unreachable`. Anything else (an audience of the wrong form, a value that is no key) is thrown.
 */
async function proveAtSts(minter: Minter, pending: Lent, identity: BoxIdentity, minted: MintedSink): Promise<'ok' | 'rejected' | 'unreachable'> {
  try {
    const federated = await minter.federate(identity, pending);
    await federated.token.use((bytes) => {
      minted.add(SIGNING_KEYREF, bytes, federated.expiresAt);
      return Promise.resolve();
    });
    return 'ok';
  } catch (error) {
    const answer = error instanceof GoogleError ? PROOF_ANSWER[error.code] : undefined;
    if (answer === undefined) throw error;
    return answer;
  }
}

/** The exchange's failures that are an answer about the new key; every other failure is thrown. */
const PROOF_ANSWER: Partial<Readonly<Record<GoogleErrorCode, 'rejected' | 'unreachable'>>> = {
  sts_refused: 'rejected',
  sts_failed: 'unreachable',
  unreachable: 'unreachable',
  bad_answer: 'unreachable',
};

/** KBOX-55: the box's signing key, `google/p/OIDC_SIGNING_KEY`, proven at STS by `minter` before a rotation switches to it. */
const signingKey = (minter: Minter): BoxMadeKey => ({
  name: SIGNING_KEY_NAME,
  shape: SIGNING_KEY_SHAPE,
  publishLeadMs: JWKS_PUBLISH_LEAD_MS,
  generate: generateSigningKey,
  check: checkSigningKey,
  prove: (pending, identity, minted) => proveAtSts(minter, pending, identity, minted),
});

/** What the registry hands every adapter (`RegistryDeps`), and the optional pause. */
export interface GoogleDeps extends RegistryDeps {
  /** Waits `ms` between two reads of an Operation; the real timer when absent. */
  readonly pause?: (ms: number) => Promise<void>;
}

const realPause = (ms: number): Promise<void> => new Promise((resolve) => void setTimeout(resolve, ms));

export function createGoogleEntry(deps: GoogleDeps): PlatformEntry {
  // The minter takes the deps whole: the stored-record reader is read there and nowhere else (the arch check `key info reads`).
  const minter = createMinter(deps);
  const admin = { http: deps.http, minter };
  return {
    id: 'google',
    hosts: [STS_HOST, IAM_CREDENTIALS_HOST, RESOURCE_MANAGER_HOST, APIKEYS_HOST, SECRET_MANAGER_HOST],
    unverified: UNVERIFIED,
    // KBOX-59: the API-key issuer states the class and shape of every key it makes; the signing key's own are the box key's (`kitFor`, KBOX-55).
    issuer: createIssuer({ ...admin, clock: deps.clock, pause: deps.pause ?? realPause }),
    lister: createLister(admin),
    verifier: createVerifier(admin),
    destinations: [{ destination: createSecretDestination(admin) }],
    relay: googleRelayProfile,
    // KBOX-57: the project of an API key is its one stored location, required of an ordinary key; it names no host.
    location: { project: { pattern: GOOGLE_ID, requiredFor: ['ordinary'] } },
    identity: { discovery: discoveryDocument, jwks: jwksDocument },
    grantCheck: createGrantCheck({ http: deps.http, minter }),
    boxKey: signingKey(minter),
  };
}
