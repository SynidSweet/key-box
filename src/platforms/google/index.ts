// KBOX-41 (identity half), KBOX-24, KBOX-55: the `google` registry entry. This unit registers the box's own identity toward Google Cloud: the
// OIDC documents core serves, the grant check, and the box's signing key, which the box makes itself (`boxKey`), as the platform's one key class
// and shape. The API-key issuer, its lister and verifier, the Secret Manager destination and the relay profile are added by the next Google unit
// (google-b, KBOX-59), which then takes the class and shape from its issuer.
import type { BoxIdentity, BoxMadeKey, PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import type { MintedSink } from '../../ports/minted.ts';
import type { Lent } from '../../ports/types.ts';
import { GoogleError } from './errors.ts';
import type { GoogleErrorCode } from './errors.ts';
import { createGrantCheck, RESOURCE_MANAGER_HOST } from './grant-check.ts';
import { createMinter, IAM_CREDENTIALS_HOST, STS_HOST } from './minter.ts';
import type { Minter } from './minter.ts';
import { JWKS_PUBLISH_LEAD_MS, discoveryDocument, jwksDocument } from './oidc.ts';
import { SIGNING_KEYREF, SIGNING_KEY_NAME, SIGNING_KEY_SHAPE, checkSigningKey, generateSigningKey } from './signing-key.ts';

/** The ids docs/probes/google.md still marks STILL UNVERIFIED (KBOX-42). */
const UNVERIFIED = [
  'google.generateaccesstoken-scope',
  'google.apikeys-patch-restrictions',
  'google.jwks-cache-duration',
  'google.gocspx-length',
  'google.aiza-length',
  'google.must-deny-discovery',
  'google.apikeys-admin-scope',
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

export function createGoogleEntry(deps: RegistryDeps): PlatformEntry {
  // The minter takes the deps whole: the stored-record reader is read there and nowhere else (the arch check `key info reads`).
  const minter = createMinter(deps);
  return {
    id: 'google',
    hosts: [STS_HOST, IAM_CREDENTIALS_HOST, RESOURCE_MANAGER_HOST],
    unverified: UNVERIFIED,
    // The only key this unit knows is the box's signing key, so every Google key is master class (never lent to the relay, KBOX-3).
    shape: SIGNING_KEY_SHAPE,
    classify: () => 'master',
    identity: { discovery: discoveryDocument, jwks: jwksDocument },
    grantCheck: createGrantCheck({ http: deps.http, minter }),
    boxKey: signingKey(minter),
  };
}
