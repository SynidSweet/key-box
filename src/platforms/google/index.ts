// KBOX-41 (identity half), KBOX-24: the `google` registry entry. This unit registers the box's own identity toward Google Cloud: the OIDC
// documents core serves, the grant check, and the box's signing key as the platform's one key class and shape. The API-key issuer, its
// lister and verifier, the Secret Manager destination and the relay profile are added by the next Google unit (google-b, KBOX-59), which then
// takes the class and shape from its issuer.
import type { PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import { createGrantCheck, RESOURCE_MANAGER_HOST } from './grant-check.ts';
import { createMinter, IAM_CREDENTIALS_HOST, STS_HOST } from './minter.ts';
import { discoveryDocument, jwksDocument } from './oidc.ts';
import { SIGNING_KEY_SHAPE } from './signing-key.ts';

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
  };
}
