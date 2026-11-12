// KBOX-24: the service-account grant check. It applies only to a key that makes the box act as a service account (an `sa:` item in its stored
// scope, KBOX-41); a Google API key is never checked. For such a key, core impersonates its stored target (a read-only token, used inside
// core) and asks Cloud Resource Manager `testIamPermissions` on the target's project which of the nine permissions it holds (probe
// `google.testiampermissions-path`, VERIFIED path). One held refuses, naming it; none passes; anything else refuses (fail closed).
import type { AdapterHttp } from '../../ports/http.ts';
import type { GrantCheck, GrantVerdict } from '../../ports/platform.ts';
import { decodeJsonBody } from '../../pure/schemas.ts';
import { GoogleError } from './errors.ts';
import type { GoogleErrorCode } from './errors.ts';
import { send } from './minter.ts';
import type { Minter, MintedToken } from './minter.ts';
import { actsAs } from './scope.ts';

export const RESOURCE_MANAGER_HOST = 'cloudresourcemanager.googleapis.com';

/** KBOX-24's nine: a service account holding any of them could mint keys or tokens, or widen its own access. */
export const RISK_PERMISSIONS = [
  'iam.serviceAccountKeys.create',
  'iam.serviceAccounts.getAccessToken',
  'iam.serviceAccounts.signBlob',
  'iam.serviceAccounts.signJwt',
  'iam.serviceAccounts.actAs',
  'iam.serviceAccounts.implicitDelegation',
  'resourcemanager.projects.setIamPolicy',
  'storage.hmacKeys.create',
  'secretmanager.versions.access',
] as const;

type RiskPermission = (typeof RISK_PERMISSIONS)[number];

const isRisk = (p: unknown): p is RiskPermission => typeof p === 'string' && (RISK_PERMISSIONS as readonly string[]).includes(p);

/** The refusal code naming a permission: `holds_iam_serviceaccountkeys_create`. */
const holds = (permission: RiskPermission): string => `holds_${permission.toLowerCase().replaceAll('.', '_')}`;

const refused = (code: string): GrantVerdict => ({ verdict: 'refused', code });

/** The refusal a minter or check failure is: the target's own codes as they are, the rest by what went wrong. */
function refusalOf(code: GoogleErrorCode): string {
  switch (code) {
    case 'target_count':
    case 'target_malformed':
    case 'target_reserved':
      return code;
    case 'identity_unconfigured':
      return 'grant_check_no_identity';
    case 'no_key_info':
      return 'grant_check_no_key_info';
    case 'unreachable':
      return 'grant_check_unreachable';
    case 'claims_fixed':
    case 'identity_malformed':
    case 'signing_key_unreadable':
    case 'bad_location':
    case 'bad_scope':
    case 'bad_key_id':
    case 'bad_secret_target':
    case 'location_unconfirmed':
    case 'apikeys_refused':
    case 'apikeys_failed':
    case 'remove_unsupported':
    case 'cloud_platform_for_relay':
    case 'scope_not_in_profile':
    case 'scope_malformed':
    case 'sts_refused':
    case 'sts_failed':
    case 'impersonation_refused':
    case 'impersonation_failed':
    case 'permissions_failed':
    case 'bad_answer':
      return 'grant_check_failed';
  }
}

/** The risk permissions the token's service account holds on its own project; a failure or an answer naming anything not asked is an error. */
async function heldBy(http: AdapterHttp, minted: MintedToken): Promise<readonly RiskPermission[]> {
  const body = Buffer.from(JSON.stringify({ permissions: RISK_PERMISSIONS }), 'utf8');
  const response = await minted.token.use((bytes) =>
    send(http, {
      method: 'POST',
      url: `https://${RESOURCE_MANAGER_HOST}/v1/projects/${minted.target.project}:testIamPermissions`,
      headers: { authorization: `Bearer ${Buffer.from(bytes).toString('utf8')}`, 'content-type': 'application/json' },
      body,
    }),
  );
  if (response.status !== 200) throw new GoogleError('permissions_failed', response.status);
  const parsed = decodeJsonBody(response.body);
  if (!parsed.ok || typeof parsed.value !== 'object' || parsed.value === null || Array.isArray(parsed.value)) throw new GoogleError('bad_answer');
  // A project where none is held answers `{}`: the member is absent, not an empty list.
  const permissions = (parsed.value as Record<string, unknown>)['permissions'] ?? [];
  if (!Array.isArray(permissions) || !permissions.every(isRisk)) throw new GoogleError('bad_answer');
  return permissions;
}

export function createGrantCheck(deps: { readonly http: AdapterHttp; readonly minter: Minter }): GrantCheck {
  return {
    appliesTo: actsAs,
    async check(subject, master) {
      try {
        // The minter reads the key's target from its stored record by keyref; the project tested is that target's.
        const minted = await deps.minter.mint({ use: 'grant-check', keyref: subject.keyref }, master);
        const held = await heldBy(deps.http, minted);
        const first = RISK_PERMISSIONS.find((p) => held.includes(p));
        return first === undefined ? { verdict: 'pass' } : refused(holds(first));
      } catch (error) {
        if (error instanceof GoogleError) return refused(refusalOf(error.code));
        throw error;
      }
    },
  };
}
