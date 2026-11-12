// Two test profiles, one per platform shape the spec lists (KBOX-13, KBOX-25): `pathplat` takes its origin from the profile
// (as OpenAI and Supabase do) and `hostplat` takes the host as the first path segment (as Google does). The platform units
// supply the real profiles; these exist so the deny-by-name tests run against real shapes. Every endpoint in `mustDeny`
// mints a credential, a token or a login.
import type { PlatformEntry } from '../../src/ports/platform.ts';
import type { DenyRule, RelayProfile } from '../../src/ports/relay-profile.ts';
import type { KeyShape, Lent } from '../../src/ports/types.ts';

const bearer = async (h: Headers, v: Lent): Promise<void> => {
  const value = await v.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
  h.set('authorization', `Bearer ${value}`);
};

export const PATH_HOST = 'api.pathplat.example';

/** The one key shape the shapeless test entries state (an entry with no issuer must carry its own, KBOX-40). */
export const NO_ISSUER_SHAPE: KeyShape = { prefix: null, alphabet: 'hex', coreLength: { min: 8, max: 8 }, random: true };

/** Sample variants of one upstream request: the canonicalisation table of KBOX-13 applied to it. */
export function variants(method: string, host: string, path: string): DenyRule['samples'] {
  const parts = path.split('/');
  const second = parts[2] ?? '';
  const escaped = `%${second.charCodeAt(0).toString(16).toUpperCase()}${second.slice(1)}`;
  const withEscape = [...parts.slice(0, 2), escaped, ...parts.slice(3)].join('/');
  return [
    { method, url: `https://${host}${path}` },
    { method, url: `https://${host}${withEscape}` },
    { method, url: `https://${host}${path}/` },
    { method, url: `https://${host}${path.replace('/', '//')}` },
    { method, url: `https://${host}${path.replace(/\/([^/]+)$/, '/x/../$1')}` },
    { method, url: `https://${host}${path.replace(/\/([^/]+)$/, '/%2e%2e/$1')}` },
    { method, url: `https://${host}${path.replace(/\/([^/]+)$/, '%2F$1')}` },
    { method, url: `https://${host}${path};x` },
    { method, url: `https://${host}${path}?_method=${method}` },
    { method: 'GET', url: `https://${host}${path}?%24method=${method}` },
  ];
}

export const pathProfile: RelayProfile = {
  platform: 'pathplat',
  origin: { kind: 'fixed', host: PATH_HOST },
  callerTokenHeaders: ['authorization', 'apikey'],
  inject: bearer,
  allow: [
    { id: 'models-list', method: 'GET', host: PATH_HOST, pathTemplate: '/v1/models', query: {} },
    { id: 'model-get', method: 'GET', host: PATH_HOST, pathTemplate: '/v1/models/{id:[A-Za-z0-9_.-]{1,128}}', query: {} },
    {
      id: 'items-list',
      method: 'GET',
      host: PATH_HOST,
      pathTemplate: '/v1/items',
      query: { limit: { kind: 'int', min: 1, max: 100 }, order: { kind: 'word', words: ['asc', 'desc'] } },
    },
    { id: 'item-create', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/items', query: {} },
    { id: 'files-tail', method: 'GET', host: PATH_HOST, pathTemplate: '/v1/files/{rest:**}', query: {} },
    { id: 'events-stream', method: 'GET', host: PATH_HOST, pathTemplate: '/v1/events', query: {} },
  ],
  tailRules: ['files-tail'],
  mustDeny: [
    { id: 'admin-key-create', samples: variants('POST', PATH_HOST, '/v1/organization/admin_api_keys') },
    { id: 'project-key-create', samples: variants('POST', PATH_HOST, '/v1/organization/projects/proj01/api_keys') },
    { id: 'service-account-create', samples: variants('POST', PATH_HOST, '/v1/organization/projects/proj01/service_accounts') },
    { id: 'login-token', samples: variants('POST', PATH_HOST, '/v1/auth/token') },
  ],
  requestHeaders: ['openai-beta', 'idempotency-key', 'prefer', 'accept-profile', 'content-profile'],
  headerWords: { 'accept-profile': ['public'], 'content-profile': ['public'] },
  responseHeaders: ['x-request-id', 'x-ratelimit-remaining'],
  envForClients: (relayUrl: string): Record<string, string> => ({ PATHPLAT_BASE_URL: `${relayUrl}/v1`, PATHPLAT_API_KEY: '<pass>' }),
};

export const IAM_HOST = 'iam.hostplat.example';
export const STORAGE_HOST = 'storage.hostplat.example';

export const hostProfile: RelayProfile = {
  platform: 'hostplat',
  origin: { kind: 'host-in-path', hosts: [IAM_HOST, STORAGE_HOST] },
  callerTokenHeaders: ['authorization'],
  inject: bearer,
  allow: [
    { id: 'accounts-list', method: 'GET', host: IAM_HOST, pathTemplate: '/v1/projects/{project:[a-z0-9-]{6,30}}/serviceAccounts', query: {} },
    { id: 'objects-list', method: 'GET', host: STORAGE_HOST, pathTemplate: '/storage/v1/b/{bucket:[a-z0-9._-]{3,63}}/o', query: { alt: { kind: 'word', words: ['json'] } } },
  ],
  tailRules: [],
  mustDeny: [
    { id: 'account-key-create', samples: variants('POST', IAM_HOST, '/v1/projects/proj-01/serviceAccounts/sa1/keys') },
    { id: 'access-token', samples: variants('POST', IAM_HOST, '/v1/projects/-/serviceAccounts/sa1:generateAccessToken') },
    { id: 'id-token', samples: variants('POST', IAM_HOST, '/v1/projects/-/serviceAccounts/sa1:generateIdToken') },
    { id: 'hmac-key-create', samples: variants('POST', STORAGE_HOST, '/storage/v1/projects/proj-01/hmacKeys') },
  ],
  requestHeaders: [],
  headerWords: {},
  responseHeaders: ['x-guploader-uploadid'],
  envForClients: (relayUrl: string): Record<string, string> => ({ KBOX_GOOGLE_RELAY_URL: relayUrl }),
};

/** A profile whose allow set lets one of its own `mustDeny` samples through: the positive control of the deny harness. */
export const leakyProfile: RelayProfile = {
  ...pathProfile,
  platform: 'leaky',
  allow: [...pathProfile.allow, { id: 'org-anything', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/organization/{rest:**}', query: {} }],
  tailRules: ['files-tail', 'org-anything'],
};

/** The registry the relay tests run: both test profiles and a platform with no relay profile. */
export const TEST_REGISTRY: readonly PlatformEntry[] = [
  { id: 'pathplat', relay: pathProfile, shape: NO_ISSUER_SHAPE, unverified: [] },
  { id: 'hostplat', relay: hostProfile, shape: NO_ISSUER_SHAPE, unverified: [] },
  { id: 'plain', shape: NO_ISSUER_SHAPE, unverified: [] },
];
