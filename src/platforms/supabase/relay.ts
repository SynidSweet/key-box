// KBOX-37, KBOX-13, KBOX-25: the `supabase` relay profile. The origin is the key's own project, `https://<ref>.supabase.co` (one host per
// key, the ref a project of the key). The gateway forwards by prefix, so the profile is default-deny on path segments: it allows PostgREST on
// tables, `rpc` calls, authenticated Storage downloads and Storage listings, and names what it must never let through.
//
// Narrower than the spec's list, on purpose (reported):
// - PATCH and DELETE on a table are not allowed: a row filter is a query key named after a column, and a rule lists exact keys, so such a
//   request would always be a change to every row. A key's own rules (`set_allow_rules`) cannot add them: they only narrow this list (KBOX-61).
// - Storage uploads and deletes name a bucket in the path; a generic `{bucket}` there would also match `object/sign/<bucket>` and
//   `object/upload/sign/<bucket>`, which are denied by name. Those need a rule that names its bucket, which is a profile change (an update), not a key's own rule (KBOX-61).
// - No `limit` or `offset` query key (KBOX-13: nothing whose job is to cut a response).
import type { AllowRule, DenyRule, RelayProfile, SampleRequest } from '../../ports/relay-profile.ts';
import type { Lent } from '../../ports/types.ts';
import { projectRuleHost } from '../../pure/project-host.ts';
import { REF_LENGTH } from './shape.ts';

export const DOMAIN = 'supabase.co';
const ORIGIN = { kind: 'project-host', domain: DOMAIN, refLength: REF_LENGTH } as const;
const HOST = projectRuleHost(ORIGIN);
/** The project every sample is about: the engine ignores which one (a sample stands for any project's host). */
const SAMPLE_HOST = `${'abcdefghijklmnopqrst'}.${DOMAIN}`;

const TABLE = '{table:[A-Za-z0-9_]{1,63}}';
const BUCKET = '{bucket:[A-Za-z0-9._-]{1,63}}';
const FUNCTION = '{fn:[A-Za-z0-9_]{1,63}}';

const rule = (id: string, method: string, pathTemplate: string, query: AllowRule['query'] = {}): AllowRule => ({ id, method, host: HOST, pathTemplate, query });

const ALLOW: readonly AllowRule[] = [
  // UNVERIFIED (supabase.relay-allow-postgrest-tables)
  rule('postgrest-select', 'GET', `/rest/v1/${TABLE}`, { select: { kind: 'word', words: ['*'] } }),
  rule('postgrest-insert', 'POST', `/rest/v1/${TABLE}`),
  // UNVERIFIED (supabase.relay-allow-rpc)
  rule('rpc-call', 'POST', `/rest/v1/rpc/${FUNCTION}`),
  // UNVERIFIED (supabase.relay-allow-storage-objects)
  rule('storage-download', 'GET', `/storage/v1/object/authenticated/${BUCKET}/{rest:**}`),
  // UNVERIFIED (supabase.relay-allow-storage-list)
  rule('storage-list', 'POST', `/storage/v1/object/list/${BUCKET}`),
];

const sample = (method: string, path: string): SampleRequest => ({ method, url: `https://${SAMPLE_HOST}${path}` });
const deny = (id: string, paths: readonly (readonly [string, string])[]): DenyRule => ({ id, samples: paths.map(([method, path]) => sample(method, path)) });

const MUST_DENY: readonly DenyRule[] = [
  // UNVERIFIED (supabase.relay-deny-auth)
  deny('auth', [['POST', '/auth/v1/token?grant_type=password'], ['GET', '/auth/v1/admin/users'], ['POST', '/auth/v1/signup'], ['POST', '/auth/v1/admin/users']]),
  // UNVERIFIED (supabase.relay-deny-pg)
  deny('pg', [['GET', '/pg/tables'], ['POST', '/pg/query']]),
  // UNVERIFIED (supabase.relay-deny-graphql)
  deny('graphql', [['POST', '/graphql/v1'], ['GET', '/graphql/v1']]),
  // UNVERIFIED (supabase.relay-deny-functions)
  deny('functions', [['POST', '/functions/v1/hello'], ['GET', '/functions/v1/hello']]),
  // UNVERIFIED (supabase.relay-deny-storage-sign)
  deny('storage-sign', [['POST', '/storage/v1/object/sign/avatars/a.png'], ['GET', '/storage/v1/object/sign/avatars/a.png']]),
  // UNVERIFIED (supabase.relay-deny-storage-upload-sign)
  deny('storage-upload-sign', [['POST', '/storage/v1/object/upload/sign/avatars/a.png'], ['PUT', '/storage/v1/object/upload/sign/avatars/a.png']]),
  // UNVERIFIED (supabase.relay-deny-storage-bucket)
  deny('storage-bucket', [['GET', '/storage/v1/bucket'], ['POST', '/storage/v1/bucket'], ['GET', '/storage/v1/bucket/avatars'], ['DELETE', '/storage/v1/bucket/avatars']]),
  // UNVERIFIED (supabase.relay-deny-realtime)
  deny('realtime', [['GET', '/realtime/v1/websocket'], ['POST', '/realtime/v1/api/broadcast']]),
  // UNVERIFIED (supabase.relay-deny-rest-root): the root serves the whole schema (PostgREST's OpenAPI document).
  deny('rest-root', [['GET', '/rest/v1'], ['GET', '/rest/v1/']]),
  // Chosen here: the project's MCP endpoint (the gateway routes `/mcp`) runs SQL and manages the project; it is no relay use.
  deny('mcp', [['POST', '/mcp/sse'], ['GET', '/mcp/sse'], ['POST', '/api/mcp']]),
];

export const supabaseProfile: RelayProfile = {
  platform: 'supabase',
  origin: ORIGIN,
  callerTokenHeaders: ['authorization', 'apikey'],
  // A secret key travels in `apikey` only: the relay never forwards the caller's `Authorization` and sets none.
  inject: async (headers: Headers, value: Lent): Promise<void> => {
    headers.set('apikey', await value.use((bytes) => Promise.resolve(Buffer.from(bytes).toString('utf8'))));
  },
  allow: ALLOW,
  tailRules: ['storage-download'],
  mustDeny: MUST_DENY,
  // `Accept-Profile` and `Content-Profile` pass only as `public` (UNVERIFIED supabase.relay-deny-profile-headers: an absent header means the first schema).
  requestHeaders: ['prefer', 'accept-profile', 'content-profile'],
  headerWords: { 'accept-profile': ['public'], 'content-profile': ['public'] },
  responseHeaders: ['sb-request-id', 'x-request-id'],
  itemsRange: true,
  envForClients: (relayUrl: string): Record<string, string> => ({ SUPABASE_URL: relayUrl, SUPABASE_SECRET_KEY: '<pass>' }),
};
