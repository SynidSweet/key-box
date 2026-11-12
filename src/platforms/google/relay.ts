// KBOX-59, KBOX-13, KBOX-25, KBOX-32: the `google` relay profile, for a key used through the relay. The upstream host is the first path segment
// (`/r/<keyref>/<host>/<path>`), which must be one of the profile's hosts byte for byte; the pass arrives as `Authorization: Bearer <pass>` and is
// replaced by the key as the header `x-goog-api-key`, never a `key=` query (a query would put the key in a URL every log keeps). Default-deny: only
// the named Firestore and Cloud Storage operations pass, and everything that mints, lends or changes a credential, a policy or code is listed by
// name in `mustDeny` with the KBOX-13 canonicalisation variants of each sample.
//
// Narrower than a client might want, on purpose (reported): an object name with a slash is `%2F` in Cloud Storage's path, which KBOX-13 refuses,
// so only flat object names pass; a list or a read takes only the `alt` word; an upload takes `uploadType=multipart` only (the object's name is
// in its body). A key's own rules (`set_allow_rules`) never add more: they only narrow this list (KBOX-61). The mustDeny paths are confirmed against the discovery documents by the probe
// (KBOX-42, `google.must-deny-discovery`, UNVERIFIED): 15 of the samples name routes no discovery document describes.
import type { AllowRule, DenyRule, RelayProfile, SampleRequest } from '../../ports/relay-profile.ts';
import type { Lent } from '../../ports/types.ts';

const FIRESTORE = 'firestore.googleapis.com';
const STORAGE = 'storage.googleapis.com';

const PROJECT = '{project:[a-z0-9-]{6,30}}';
const DATABASES = ['{database:[a-z0-9-]{4,63}}', '(default)'] as const;
const BUCKET = '{bucket:[a-z0-9._-]{3,63}}';
const OBJECT = '{object:[A-Za-z0-9._~-]{1,128}}';

/** One allow rule per database form (a named database, and the literal `(default)` one) and per method or verb: the id says which. */
function documentRules(): readonly AllowRule[] {
  const rules: AllowRule[] = [];
  for (const [i, database] of DATABASES.entries()) {
    const form = i === 0 ? '' : '-default';
    const base = `/v1/projects/${PROJECT}/databases/${database}`;
    for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) rules.push({ id: `fs-doc-${method.toLowerCase()}${form}`, method, host: FIRESTORE, pathTemplate: `${base}/documents/{rest:**}`, query: {} });
    for (const verb of ['runQuery', 'batchGet', 'commit']) rules.push({ id: `fs-query-${verb.toLowerCase()}${form}`, method: 'POST', host: FIRESTORE, pathTemplate: `${base}/documents:${verb}`, query: {} });
  }
  return rules;
}

const ALT = { alt: { kind: 'word', words: ['json', 'media'] } } as const;

const ALLOW: readonly AllowRule[] = [
  ...documentRules(),
  { id: 'gcs-list', method: 'GET', host: STORAGE, pathTemplate: `/storage/v1/b/${BUCKET}/o`, query: {} },
  { id: 'gcs-object-get', method: 'GET', host: STORAGE, pathTemplate: `/storage/v1/b/${BUCKET}/o/${OBJECT}`, query: ALT },
  { id: 'gcs-object-delete', method: 'DELETE', host: STORAGE, pathTemplate: `/storage/v1/b/${BUCKET}/o/${OBJECT}`, query: {} },
  { id: 'gcs-upload', method: 'POST', host: STORAGE, pathTemplate: `/upload/storage/v1/b/${BUCKET}/o`, query: { uploadType: { kind: 'word', words: ['multipart'] } } },
];

/** The rules whose template ends in `{rest:**}`. */
const TAIL_RULES: readonly string[] = ALLOW.filter((r) => r.pathTemplate.endsWith('{rest:**}')).map((r) => r.id);

const hex = (c: string): string => c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');

/** The sample requests of one denied route: the concrete request and the KBOX-13 ambiguities of its path (escape, slashes, dots, `;`, method tricks). */
function variants(method: string, host: string, route: string): readonly SampleRequest[] {
  const [path = '', query = ''] = route.split('?');
  const url = (p: string, extra = ''): string => {
    const q = [extra, query].filter((part) => part !== '').join('&');
    return `https://${host}${p}${q === '' ? '' : `?${q}`}`;
  };
  return [
    { method, url: url(path) },
    { method, url: url(path.replace(/\/([^/])([^/]*)$/, (_all, first: string, rest: string) => `/%${hex(first)}${rest}`)) },
    { method, url: url(`${path}/`) },
    { method, url: url(path.replace('/', '//')) },
    { method, url: url(path.replace(/\/([^/]+)$/, '/x/../$1')) },
    { method, url: url(path.replace(/\/([^/]+)$/, '/%2e%2e/$1')) },
    { method, url: url(path.replace(/(\/[^/]+)?\/([^/]+)$/, (_all, head: string | undefined, last: string) => `${head ?? '/'}%2F${last}`)) },
    { method, url: url(`${path};x`) },
    { method, url: url(path, `_method=${method}`) },
    { method: 'GET', url: url(path, `%24method=${method}`) },
  ];
}

const api = (name: string): string => `${name}.googleapis.com`;

/** One denied request: its method, host and the route (path and query) a caller would send. */
type Route = readonly [method: string, host: string, route: string];

/** The code-running hosts: each could run the caller's code with the box's project authority, so none is reachable (a request to any is denied by host). */
const CODE_HOSTS = ['run', 'cloudfunctions', 'cloudbuild', 'compute', 'appengine', 'cloudscheduler', 'cloudtasks', 'workflows', 'eventarc'] as const;

const DENIED: readonly (readonly [id: string, routes: readonly Route[]])[] = [
  ['iam', [['POST', api('iam'), '/v1/projects/p/serviceAccounts/sa1/keys']]],
  ['iamcredentials', [['POST', api('iamcredentials'), '/v1/projects/-/serviceAccounts/x@p.iam.gserviceaccount.com:generateAccessToken']]],
  ['sts', [['POST', api('sts'), '/v1/token']]],
  ['oauth2', [['POST', api('oauth2'), '/token']]],
  ['accounts', [['GET', 'accounts.google.com', '/o/oauth2/v2/auth']]],
  ['securetoken', [['POST', api('securetoken'), '/v1/token']]],
  ['apikeys', [['GET', api('apikeys'), '/v2/projects/p/locations/global/keys']]],
  ['cloudresourcemanager', [['POST', api('cloudresourcemanager'), '/v1/projects/p:getIamPolicy']]],
  ['secretmanager', [['GET', api('secretmanager'), '/v1/projects/p/secrets/s/versions/1:access']]],
  ['identitytoolkit', [['POST', api('identitytoolkit'), '/v1/accounts:signInWithCustomToken']]],
  ['firebase', [['GET', api('firebase'), '/v1beta1/projects/p/webApps/a/config']]],
  ...CODE_HOSTS.map((host): (typeof DENIED)[number] => [host, [['GET', api(host), '/v1/projects/p']]]),
  ['pubsub-subscription', [['PUT', api('pubsub'), '/v1/projects/p/subscriptions/s'], ['PATCH', api('pubsub'), '/v1/projects/p/subscriptions/s']]],
  ['storage-hmac-keys', [['POST', STORAGE, '/storage/v1/projects/p/hmacKeys?serviceAccountEmail=x']]],
  ['storage-bucket-iam', [['GET', STORAGE, '/storage/v1/b/b/iam'], ['PUT', STORAGE, '/storage/v1/b/b/iam']]],
  ['set-iam-policy', [['POST', FIRESTORE, '/v1/projects/p/databases/d:setIamPolicy']]],
];

const MUST_DENY: readonly DenyRule[] = DENIED.map(([id, routes]): DenyRule => ({ id, samples: routes.flatMap(([method, host, route]) => variants(method, host, route)) }));

/** The host of every allow rule and every denied route: the profile's origin must name each, so a request for a denied host is parsed and denied by name. */
const HOSTS: readonly string[] = [...new Set([...ALLOW.map((r) => r.host), ...DENIED.flatMap(([, routes]) => routes.map(([, host]) => host))])];

async function inject(h: Headers, key: Lent): Promise<void> {
  const value = await key.use((bytes) => Promise.resolve(Buffer.from(bytes).toString('utf8')));
  // Google's API-key header. The caller's pass (its `Authorization`) does not go upstream.
  h.delete('authorization');
  h.set('x-goog-api-key', value);
}

export const googleRelayProfile: RelayProfile = {
  platform: 'google',
  origin: { kind: 'host-in-path', hosts: HOSTS },
  callerTokenHeaders: ['authorization'],
  inject,
  allow: ALLOW,
  tailRules: TAIL_RULES,
  mustDeny: MUST_DENY,
  requestHeaders: [],
  headerWords: {},
  responseHeaders: ['x-guploader-uploadid'],
  envForClients: (relayUrl: string): Record<string, string> => ({ KBOX_GOOGLE_RELAY_URL: relayUrl }),
};
