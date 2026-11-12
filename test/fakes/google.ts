// A loopback server that plays the Google hosts the box reaches, as docs/probes/google.md describes them: STS token
// exchange (`POST /v1/token`, form-encoded, `{error, error_description}` on a 400), IAM Credentials `generateAccessToken` and Cloud Resource
// Manager `testIamPermissions`. It checks the box's JWT on its own (WebCrypto against the JWKS the test hands it), so a test sees what
// Google would accept. Reached through `adapterHttpTo(fake)`; the path tells the hosts apart. Run directly, this file does nothing.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fakeApis } from './google-apis.ts';
import type { ApisRoute, FakeApis } from './google-apis.ts';

/** Anything that runs a cleanup when its test or suite ends: a TestContext, or a suite-level hook's own list. */
export interface Cleanups {
  after(fn: () => unknown): void;
}

export interface GoogleRequest {
  readonly method: string;
  readonly path: string;
  readonly authorization: string | undefined;
  readonly contentType: string | undefined;
  readonly body: string;
}

/** A public signing key as a JWKS lists it. */
export interface TrustedJwk {
  readonly kid: string;
  readonly kty: string;
  readonly crv: string;
  readonly x: string;
  readonly y: string;
}

/** What one route answers in place of its normal answer. */
export type Override =
  | { readonly kind: 'status'; readonly status: number; readonly body: string }
  | { readonly kind: 'hang' }
  | { readonly kind: 'cut' };

export type GoogleRoute = 'sts' | 'impersonate' | 'test-permissions' | ApisRoute;

export interface FakeGoogle {
  readonly url: string;
  readonly requests: readonly GoogleRequest[];
  /** The JWKS the pool's provider trusts (Google's view of the box's JWKS). */
  trust(keys: readonly TrustedJwk[]): void;
  /** The service accounts the federated principal holds Token Creator on. */
  creatorOn(serviceAccounts: readonly string[]): void;
  /** The permissions a service account holds on its project. */
  holds(serviceAccount: string, permissions: readonly string[]): void;
  /** The next answers of one route, in place of the normal one; `undefined` restores it. */
  override(route: GoogleRoute, override: Override | undefined): void;
  /** The access token the next generateAccessToken returns (a test plants a canary here). */
  nextAccessToken(token: string): void;
  /** The claims of the last JWT STS accepted. */
  readonly lastClaims: Readonly<Record<string, unknown>> | undefined;
  readonly lastHeader: Readonly<Record<string, unknown>> | undefined;
  /** The API Keys, Cloud Resource Manager v3 and Secret Manager halves (google-apis.ts). */
  readonly apis: FakeApis;
  /** A bearer the fake takes as this service account's token, without the exchange (a test that needs no minter). */
  admit(token: string, serviceAccount: string): void;
  /** Forgets every request, override, key and secret; keeps what STS trusts and who may impersonate. */
  reset(): void;
  /** Forgets the requests seen so far and nothing else. */
  clearRequests(): void;
}

export interface FakeGoogleOptions {
  /** The audience STS takes: `//iam.googleapis.com/projects/<n>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`. */
  readonly audience: string;
  /** The issuer the provider trusts. */
  readonly issuer: string;
  /** The subject the principal is bound to. */
  readonly subject: string;
}

const STS = '/v1/token';
const IMPERSONATE = /^\/v1\/projects\/-\/serviceAccounts\/([^/:]+):generateAccessToken$/;
const TEST_PERMISSIONS = /^\/v1\/projects\/([^/:]+):testIamPermissions$/;
const FEDERATED_PREFIX = 'kbox-test-federated-';
const SA_TOKEN_PREFIX = 'ya29.kbox-test-sa-';

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

/** A JWT segment's JSON object; an empty object (no `alg`, no claim) when it is not one, which STS then refuses. */
const decodeSegment = (s: string): Record<string, unknown> => {
  try {
    const value: unknown = JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
};

export async function fakeGoogle(t: Cleanups, options: FakeGoogleOptions): Promise<FakeGoogle> {
  const requests: GoogleRequest[] = [];
  let trusted: readonly TrustedJwk[] = [];
  let creators = new Set<string>();
  const held = new Map<string, readonly string[]>();
  const overrides = new Map<GoogleRoute, Override>();
  const apis = fakeApis();
  const federated = new Set<string>();
  const saTokens = new Map<string, string>();
  let planted: string | undefined;
  let issued = 0;
  let lastClaims: Record<string, unknown> | undefined;
  let lastHeader: Record<string, unknown> | undefined;

  /** STS's own check of the subject token: an ES256 JWT by a trusted key, with the provider's issuer, subject and audience, not expired. */
  const verifyJwt = async (token: string): Promise<boolean> => {
    const [h, p, s, extra] = token.split('.');
    if (h === undefined || p === undefined || s === undefined || extra !== undefined) return false;
    const header = decodeSegment(h);
    const claims = decodeSegment(p);
    if (header['alg'] !== 'ES256') return false;
    const jwk = trusted.find((k) => k.kid === header['kid']);
    if (jwk === undefined) return false;
    const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(s, 'base64url'), Buffer.from(`${h}.${p}`));
    if (!ok) return false;
    const audience = `https:${options.audience}`;
    if (claims['iss'] !== options.issuer || claims['sub'] !== options.subject || claims['aud'] !== audience) return false;
    lastClaims = claims;
    lastHeader = header;
    return true;
  };

  const sts = async (req: GoogleRequest, res: ServerResponse): Promise<void> => {
    const form = new URLSearchParams(req.body);
    const field = (name: string): string => form.get(name) ?? '';
    if (field('subject_token') === '') return json(res, 400, { error: 'invalid_request', error_description: 'subject_token is empty' });
    if (field('subject_token_type') !== 'urn:ietf:params:oauth:token-type:jwt') return json(res, 400, { error: 'invalid_request', error_description: 'subject_token_type' });
    if (!field('audience').startsWith('//iam.googleapis.com/projects/')) return json(res, 400, { error: 'invalid_request', error_description: 'Invalid value for audience' });
    if (field('grant_type') !== 'urn:ietf:params:oauth:grant-type:token-exchange') return json(res, 400, { error: 'unsupported_grant_type', error_description: 'Unsupported grant_type' });
    if (field('requested_token_type') !== 'urn:ietf:params:oauth:token-type:access_token') return json(res, 400, { error: 'invalid_request', error_description: 'requested_token_type' });
    if (field('audience') !== options.audience) return json(res, 400, { error: 'invalid_target', error_description: "The target pool or provider doesn't exist" });
    if (!(await verifyJwt(field('subject_token')))) return json(res, 400, { error: 'invalid_grant', error_description: `The token ${field('subject_token')} could not be verified` });
    issued += 1;
    const token = `${FEDERATED_PREFIX}${issued}`;
    federated.add(token);
    return json(res, 200, { access_token: token, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', token_type: 'Bearer', expires_in: 3599 });
  };

  const bearer = (req: GoogleRequest): string => (req.authorization ?? '').replace(/^Bearer /, '');

  const impersonate = (req: GoogleRequest, res: ServerResponse, serviceAccount: string): void => {
    if (!federated.has(bearer(req))) return json(res, 401, { error: { code: 401, message: `Request had invalid authentication credentials: ${bearer(req)}`, status: 'UNAUTHENTICATED' } });
    if (!creators.has(serviceAccount)) return json(res, 403, { error: { code: 403, message: 'Permission iam.serviceAccounts.getAccessToken denied', status: 'PERMISSION_DENIED' } });
    let body: unknown;
    try {
      body = JSON.parse(req.body);
    } catch {
      return json(res, 400, { error: { code: 400, status: 'INVALID_ARGUMENT' } });
    }
    const scope = typeof body === 'object' && body !== null ? (body as Record<string, unknown>)['scope'] : undefined;
    if (!Array.isArray(scope) || scope.length === 0) return json(res, 400, { error: { code: 400, message: 'scope', status: 'INVALID_ARGUMENT' } });
    issued += 1;
    const token = planted ?? `${SA_TOKEN_PREFIX}${issued}`;
    planted = undefined;
    saTokens.set(token, serviceAccount);
    return json(res, 200, { accessToken: token, expireTime: '2023-11-14T23:13:20Z' });
  };

  const testPermissions = (req: GoogleRequest, res: ServerResponse, project: string): void => {
    const serviceAccount = saTokens.get(bearer(req));
    if (serviceAccount === undefined) return json(res, 401, { error: { code: 401, status: 'UNAUTHENTICATED' } });
    if (!serviceAccount.endsWith(`@${project}.iam.gserviceaccount.com`)) return json(res, 403, { error: { code: 403, status: 'PERMISSION_DENIED' } });
    const asked = (JSON.parse(req.body) as { permissions?: unknown }).permissions;
    const list = Array.isArray(asked) ? asked.filter((p): p is string => typeof p === 'string') : [];
    const holding = list.filter((p) => (held.get(serviceAccount) ?? []).includes(p));
    return json(res, 200, holding.length === 0 ? {} : { permissions: holding });
  };

  const routeOf = (method: string, pathname: string): GoogleRoute | undefined => {
    if (method === 'POST') return pathname === STS ? 'sts' : IMPERSONATE.test(pathname) ? 'impersonate' : TEST_PERMISSIONS.test(pathname) ? 'test-permissions' : apis.routeOf(method, pathname);
    return apis.routeOf(method, pathname);
  };

  const handle = async (incoming: IncomingMessage, res: ServerResponse, body: string): Promise<void> => {
    const path = incoming.url ?? '';
    const req: GoogleRequest = { method: incoming.method ?? '', path, authorization: incoming.headers.authorization, contentType: incoming.headers['content-type'], body };
    requests.push(req);
    const url = new URL(path, 'http://fake.invalid');
    const route = routeOf(incoming.method ?? '', url.pathname);
    if (route === undefined) {
      res.writeHead(404, { 'content-type': 'text/html' });
      res.end('<html>404</html>');
      return;
    }
    const override = overrides.get(route);
    if (override?.kind === 'hang') return;
    if (override?.kind === 'cut') {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' });
      res.write('{"x":', () => incoming.socket.destroy());
      return;
    }
    if (override?.kind === 'status') {
      res.writeHead(override.status, { 'content-type': 'application/json' });
      res.end(override.body);
      return;
    }
    const apisRoute = apis.routeOf(req.method, url.pathname);
    if (apisRoute !== undefined) {
      const answered = apis.answer(apisRoute, { method: req.method, pathname: url.pathname, query: url.searchParams, body }, saTokens.get(bearer(req)));
      return json(res, answered.status, answered.body);
    }
    if (route === 'sts') return sts(req, res);
    const sa = IMPERSONATE.exec(path)?.[1];
    if (route === 'impersonate' && sa !== undefined) return impersonate(req, res, decodeURIComponent(sa));
    const project = TEST_PERMISSIONS.exec(path)?.[1];
    if (project !== undefined) return testPermissions(req, res, project);
  };

  const server: Server = createServer((incoming, res) => {
    const chunks: Buffer[] = [];
    incoming.on('data', (c: Buffer) => void chunks.push(c));
    incoming.on('end', () => {
      handle(incoming, res, Buffer.concat(chunks).toString('utf8')).catch(() => res.writeHead(500).end());
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err === undefined ? resolve() : reject(err)));
      }),
  );
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    trust: (keys) => void (trusted = keys),
    creatorOn: (sas) => void (creators = new Set(sas)),
    holds: (sa, permissions) => void held.set(sa, permissions),
    override: (route, o) => void (o === undefined ? overrides.delete(route) : overrides.set(route, o)),
    nextAccessToken: (token) => void (planted = token),
    get lastClaims() {
      return lastClaims;
    },
    get lastHeader() {
      return lastHeader;
    },
    apis,
    admit: (token, serviceAccount) => void saTokens.set(token, serviceAccount),
    clearRequests: () => void (requests.length = 0),
    reset: () => {
      requests.length = 0;
      overrides.clear();
      apis.reset();
      planted = undefined;
    },
  };
}
