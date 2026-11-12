// KBOX-41: the minter. Inside core only: a fresh assertion is exchanged at STS for a federated token, which is used once to ask IAM Credentials
// `generateAccessToken` for ONE service account, with only the scopes the use may have. Every check runs before the first call. Both tokens
// join the scanner's match set (KBOX-14) before the minter hands anything out.
//
// Which service account: for the relay and the grant check, the request carries only a keyref and the minter reads that key's stored scope
// itself (`RegistryDeps.keyInfo`, read nowhere else: the arch check `key info reads`), so no caller can name another key's target. For the
// admin token, the request carries the stored location core handed the adapter for the call, and the account is that project's `kbox-keys`.
//
// The STS step's own scope: `cloud-platform`. Google's documented token exchange for impersonation asks it, IAM Credentials takes a token with
// it, and the probe saw STS accept it. The federated token it buys never leaves core: it is used for the one generateAccessToken call that
// follows, and it is held by the scanner until it expires. The `cloud-platform` ban of KBOX-41 is on the token that leaves core for the relay.
import type { AdapterHttp, HttpRequest, HttpResponse } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { BoxIdentity, RegistryDeps } from '../../ports/platform.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import { makeLent } from '../../pure/lent.ts';
import { decodeJsonBody } from '../../pure/schemas.ts';
import { GoogleError } from './errors.ts';
import type { GoogleErrorCode } from './errors.ts';
import { providerOf, signAssertion } from './oidc.ts';
import { ADMIN_ACCOUNT, GOOGLE_ID, serviceAccount, targetOf } from './scope.ts';
import type { Target } from './scope.ts';

export const STS_HOST = 'sts.googleapis.com';
export const IAM_CREDENTIALS_HOST = 'iamcredentials.googleapis.com';
export const CLOUD_PLATFORM = 'https://www.googleapis.com/auth/cloud-platform';
/**
 * The scope of the grant check's own token (KBOX-24): read-only, and it never leaves core. UNVERIFIED (google.generateaccesstoken-scope):
 * that testIamPermissions takes a token of this scope is from Google's documentation, not the probe; if it does not, every check refuses
 * (fail closed), never passes.
 */
export const CLOUD_PLATFORM_READ_ONLY = 'https://www.googleapis.com/auth/cloud-platform.read-only';
/** Seconds a minted service-account token is asked to live. */
export const MINTED_LIFETIME_S = 900;

const SCOPE = /^https:\/\/www\.googleapis\.com\/auth\/[a-z][a-z0-9._-]{0,63}$/;
/** A bearer token as Google returns one: printable, no space; long enough for the scanner to hold its forms. */
const TOKEN = /^[\x21-\x7e]{8,4096}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

/**
 * What a token is minted for. `relay`: the token the relay injects for the key, with the scopes asked, each named by the key's profile, never
 * `cloud-platform`. `grant-check`: the KBOX-24 check's own token for the key, read-only, used inside core. `admin`: the token issuer, lister,
 * verifier and destination calls use inside core, for `kbox-keys` of the project of `at`, which is the stored location core handed the adapter
 * for that call (by convention: the adapter passes it on unchanged), never lent.
 */
export type MintRequest =
  | {
      readonly use: 'relay';
      readonly keyref: string;
      readonly scopes: readonly string[];
      /** The scopes the key's profile names. */
      readonly profileScopes: readonly string[];
    }
  | { readonly use: 'grant-check'; readonly keyref: string }
  | { readonly use: 'admin'; readonly at: KeyLocation };

export interface MintedToken {
  readonly token: Lent;
  /** Milliseconds since the epoch; the scanner holds the token until then. */
  readonly expiresAt: number;
  /** The service account the token acts as. */
  readonly target: Target;
}

export interface Minter {
  /** `master` is the box's signing key (the platform's master key). */
  mint(request: MintRequest, master: Lent): Promise<MintedToken>;
}

/** The keyref the scanner files the tokens under: the key's own, or the admin account's address. */
const holderOf = (request: MintRequest, target: Target): string => (request.use === 'admin' ? target.email : request.keyref);

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The answer's JSON object, or `bad_answer`. */
function bodyOf(response: HttpResponse): Record<string, unknown> {
  const parsed = decodeJsonBody(response.body);
  if (!parsed.ok || !isRecord(parsed.value)) throw new GoogleError('bad_answer');
  return parsed.value;
}

/** A 200, or the step's own code: `refused` for a 4xx, `failed` for anything else. Google's body is never read on a failure. */
function expectOk(response: HttpResponse, refused: GoogleErrorCode, failed: GoogleErrorCode): void {
  if (response.status === 200) return;
  throw new GoogleError(response.status >= 400 && response.status < 500 ? refused : failed, response.status);
}

const tokenIn = (body: Record<string, unknown>, field: string): string => {
  const value = body[field];
  if (typeof value !== 'string' || !TOKEN.test(value)) throw new GoogleError('bad_answer');
  return value;
};

/** One call through the adapter's client; no answer at all is `unreachable`. */
export async function send(http: AdapterHttp, request: HttpRequest): Promise<HttpResponse> {
  try {
    return await http.request(request);
  } catch (error) {
    if (error instanceof HttpTransportError) throw new GoogleError('unreachable');
    throw error;
  }
}

export function createMinter(deps: RegistryDeps): Minter {
  const { http, clock, identity, minted, keyInfo } = deps;

  /** The service account and scopes of a request, once every rule of it holds; a refusal otherwise. No call is made before this. */
  const planOf = (request: MintRequest, read: NonNullable<RegistryDeps['keyInfo']>): { readonly target: Target; readonly scopes: readonly string[] } => {
    if (request.use === 'admin') {
      const project = request.at.project;
      if (project === undefined || !GOOGLE_ID.test(project)) throw new GoogleError('bad_location');
      return { target: serviceAccount(project, ADMIN_ACCOUNT), scopes: [CLOUD_PLATFORM] };
    }
    const stored = read(request.keyref);
    if (stored === undefined) throw new GoogleError('no_key_info');
    const found = targetOf(stored.scopeItems);
    if (!found.ok) throw new GoogleError(found.code);
    switch (request.use) {
      case 'grant-check':
        return { target: found.target, scopes: [CLOUD_PLATFORM_READ_ONLY] };
      case 'relay': {
        const { scopes } = request;
        if (scopes.length === 0 || new Set(scopes).size !== scopes.length || !scopes.every((s) => SCOPE.test(s))) throw new GoogleError('scope_malformed');
        if (scopes.includes(CLOUD_PLATFORM)) throw new GoogleError('cloud_platform_for_relay');
        if (!scopes.every((s) => request.profileScopes.includes(s))) throw new GoogleError('scope_not_in_profile');
        return { target: found.target, scopes };
      }
    }
  };

  /** STS token exchange (probe `google.sts-exchange`, VERIFIED field names): the federated token and when it expires. */
  const exchange = async (master: Lent, box: BoxIdentity): Promise<{ readonly token: string; readonly expiresAt: number }> => {
    const assertion = await signAssertion(box, master, clock.now());
    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      audience: providerOf(box),
      scope: CLOUD_PLATFORM,
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      subject_token: assertion,
    });
    const response = await send(http, { method: 'POST', url: `https://${STS_HOST}/v1/token`, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: Buffer.from(form.toString(), 'utf8') });
    expectOk(response, 'sts_refused', 'sts_failed');
    const body = bodyOf(response);
    const token = tokenIn(body, 'access_token');
    const expiresIn = body['expires_in'];
    if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn <= 0) throw new GoogleError('bad_answer');
    return { token, expiresAt: clock.now() + expiresIn * 1000 };
  };

  /** IAM Credentials generateAccessToken (a 401 naming the method seen): the service account's token and when it expires. */
  const impersonate = async (email: string, scopes: readonly string[], federated: string): Promise<{ readonly token: string; readonly expiresAt: number }> => {
    // UNVERIFIED (google.generateaccesstoken-scope): the request fields `scope` (an array) and `lifetime` are from the discovery document;
    // auth failed before the body was read, so neither was exercised. A scope Google ignored would show as a 400 or a wider token.
    const body = Buffer.from(JSON.stringify({ scope: scopes, lifetime: `${MINTED_LIFETIME_S}s` }), 'utf8');
    const response = await send(http, {
      method: 'POST',
      url: `https://${IAM_CREDENTIALS_HOST}/v1/projects/-/serviceAccounts/${email}:generateAccessToken`,
      headers: { authorization: `Bearer ${federated}`, 'content-type': 'application/json' },
      body,
    });
    expectOk(response, 'impersonation_refused', 'impersonation_failed');
    const answer = bodyOf(response);
    const token = tokenIn(answer, 'accessToken');
    const expireTime = answer['expireTime'];
    const at = typeof expireTime === 'string' && RFC3339_UTC.test(expireTime) ? Date.parse(expireTime) : Number.NaN;
    if (Number.isNaN(at)) throw new GoogleError('bad_answer');
    // Held at least as long as it was asked to live: a token the scanner dropped early could be echoed unseen.
    return { token, expiresAt: Math.max(at, clock.now() + MINTED_LIFETIME_S * 1000) };
  };

  return {
    async mint(request, master) {
      // The relay's registry is built without these (KBOX-3): there, and anywhere core has not configured them, nothing is minted.
      if (identity === undefined || minted === undefined || keyInfo === undefined) throw new GoogleError('identity_unconfigured');
      const { target, scopes } = planOf(request, keyInfo);
      const holder = holderOf(request, target);
      const federated = await exchange(master, identity);
      minted.add(holder, Buffer.from(federated.token, 'utf8'), federated.expiresAt);
      const issued = await impersonate(target.email, scopes, federated.token);
      minted.add(holder, Buffer.from(issued.token, 'utf8'), issued.expiresAt);
      const token = issued.token;
      return { token: makeLent(`google-token ${holder}`, () => Buffer.from(token, 'utf8')), expiresAt: issued.expiresAt, target };
    },
  };
}
