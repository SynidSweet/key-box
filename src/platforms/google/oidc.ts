// KBOX-41: the box as an OIDC issuer toward Google's workload identity federation. Core serves the discovery document and the JWKS on
// keys.<domain>; the minter signs one short ES256 assertion per exchange. The claims are fixed: issuer and audience come from core's
// configuration, the subject is the box, and no caller can ask for another audience or subject.
import type { BoxIdentity } from '../../ports/platform.ts';
import type { Lent } from '../../ports/types.ts';
import { GoogleError } from './errors.ts';
import { publicJwkOf, signCompact } from './signing-key.ts';
import type { PublicJwk } from './signing-key.ts';

/** Seconds an assertion is valid: it is exchanged at once, so minutes (Google accepts `exp - iat` up to 24 h). */
export const ASSERTION_LIFETIME_S = 300;
/** The one subject the box asserts; the pool's principal for it holds Token Creator on the listed service accounts. */
export const BOX_SUBJECT = 'keybox';
export const JWKS_PATH = '/.well-known/jwks.json';
export const DISCOVERY_PATH = '/.well-known/openid-configuration';

/** `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` (probe `google.sts-exchange`). */
const PROVIDER = /^\/\/iam\.googleapis\.com\/projects\/[0-9]{1,20}\/locations\/global\/workloadIdentityPools\/[a-z0-9-]{4,32}\/providers\/[a-z0-9-]{4,32}$/;

/** The workload identity provider of the identity, refused when it has any other form. */
export function providerOf(identity: BoxIdentity): string {
  if (!PROVIDER.test(identity.audience)) throw new GoogleError('identity_malformed');
  return identity.audience;
}

export function discoveryDocument(issuer: string): Readonly<Record<string, unknown>> {
  return {
    issuer,
    jwks_uri: `${issuer}${JWKS_PATH}`,
    response_types_supported: ['id_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['ES256'],
    claims_supported: ['iss', 'sub', 'aud', 'iat', 'exp'],
  };
}

export async function jwksDocument(keys: readonly Lent[]): Promise<{ readonly keys: readonly PublicJwk[] }> {
  const jwks: PublicJwk[] = [];
  for (const key of keys) jwks.push(await publicJwkOf(key));
  return { keys: jwks };
}

/** What a caller may say about the claims: nothing that differs from the fixed values. */
export interface ClaimRequest {
  readonly audience?: string;
  readonly subject?: string;
}

const segment = (value: unknown): string => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

/**
 * The assertion STS exchanges: header `{alg: ES256, typ: JWT, kid}`, claims exactly `{iss, sub, aud, iat, exp}`. `aud` is the provider as
 * an https URL, the default allowed audience of a Google OIDC provider. A request for another audience or subject is refused.
 */
export async function signAssertion(identity: BoxIdentity, key: Lent, nowMs: number, asked: ClaimRequest = {}): Promise<string> {
  const provider = providerOf(identity);
  if ((asked.audience !== undefined && asked.audience !== provider) || (asked.subject !== undefined && asked.subject !== BOX_SUBJECT)) throw new GoogleError('claims_fixed');
  const iat = Math.floor(nowMs / 1000);
  const claims = { iss: identity.issuer, sub: BOX_SUBJECT, aud: `https:${provider}`, iat, exp: iat + ASSERTION_LIFETIME_S };
  return signCompact(key, (kid) => `${segment({ alg: 'ES256', typ: 'JWT', kid })}.${segment(claims)}`);
}
