// KBOX-10: machine API tokens are `kbt_` plus 32 random bytes in base64url (43 characters). The box keeps only the
// SHA-256 of the token text, and a presented token is compared against every stored hash in constant time.
import { createHash, timingSafeEqual } from 'node:crypto';
import type { TokenRecord } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';

const TOKEN = /^kbt_[A-Za-z0-9_-]{43}$/;

export function newToken(random: Random): string {
  return `kbt_${Buffer.from(random.bytes(32)).toString('base64url')}`;
}

/** Lower-case hex SHA-256 of the whole token text, `kbt_` included. */
export const hashToken = (token: string): string => createHash('sha256').update(token, 'utf8').digest('hex');

export type BearerParse = { readonly kind: 'absent' } | { readonly kind: 'malformed' } | { readonly kind: 'token'; readonly token: string };

/** Reads the Authorization header. A malformed token is told apart here, so it never reaches a lookup. */
export function parseBearer(header: string | undefined): BearerParse {
  if (header === undefined) return { kind: 'absent' };
  const match = /^bearer (\S+)$/i.exec(header);
  const token = match?.[1];
  return token !== undefined && TOKEN.test(token) ? { kind: 'token', token } : { kind: 'malformed' };
}

export type PassHeaderName = 'authorization' | 'apikey';
export type PassParse =
  | { readonly kind: 'absent' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'mismatch' }
  | { readonly kind: 'pass'; readonly token: string; readonly carriers: readonly PassHeaderName[] };

/** KBOX-13 step 1, KBOX-32: a relay pass from `Authorization: Bearer` and `apikey`; when both are present they must agree. */
export function parsePass(authorization: string | undefined, apikey: string | undefined): PassParse {
  const found: { readonly header: PassHeaderName; readonly token: string | undefined }[] = [];
  if (authorization !== undefined) {
    const bearer = parseBearer(authorization);
    found.push({ header: 'authorization', token: bearer.kind === 'token' ? bearer.token : undefined });
  }
  if (apikey !== undefined) found.push({ header: 'apikey', token: TOKEN.test(apikey) ? apikey : undefined });
  const first = found[0];
  if (first === undefined) return { kind: 'absent' };
  if (found.some((f) => f.token === undefined)) return { kind: 'malformed' };
  if (found.some((f) => f.token !== first.token) || first.token === undefined) return { kind: 'mismatch' };
  return { kind: 'pass', token: first.token, carriers: found.map((f) => f.header) };
}

/** The record whose hash equals the token's. Every record is compared, whatever the outcome, with a constant-time comparison. */
export const findToken = (records: readonly TokenRecord[], token: string): TokenRecord | undefined => findTokenHash(records, hashToken(token));

/** The same for a token's lower-case hex SHA-256, as kb-relay sends it on the lend socket (KBOX-3). */
export function findTokenHash(records: readonly TokenRecord[], tokenSha256: string): TokenRecord | undefined {
  const wanted = Buffer.from(tokenSha256, 'hex');
  if (wanted.length !== 32) return undefined;
  let found: TokenRecord | undefined;
  for (const record of records) {
    const stored = Buffer.from(record.tokenSha256, 'hex');
    if (stored.length === wanted.length && timingSafeEqual(stored, wanted)) found = record;
  }
  return found;
}
