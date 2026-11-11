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

/** The record whose hash equals the token's. Every record is compared, whatever the outcome, with a constant-time comparison. */
export function findToken(records: readonly TokenRecord[], token: string): TokenRecord | undefined {
  const wanted = Buffer.from(hashToken(token), 'hex');
  let found: TokenRecord | undefined;
  for (const record of records) {
    const stored = Buffer.from(record.tokenSha256, 'hex');
    if (stored.length === wanted.length && timingSafeEqual(stored, wanted)) found = record;
  }
  return found;
}
