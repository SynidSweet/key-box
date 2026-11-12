// KBOX-41: the box's signing key, a vault key of master class. The vault holds the P-256 private scalar as 43 base64url characters (32 random
// bytes): random over its whole length, so KBOX-18 watches it windowed. The key is used only inside `Lent.use`: its public half and its
// signature leave, the scalar and the KeyObject built from it never do.
import { createECDH, createHash, createPrivateKey, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { KeyShape, Lent } from '../../ports/types.ts';
import { GoogleError } from './errors.ts';

export const SIGNING_KEY_SHAPE: KeyShape = { prefix: null, alphabet: 'base64url', coreLength: { min: 43, max: 43 }, random: true };

/** A signing key's public half as the JWKS lists it. `kid` is its RFC 7638 thumbprint, so the same key always has the same id. */
export interface PublicJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly kid: string;
  readonly alg: 'ES256';
  readonly use: 'sig';
}

const SCALAR = /^[A-Za-z0-9_-]{43}$/;

interface Opened {
  readonly jwk: PublicJwk;
  readonly privateKey: KeyObject;
}

/** The key's public half and a KeyObject for signing, from the scalar's bytes; anything that is not a valid P-256 scalar is refused. */
function open(bytes: Uint8Array): Opened {
  const text = Buffer.from(bytes).toString('latin1');
  const d = Buffer.from(text, 'base64url');
  if (!SCALAR.test(text) || d.length !== 32 || d.toString('base64url') !== text) throw new GoogleError('signing_key_unreadable');
  const ecdh = createECDH('prime256v1');
  try {
    ecdh.setPrivateKey(d);
  } catch {
    // Zero, or not below the curve's order: not a key. Nothing of the value is kept.
    throw new GoogleError('signing_key_unreadable');
  } finally {
    d.fill(0);
  }
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  // RFC 7638: the members kty, crv, x, y in lexicographic order, no whitespace.
  const kid = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url');
  const privateKey = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: text, x, y }, format: 'jwk' });
  return { jwk: { kty: 'EC', crv: 'P-256', x, y, kid, alg: 'ES256', use: 'sig' }, privateKey };
}

export const publicJwkOf = (key: Lent): Promise<PublicJwk> => key.use((bytes) => Promise.resolve(open(bytes).jwk));

/**
 * A compact JWS: `signingInput(kid)` (the key's id goes into the header it builds), a dot, and the ES256 signature over it in JWS form
 * (the raw 64-byte r||s, base64url).
 */
export const signCompact = (key: Lent, signingInput: (kid: string) => string): Promise<string> =>
  key.use((bytes) => {
    const { jwk, privateKey } = open(bytes);
    const input = signingInput(jwk.kid);
    return Promise.resolve(`${input}.${sign('sha256', Buffer.from(input, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`);
  });
