// KBOX-22: Web Push cryptography with node:crypto only. RFC 8291 payload encryption (RFC 8188 `aes128gcm`, HKDF, ECDH P-256)
// and the RFC 8292 VAPID header (ES256). Keys and the salt come in as arguments: nothing here generates a key or draws
// a random byte (KBOX-28). A failure is one fixed code, never text from the input.
import { createCipheriv, createECDH, createPrivateKey, hkdfSync, sign } from 'node:crypto';

export interface P256KeyPair {
  /** The 32-byte private scalar. */
  readonly privateKey: Uint8Array;
  /** The 65-byte uncompressed point (`0x04 || x || y`) of that private scalar. */
  readonly publicKey: Uint8Array;
}

export type PushCryptoCode = 'bad_key' | 'bad_secret' | 'bad_salt' | 'too_long';
export type CryptoResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: PushCryptoCode };

export const P256_POINT_BYTES = 65;
export const AUTH_SECRET_BYTES = 16;
const SALT_BYTES = 16;
const TAG_BYTES = 16;
/** RFC 8291 section 4: the record size this box always writes. One record holds the whole payload. */
const RECORD_SIZE = 4096;
/** One record carries the data, the 0x02 delimiter and the GCM tag. */
export const MAX_PLAINTEXT_BYTES = RECORD_SIZE - TAG_BYTES - 1;

const text = (s: string): Buffer => Buffer.from(s, 'utf8');
const fail = (code: PushCryptoCode): { readonly ok: false; readonly code: PushCryptoCode } => ({ ok: false, code });
const same = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(b);

type Agreement = { readonly ok: true; readonly secret: Buffer; readonly publicKey: Buffer } | { readonly ok: false };

/** The shared secret of a private scalar and a peer point; refused when either is not a valid P-256 value. */
function ecdhSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Agreement {
  try {
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(privateKey));
    return { ok: true, secret: ecdh.computeSecret(Buffer.from(peerPublicKey)), publicKey: ecdh.getPublicKey() };
  } catch {
    return { ok: false };
  }
}

/** The scalar 1: any valid private key does to ask the curve whether a point lies on it. */
const PROBE_SCALAR = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);

/** True when the bytes are an uncompressed point that lies on P-256. */
export function isP256Point(bytes: Uint8Array): boolean {
  return bytes.length === P256_POINT_BYTES && bytes[0] === 4 && ecdhSecret(PROBE_SCALAR, bytes).ok;
}

export interface EncryptInput {
  readonly plaintext: Uint8Array;
  /** The browser's 65-byte public key (`p256dh`). */
  readonly receiverPublicKey: Uint8Array;
  /** The browser's 16-byte auth secret. */
  readonly authSecret: Uint8Array;
  /** The sender's ephemeral key pair, fresh for this message. */
  readonly sender: P256KeyPair;
  /** 16 random bytes, fresh for this message. */
  readonly salt: Uint8Array;
}

/** RFC 8291 section 3.4 and 4: header (salt, record size, key id = the sender's public key) then one encrypted record. */
export function encryptPayload(input: EncryptInput): CryptoResult<Uint8Array> {
  if (input.authSecret.length !== AUTH_SECRET_BYTES) return fail('bad_secret');
  if (input.salt.length !== SALT_BYTES) return fail('bad_salt');
  if (input.plaintext.length > MAX_PLAINTEXT_BYTES) return fail('too_long');
  const agreed = ecdhSecret(input.sender.privateKey, input.receiverPublicKey);
  if (!agreed.ok || input.receiverPublicKey.length !== P256_POINT_BYTES || !same(input.sender.publicKey, agreed.publicKey)) return fail('bad_key');

  const keyInfo = Buffer.concat([text('WebPush: info\0'), input.receiverPublicKey, input.sender.publicKey]);
  const ikm = Buffer.from(hkdfSync('sha256', agreed.secret, input.authSecret, keyInfo, 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, input.salt, text('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, input.salt, text('Content-Encoding: nonce\0'), 12));

  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const record = Buffer.concat([cipher.update(Buffer.concat([input.plaintext, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);
  const header = Buffer.alloc(SALT_BYTES + 4 + 1);
  header.set(input.salt, 0);
  header.writeUInt32BE(RECORD_SIZE, SALT_BYTES);
  header.writeUInt8(P256_POINT_BYTES, SALT_BYTES + 4);
  return { ok: true, value: Uint8Array.from(Buffer.concat([header, input.sender.publicKey, record])) };
}

export interface VapidInput {
  readonly sender: P256KeyPair;
  /** The push service's endpoint: the JWT's `aud` is its origin. */
  readonly endpoint: URL;
  /** Seconds since the Unix epoch; RFC 8292 section 2 allows at most 24 hours ahead. */
  readonly expiresAt: number;
  /** A `mailto:` or `https:` contact for the push service operator. */
  readonly subject: string;
}

const json64 = (value: Readonly<Record<string, string | number>>): string => text(JSON.stringify(value)).toString('base64url');

/** RFC 8292 section 2: `vapid t=<jwt>, k=<public key>`, the JWT signed ES256 with a raw r||s signature. */
export function vapidAuthorization(input: VapidInput): CryptoResult<string> {
  const { privateKey, publicKey } = input.sender;
  if (!isP256Point(publicKey)) return fail('bad_key');
  const signed = `${json64({ typ: 'JWT', alg: 'ES256' })}.${json64({ aud: input.endpoint.origin, exp: input.expiresAt, sub: input.subject })}`;
  try {
    const key = createPrivateKey({
      key: { kty: 'EC', crv: 'P-256', d: Buffer.from(privateKey).toString('base64url'), x: Buffer.from(publicKey.slice(1, 33)).toString('base64url'), y: Buffer.from(publicKey.slice(33, 65)).toString('base64url') },
      format: 'jwk',
    });
    const signature = sign('sha256', Buffer.from(signed), { key, dsaEncoding: 'ieee-p1363' });
    return { ok: true, value: `vapid t=${signed}.${signature.toString('base64url')}, k=${Buffer.from(publicKey).toString('base64url')}` };
  } catch {
    return fail('bad_key');
  }
}
