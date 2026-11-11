// KBOX-22: how the owner learns something waits. Web Push from the box itself: RFC 8291 payload encryption, RFC 8292 VAPID.
import assert from 'node:assert/strict';
import { createDecipheriv, createECDH, createPublicKey, hkdfSync, verify } from 'node:crypto';
import { test } from 'node:test';
import { encryptPayload, vapidAuthorization } from '../src/pure/pushcrypto.ts';
import type { P256KeyPair } from '../src/pure/pushcrypto.ts';

const b64u = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'base64url'));
const toB64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const concat = (...parts: readonly Uint8Array[]): Uint8Array => Uint8Array.from(Buffer.concat(parts));

// RFC 8291 Appendix A: the example's inputs and intermediate values, copied from the RFC text.
const RFC = {
  plaintext: b64u('V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24'),
  asPublic: b64u('BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8'),
  asPrivate: b64u('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw'),
  uaPrivate: b64u('q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94'),
  uaPublic: b64u('BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4'),
  salt: b64u('DGv6ra1nlYgDCS1FRnbzlw'),
  authSecret: b64u('BTBZMqHH6r4Tts7J_aSIgg'),
  header: b64u('DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8'),
  ciphertext: b64u('8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ'),
};
const rfcSender: P256KeyPair = { privateKey: RFC.asPrivate, publicKey: RFC.asPublic };

const rfcInput = {
  plaintext: RFC.plaintext,
  receiverPublicKey: RFC.uaPublic,
  authSecret: RFC.authSecret,
  sender: rfcSender,
  salt: RFC.salt,
};

test('KBOX-22 payload encryption reproduces the RFC 8291 Appendix A example byte for byte', () => {
  const result = encryptPayload(rfcInput);
  assert.ok(result.ok);
  assert.equal(toB64u(result.value), toB64u(concat(RFC.header, RFC.ciphertext)));
  assert.equal(RFC.header.length, 86, 'RFC 8291 Appendix A: the header is 86 octets');
});

test('KBOX-22 payload encryption refuses a bad key, secret, salt, a mismatched pair and a payload over one record, by fixed code', () => {
  const code = (override: Partial<typeof rfcInput>): string | undefined => {
    const result = encryptPayload({ ...rfcInput, ...override });
    return result.ok ? undefined : result.code;
  };
  assert.equal(code({ receiverPublicKey: RFC.uaPublic.slice(0, 64) }), 'bad_key');
  assert.equal(code({ receiverPublicKey: Uint8Array.from({ length: 65 }, () => 4) }), 'bad_key', 'a point that is not on the curve');
  assert.equal(code({ authSecret: RFC.authSecret.slice(0, 15) }), 'bad_secret');
  assert.equal(code({ salt: RFC.salt.slice(0, 15) }), 'bad_salt');
  assert.equal(code({ sender: { privateKey: RFC.asPrivate, publicKey: RFC.uaPublic } }), 'bad_key', 'public key that is not the private key\'s');
  assert.equal(code({ plaintext: new Uint8Array(4079) }), undefined, 'RFC 8188: 4096 minus tag and delimiter fits');
  assert.equal(code({ plaintext: new Uint8Array(4080) }), 'too_long');
});

interface Jwt {
  readonly header: Record<string, unknown>;
  readonly claims: Record<string, unknown>;
  readonly signed: string;
  readonly signature: Uint8Array;
}

/** RFC 8292 section 2: `vapid t=<jwt>, k=<key>`; the JWT decoded here without the module's help. */
function parseAuthorization(value: string): { jwt: Jwt; key: Uint8Array } {
  const match = /^vapid t=([\w-]+)\.([\w-]+)\.([\w-]+), k=([\w-]+)$/.exec(value);
  assert.ok(match, 'the header has the shape vapid t=<jwt>, k=<key>');
  const [, h, c, s, k] = match;
  assert.ok(h !== undefined && c !== undefined && s !== undefined && k !== undefined);
  return {
    jwt: { header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as Record<string, unknown>, claims: JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as Record<string, unknown>, signed: `${h}.${c}`, signature: b64u(s) },
    key: b64u(k),
  };
}

const verifyEs256 = (jwt: Jwt, publicKey: Uint8Array): boolean =>
  verify(
    'sha256',
    Buffer.from(jwt.signed),
    { key: createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: toB64u(publicKey.slice(1, 33)), y: toB64u(publicKey.slice(33, 65)) }, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    jwt.signature,
  );

test('KBOX-22 the VAPID JWT verifies with an independent ES256 check and carries aud, exp, sub and the public key', () => {
  const result = vapidAuthorization({ sender: rfcSender, endpoint: new URL('https://updates.push.services.mozilla.com:443/wpush/v2/abc?x=1'), expiresAt: 1_800_000_000, subject: 'mailto:box@example.test' });
  assert.ok(result.ok);
  const { jwt, key } = parseAuthorization(result.value);
  assert.deepEqual(jwt.header, { typ: 'JWT', alg: 'ES256' });
  assert.deepEqual(jwt.claims, { aud: 'https://updates.push.services.mozilla.com', exp: 1_800_000_000, sub: 'mailto:box@example.test' }, 'aud is the endpoint origin, nothing of its path');
  assert.equal(jwt.signature.length, 64, 'RFC 7518 section 3.4: r||s, 64 octets, not DER');
  assert.deepEqual(key, RFC.asPublic);
  assert.equal(verifyEs256(jwt, RFC.asPublic), true);
  assert.equal(verifyEs256({ ...jwt, signed: `${jwt.signed}x` }, RFC.asPublic), false, 'a changed JWT does not verify');
  assert.equal(verifyEs256(jwt, RFC.uaPublic), false, 'another key does not verify');
});

test('KBOX-22 a VAPID header from a mismatched key pair is refused by fixed code', () => {
  const result = vapidAuthorization({ sender: { privateKey: RFC.asPrivate, publicKey: RFC.uaPublic }, endpoint: new URL('https://fcm.googleapis.com/x'), expiresAt: 1, subject: 'mailto:a@b.test' });
  assert.deepEqual(result, { ok: false, code: 'bad_key' });
});

// Receiver side of RFC 8291 section 3-4 and RFC 8188, written for the tests: the oracle that decrypts what the box sends.
function decryptAes128gcm(body: Uint8Array, uaPrivate: Uint8Array, uaPublic: Uint8Array, authSecret: Uint8Array): Uint8Array {
  const salt = body.slice(0, 16);
  const idlen = body[20];
  assert.equal(idlen, 65);
  const asPublic = body.slice(21, 21 + 65);
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(uaPrivate));
  const secret = ecdh.computeSecret(Buffer.from(asPublic));
  const ikm = Buffer.from(hkdfSync('sha256', secret, authSecret, Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]), 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const record = body.slice(21 + 65);
  const decipher = createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(Buffer.from(record.slice(record.length - 16)));
  const padded = Buffer.concat([decipher.update(record.slice(0, record.length - 16)), decipher.final()]);
  const end = padded.lastIndexOf(2);
  return Uint8Array.from(padded.subarray(0, end));
}

test('KBOX-22 the test-side decryption opens the RFC example, so it can stand as the oracle for what the box sends', () => {
  const opened = decryptAes128gcm(concat(RFC.header, RFC.ciphertext), RFC.uaPrivate, RFC.uaPublic, RFC.authSecret);
  assert.deepEqual(opened, RFC.plaintext);
});
