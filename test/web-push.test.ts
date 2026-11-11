// KBOX-22: how the owner learns something waits. Web Push from the box itself: RFC 8291 payload encryption, RFC 8292 VAPID.
import assert from 'node:assert/strict';
import { createDecipheriv, createECDH, createPublicKey, hkdfSync, verify } from 'node:crypto';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { PrivateStore } from '../src/ports/private.ts';
import type { Push, PushSubscriptionInput, PushSubscriptions, PushTransport } from '../src/ports/push.ts';
import { encryptPayload, vapidAuthorization } from '../src/pure/pushcrypto.ts';
import type { P256KeyPair } from '../src/pure/pushcrypto.ts';
import { createPush } from '../src/shell/push.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';
import { FakeAudit } from './fakes/audit.ts';
import { TimedClock, seedFor, seededRandom, tempDir } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';

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

// --- the shell: subscriptions, send ---------------------------------------------------------------------------------

interface Browser {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly authSecret: Uint8Array;
  subscription(endpoint: string): PushSubscriptionInput;
}

/** A browser's side of a subscription: its own P-256 key pair and 16-byte auth secret, drawn from the test's seeded stream. */
function browser(rng: SeededRandom): Browser {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(rng.bytes(32)));
  const privateKey = Uint8Array.from(ecdh.getPrivateKey());
  const publicKey = Uint8Array.from(ecdh.getPublicKey());
  const authSecret = rng.bytes(16);
  return { privateKey, publicKey, authSecret, subscription: (endpoint) => ({ endpoint, p256dh: toB64u(publicKey), auth: toB64u(authSecret) }) };
}

const seed = seedFor(process.env);

interface Sent {
  readonly endpoint: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

/** A PushTransport that answers what the test says and records what it was given. */
class ScriptedTransport implements PushTransport {
  readonly sent: Sent[] = [];
  readonly signals: AbortSignal[] = [];
  answer: (endpoint: string) => Promise<number> = () => Promise.resolve(201);

  post(endpoint: URL, headers: Readonly<Record<string, string>>, body: Uint8Array, signal: AbortSignal): Promise<number> {
    this.sent.push({ endpoint: endpoint.href, headers, body });
    this.signals.push(signal);
    return this.answer(endpoint.href);
  }
}

interface World {
  readonly store: PrivateStore;
  readonly transport: ScriptedTransport;
  readonly clock: TimedClock;
  readonly audit: FakeAudit;
  readonly push: Push & PushSubscriptions;
  readonly rng: SeededRandom;
  readonly dir: string;
}

async function world(t: TestContext, transport: PushTransport = new ScriptedTransport()): Promise<World> {
  const dir = await tempDir(t);
  const store = openPrivateDatabase(join(dir, 'private.db'));
  t.after(() => store.close());
  const clock = new TimedClock(1_700_000_000_000);
  const audit = new FakeAudit();
  const rng = seededRandom(seed);
  const push = createPush({ store, transport, scheduler: clock, clock, random: rng, audit, subject: 'mailto:box@example.test' });
  return { store, transport: transport as ScriptedTransport, clock, audit, push, rng, dir };
}

const GOOD_ENDPOINTS = [
  'https://fcm.googleapis.com/fcm/send/abc',
  'https://updates.push.services.mozilla.com/wpush/v2/abc',
  'https://web.push.apple.com/QAbc',
  'https://db5p.notify.windows.com/?token=abc',
  'https://a.b.notify.windows.com/w/?token=abc',
];

test('KBOX-22 a subscription on a push service host over https is accepted and stored', async (t) => {
  const w = await world(t);
  const b = browser(w.rng);
  for (const endpoint of GOOD_ENDPOINTS) assert.deepEqual(w.push.subscribe(b.subscription(endpoint)), { ok: true }, endpoint);
  assert.deepEqual(
    w.store.listPushSubscriptions().map((s) => s.endpoint).sort(),
    [...GOOD_ENDPOINTS].sort(),
  );
});

test('KBOX-22 a subscription endpoint on another host, over http, on an IP literal, with a port, with userinfo or on a bare wildcard domain is refused', async (t) => {
  const w = await world(t);
  const b = browser(w.rng);
  const refused = [
    'https://example.com/push',
    'https://fcm.googleapis.com.evil.test/x',
    'https://evilfcm.googleapis.com/x',
    'https://sub.fcm.googleapis.com/x',
    'http://fcm.googleapis.com/x',
    'https://127.0.0.1/x',
    'https://192.0.2.7/x',
    'https://[::1]/x',
    'https://[2001:db8::1]/x',
    'https://fcm.googleapis.com:8443/x',
    'https://user:pass@fcm.googleapis.com/x',
    'https://user@fcm.googleapis.com/x',
    'https://notify.windows.com/x',
    'https://xnotify.windows.com/x',
    'https://fcm.googleapis.com./x',
    'wss://fcm.googleapis.com/x',
    'fcm.googleapis.com/x',
    '',
    'not a url',
  ];
  for (const endpoint of refused) assert.deepEqual(w.push.subscribe(b.subscription(endpoint)), { ok: false, code: 'bad_endpoint' }, endpoint);
  assert.equal(w.push.subscribe(b.subscription('https://fcm.googleapis.com:443/x')).ok, true, 'port 443 written out is the https port');
  assert.deepEqual(w.store.listPushSubscriptions().map((s) => s.endpoint), ['https://fcm.googleapis.com/x'], 'only the accepted one is stored');
});

test('KBOX-22 a subscription key that is not a 65-byte uncompressed P-256 point, or an auth that is not 16 bytes, is refused', async (t) => {
  const w = await world(t);
  const b = browser(w.rng);
  const endpoint = GOOD_ENDPOINTS[0] ?? '';
  const sub = b.subscription(endpoint);
  const code = (over: Partial<PushSubscriptionInput>): unknown => w.push.subscribe({ ...sub, ...over });
  const bad = { ok: false, code: 'bad_key' };
  assert.deepEqual(code({ p256dh: toB64u(b.publicKey.slice(0, 64)) }), bad, '64 bytes');
  assert.deepEqual(code({ p256dh: toB64u(concat(b.publicKey, new Uint8Array(1))) }), bad, '66 bytes');
  assert.deepEqual(code({ p256dh: toB64u(concat(Uint8Array.from([2]), b.publicKey.slice(1, 33))) }), bad, 'a compressed point');
  assert.deepEqual(code({ p256dh: toB64u(concat(Uint8Array.from([4]), new Uint8Array(64).fill(1))) }), bad, 'a point off the curve');
  assert.deepEqual(code({ p256dh: `${sub.p256dh}=` }), bad, 'padded base64');
  assert.deepEqual(code({ p256dh: sub.p256dh.replace(/[-_]/, '+') }), bad, 'standard-alphabet base64');
  assert.deepEqual(code({ p256dh: '' }), bad);
  assert.deepEqual(code({ auth: toB64u(b.authSecret.slice(0, 15)) }), bad, '15 bytes');
  assert.deepEqual(code({ auth: toB64u(concat(b.authSecret, new Uint8Array(1))) }), bad, '17 bytes');
  assert.deepEqual(code({ auth: '' }), bad);
  assert.deepEqual(w.store.listPushSubscriptions(), []);
});
