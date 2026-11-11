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
import { AUDIT_SCHEMAS, isAuditAction, parseObject } from '../src/pure/schemas.ts';
import type { Schema } from '../src/pure/schemas.ts';
import { createHttpPushTransport } from '../src/shell/push-transport.ts';
import { createPush } from '../src/shell/push.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';
import { FakeAudit } from './fakes/audit.ts';
import { TimedClock, canary, fakePlatform, seedFor, seededRandom, settle, tempDir, waitUntil } from './kit/index.ts';
import type { SeededRandom, Surface } from './kit/index.ts';

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
function decrypt(body: Uint8Array, uaPrivate: Uint8Array, uaPublic: Uint8Array, authSecret: Uint8Array): Uint8Array {
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
  const opened = decrypt(concat(RFC.header, RFC.ciphertext), RFC.uaPrivate, RFC.uaPublic, RFC.authSecret);
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

const HOSTS_SUB = GOOD_ENDPOINTS[0] ?? '';
const PAYLOAD_BYTES_MAX = 4096;

function subscribeAll(w: World, endpoints: readonly string[]): Browser[] {
  return endpoints.map((endpoint) => {
    const b = browser(w.rng);
    assert.deepEqual(w.push.subscribe(b.subscription(endpoint)), { ok: true });
    return b;
  });
}

/** What the box audited must be a closed row of the audit schemas, and name nothing about an endpoint. */
function assertClosedAudit(w: World, extra: Readonly<Record<string, Surface>> = {}): void {
  const events = w.audit.entries();
  for (const event of events) {
    assert.ok(isAuditAction(event.action), `${event.action} is a declared audit action`);
    assert.ok(parseObject(AUDIT_SCHEMAS[event.action] as Schema, event.detail ?? {}).ok, `${event.action} detail is closed: ${JSON.stringify(event.detail)}`);
  }
  canary().assertAbsent({ audit: JSON.stringify(events), ...extra });
}

test('KBOX-22 send posts to every subscription an aes128gcm body that only its browser can open, with TTL, Urgency and a VAPID Authorization', async (t) => {
  const w = await world(t);
  const [a, b] = subscribeAll(w, [GOOD_ENDPOINTS[0] ?? '', GOOD_ENDPOINTS[1] ?? '']);
  assert.ok(a !== undefined && b !== undefined);
  assert.equal(w.push.send({ title: 'Add key stripe-prod', kind: 'add_key' }), undefined);
  assert.equal(w.transport.sent.length, 2, 'both posts are made before send returns: nothing waits on the push service');
  const [first, second] = w.transport.sent;
  assert.ok(first !== undefined && second !== undefined);
  assert.equal(first.endpoint, GOOD_ENDPOINTS[0]);
  assert.equal(second.endpoint, GOOD_ENDPOINTS[1]);
  for (const [sent, receiver] of [[first, a], [second, b]] as const) {
    assert.equal(sent.headers['Content-Encoding'], 'aes128gcm');
    assert.match(sent.headers['TTL'] ?? '', /^[1-9]\d*$/);
    assert.ok(['very-low', 'low', 'normal', 'high'].includes(sent.headers['Urgency'] ?? ''), 'RFC 8030 section 5.3 urgency');
    assert.ok(sent.body.length <= PAYLOAD_BYTES_MAX);
    const opened = decrypt(sent.body, receiver.privateKey, receiver.publicKey, receiver.authSecret);
    assert.deepEqual(JSON.parse(Buffer.from(opened).toString('utf8')), { title: 'Add key stripe-prod', kind: 'add_key' });
  }
  assert.notDeepEqual(first.body.slice(0, 16), second.body.slice(0, 16), 'a fresh salt for every message');
  assert.notDeepEqual(first.body.slice(21, 86), second.body.slice(21, 86), 'a fresh ephemeral sender key for every message');
  const wrong = browser(w.rng);
  assert.throws(() => decrypt(first.body, wrong.privateKey, wrong.publicKey, wrong.authSecret), 'another browser cannot open it');
  await settle();
  assertClosedAudit(w);
});

test('KBOX-22 the VAPID header of a send verifies for the stored public key, names the endpoint origin and expires within a day', async (t) => {
  const w = await world(t);
  subscribeAll(w, [GOOD_ENDPOINTS[3] ?? '']);
  w.push.send({ title: 'Enrol', kind: 'enrol', count: 2 });
  const sent = w.transport.sent[0];
  assert.ok(sent !== undefined);
  const { jwt, key } = parseAuthorization(sent.headers['Authorization'] ?? '');
  const stored = w.store.getVapidKeyPair();
  assert.ok(stored !== undefined);
  assert.deepEqual(key, b64u(stored.publicKey));
  assert.equal(verifyEs256(jwt, key), true);
  assert.equal(jwt.claims['aud'], 'https://db5p.notify.windows.com');
  assert.equal(jwt.claims['sub'], 'mailto:box@example.test');
  const now = w.clock.now() / 1000;
  assert.ok(typeof jwt.claims['exp'] === 'number' && jwt.claims['exp'] > now && jwt.claims['exp'] <= now + 24 * 3600, 'RFC 8292 section 2: exp is within 24 hours');
});

test('KBOX-22 the VAPID key pair is made once, kept only in the private store and reused by the next start', async (t) => {
  const w = await world(t);
  subscribeAll(w, [HOSTS_SUB]);
  assert.equal(w.store.getVapidKeyPair(), undefined, 'nothing is generated before the first send');
  w.push.send({ title: 'x', kind: 'enrol' });
  const pair = w.store.getVapidKeyPair();
  assert.ok(pair !== undefined);
  assert.equal(b64u(pair.privateKey).length, 32);
  assert.equal(b64u(pair.publicKey).length, 65);
  w.push.send({ title: 'y', kind: 'enrol' });
  const restarted = createPush({ store: w.store, transport: w.transport, scheduler: w.clock, clock: w.clock, random: w.rng, audit: w.audit, subject: 'mailto:box@example.test' });
  restarted.send({ title: 'z', kind: 'enrol' });
  const keys = w.transport.sent.map((s) => toB64u(parseAuthorization(s.headers['Authorization'] ?? '').key));
  assert.equal(keys.length, 3);
  assert.deepEqual(new Set(keys), new Set([pair.publicKey]));
  assert.deepEqual(w.store.getVapidKeyPair(), pair);
});

test('KBOX-22 a payload never contains more than title, kind and count, whatever the caller handed in', async (t) => {
  const w = await world(t);
  const [b] = subscribeAll(w, [HOSTS_SUB]);
  assert.ok(b !== undefined);
  const wider = { title: 'T', kind: 'enrol', count: 3, url: 'https://box.example.test/approve/1', value: 'hunter2', requester: 'free text' };
  w.push.send(wider);
  w.push.send({ title: 'only', kind: 'recovery' });
  const [one, two] = w.transport.sent.map((s) => JSON.parse(Buffer.from(decrypt(s.body, b.privateKey, b.publicKey, b.authSecret)).toString('utf8')) as Record<string, unknown>);
  assert.deepEqual(one, { title: 'T', kind: 'enrol', count: 3 });
  assert.deepEqual(two, { title: 'only', kind: 'recovery' }, 'no count member when there is no count');
  assert.deepEqual(Object.keys(two ?? {}).sort(), ['kind', 'title']);
});

test('KBOX-22 a 404 or 410 answer removes that subscription and only that one; other answers keep it', async (t) => {
  const w = await world(t);
  const endpoints = GOOD_ENDPOINTS.slice(0, 4);
  subscribeAll(w, endpoints);
  const answers = new Map<string, number>([
    [endpoints[0] ?? '', 410],
    [endpoints[1] ?? '', 404],
    [endpoints[2] ?? '', 201],
    [endpoints[3] ?? '', 429],
  ]);
  w.transport.answer = (endpoint) => Promise.resolve(answers.get(endpoint) ?? 0);
  w.push.send({ title: 'x', kind: 'enrol' });
  await waitUntil(() => w.audit.entries().length === 4, 'four outcomes audited');
  assert.deepEqual(w.store.listPushSubscriptions().map((s) => s.endpoint), [endpoints[2], endpoints[3]]);
  assert.deepEqual(w.audit.entries().map((e) => e.action).sort(), ['push.delivered', 'push.failed', 'push.subscription_removed', 'push.subscription_removed']);
  assertClosedAudit(w);
});

/** The real HTTP adapter, pointed at a loopback fake instead of the push service the endpoint names (the endpoint's path is kept). */
class LoopbackTransport implements PushTransport {
  readonly signals: AbortSignal[] = [];
  readonly #platformUrl: string;
  readonly #real = createHttpPushTransport();

  constructor(platformUrl: string) {
    this.#platformUrl = platformUrl;
  }

  post(endpoint: URL, headers: Readonly<Record<string, string>>, body: Uint8Array, signal: AbortSignal): Promise<number> {
    this.signals.push(signal);
    return this.#real.post(new URL(`${endpoint.pathname}${endpoint.search}`, this.#platformUrl), headers, body, signal);
  }
}

const SEND_TIMEOUT_MS = 10_000;

test('KBOX-22 a push service answering 500 gets one request, nothing is retried and the subscription is kept (real HTTP adapter, loopback fake)', async (t) => {
  const platform = await fakePlatform(t);
  await platform.setMode('500');
  const w = await world(t, new LoopbackTransport(platform.url));
  subscribeAll(w, [HOSTS_SUB]);
  w.push.send({ title: 'x', kind: 'enrol' });
  await waitUntil(() => w.audit.entries().length === 1, 'the 500 audited');
  w.clock.advance(24 * 3600 * 1000);
  await settle();
  assert.equal(platform.requests.length, 1, 'one POST, no retry');
  assert.equal(platform.requests[0]?.method, 'POST');
  assert.equal(platform.requests[0]?.headers['content-encoding'], 'aes128gcm');
  assert.equal(w.store.listPushSubscriptions().length, 1);
  assert.deepEqual(w.audit.entries().map((e) => [e.action, e.detail]), [['push.failed', { code: 'bad_status', status: 500 }]]);
  assertClosedAudit(w);
});

test('KBOX-22 a push service that never answers is aborted at 10 s of scheduler time and send never waits for it (real HTTP adapter, loopback fake)', async (t) => {
  const platform = await fakePlatform(t);
  await platform.setMode('hang');
  const loopback = new LoopbackTransport(platform.url);
  const w = await world(t, loopback);
  subscribeAll(w, [HOSTS_SUB]);
  const arrived = platform.nextRequest();
  w.push.send({ title: 'x', kind: 'enrol' });
  await arrived;
  const [signal] = loopback.signals;
  assert.ok(signal !== undefined);
  assert.equal(w.clock.pendingTimers, 1, 'one timeout is set for the one send');
  w.clock.advance(SEND_TIMEOUT_MS - 1);
  await settle();
  assert.equal(signal.aborted, false, 'not aborted before 10 s');
  assert.equal(w.audit.entries().length, 0);
  w.clock.advance(1);
  assert.equal(signal.aborted, true, 'aborted at 10 s');
  await waitUntil(() => w.audit.entries().length === 1, 'the abort audited');
  assert.deepEqual(w.audit.entries().map((e) => [e.action, e.detail]), [['push.failed', { code: 'timeout' }]]);
  assert.equal(w.store.listPushSubscriptions().length, 1, 'a hang does not drop the subscription');
  assert.equal(w.clock.pendingTimers, 0);
  assertClosedAudit(w);
});

test('KBOX-22 a hung push service for one subscription does not hold up the others', async (t) => {
  const w = await world(t);
  const endpoints = GOOD_ENDPOINTS.slice(0, 3);
  subscribeAll(w, endpoints);
  w.transport.answer = (endpoint) => (endpoint === endpoints[0] ? new Promise<number>(() => undefined) : Promise.resolve(201));
  w.push.send({ title: 'x', kind: 'enrol' });
  assert.equal(w.transport.sent.length, 3, 'the post to the second subscription does not wait for the first');
  await waitUntil(() => w.audit.entries().length === 2, 'the two answered ones audited');
});

test('KBOX-22 a refused connection is audited by code and send neither throws nor reports it to the caller (real HTTP adapter, loopback fake)', async (t) => {
  const platform = await fakePlatform(t);
  await platform.setMode('refuse');
  const w = await world(t, new LoopbackTransport(platform.url));
  subscribeAll(w, [HOSTS_SUB]);
  assert.doesNotThrow(() => w.push.send({ title: 'x', kind: 'enrol' }));
  await waitUntil(() => w.audit.entries().length === 1, 'the failure audited');
  assert.deepEqual(w.audit.entries().map((e) => [e.action, e.detail]), [['push.failed', { code: 'transport_failed' }]]);
  assert.equal(w.store.listPushSubscriptions().length, 1);
  assert.equal(w.clock.pendingTimers, 0, 'the timeout is cancelled when the call ends');
  assertClosedAudit(w);
});

test('KBOX-22 a redirect from a push service is not followed and counts as a bad status (real HTTP adapter, loopback fake)', async (t) => {
  const platform = await fakePlatform(t);
  await platform.setMode('redirect');
  const w = await world(t, new LoopbackTransport(platform.url));
  subscribeAll(w, [HOSTS_SUB]);
  w.push.send({ title: 'x', kind: 'enrol' });
  await waitUntil(() => w.audit.entries().length === 1, 'the redirect audited');
  assert.equal(platform.requests.length, 1, 'the Location was not fetched');
  assert.deepEqual(w.audit.entries().map((e) => [e.action, e.detail]), [['push.failed', { code: 'bad_status', status: 302 }]]);
});

test('KBOX-22 send never throws when the transport throws at once, rejects with text, or the store is closed; the audit holds codes only', async (t) => {
  const planted = canary();
  const secretText = Buffer.from(planted.bytes).toString('base64url');
  const w = await world(t);
  subscribeAll(w, [`https://fcm.googleapis.com/fcm/send/${secretText}`]);
  w.transport.answer = () => {
    throw new Error(`boom ${secretText}`);
  };
  assert.doesNotThrow(() => w.push.send({ title: 'x', kind: 'enrol' }));
  w.transport.answer = () => Promise.reject(new Error(`rejected ${secretText}`));
  assert.doesNotThrow(() => w.push.send({ title: 'x', kind: 'enrol' }));
  await waitUntil(() => w.audit.entries().length === 2, 'both failures audited');
  assert.deepEqual(w.audit.entries().map((e) => e.detail), [{ code: 'transport_failed' }, { code: 'transport_failed' }]);
  const closed = openPrivateDatabase(join(w.dir, 'closed.db'));
  closed.close();
  const broken = createPush({ store: closed, transport: w.transport, scheduler: w.clock, clock: w.clock, random: w.rng, audit: w.audit, subject: 'mailto:box@example.test' });
  assert.doesNotThrow(() => broken.send({ title: 'x', kind: 'enrol' }));
  assert.deepEqual(w.audit.entries().map((e) => e.detail).at(-1), { code: 'store_failed' });
  assertClosedAudit(w);
  planted.assertAbsent({ audit: JSON.stringify(w.audit.entries()) });
});

test('KBOX-22 send with no subscriptions does nothing and a malformed stored subscription is skipped by code without stopping the others', async (t) => {
  const w = await world(t);
  w.push.send({ title: 'x', kind: 'enrol' });
  assert.equal(w.transport.sent.length, 0);
  const [good] = subscribeAll(w, [GOOD_ENDPOINTS[1] ?? '']);
  assert.ok(good !== undefined);
  w.store.addPushSubscription({ endpoint: GOOD_ENDPOINTS[0] ?? '', p256dh: 'AAAA', auth: 'AAAA' });
  w.push.send({ title: 'x', kind: 'enrol' });
  assert.deepEqual(w.transport.sent.map((s) => s.endpoint), [GOOD_ENDPOINTS[1]], 'the good one still gets its push');
  assert.deepEqual(w.audit.entries().map((e) => [e.action, e.detail]), [['push.failed', { code: 'bad_secret' }]]);
});
