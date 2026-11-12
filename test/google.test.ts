// KBOX-41 (identity half): the box's own OIDC identity toward Google Cloud. The discovery document and JWKS, the ES256 assertion with fixed
// claims checked by an independent verifier (WebCrypto, in the test and in the fake STS), the impersonation target read from the key's stored
// `sa:` scope item (never from `projects`), the minter (STS exchange, then generateAccessToken for that one target with only the profile's
// scopes, never `cloud-platform` for the relay; the admin token for `kbox-keys@<the call's stored project>`), the minted tokens held by the
// scanner while they live (KBOX-14), and failures mapped to fixed codes that never carry a platform's text or a value.
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { inspect } from 'node:util';
import type { MintedSink } from '../src/ports/minted.ts';
import type { BoxIdentity, RegistryDeps, StoredKey } from '../src/ports/platform.ts';
import type { Lent } from '../src/ports/types.ts';
import { matchesShape } from '../src/pure/class.ts';
import { assess } from '../src/pure/coverage.ts';
import { GoogleError } from '../src/platforms/google/errors.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { MINTED_LIFETIME_S, createMinter } from '../src/platforms/google/minter.ts';
import type { MintRequest } from '../src/platforms/google/minter.ts';
import { ASSERTION_LIFETIME_S, BOX_SUBJECT, discoveryDocument, jwksDocument, signAssertion } from '../src/platforms/google/oidc.ts';
import { actsAs, targetOf } from '../src/platforms/google/scope.ts';
import { SIGNING_KEY_SHAPE } from '../src/platforms/google/signing-key.ts';
import { createRelayRegistry } from '../src/platforms/registry.ts';
import { fakeGoogle } from './fakes/google.ts';
import type { FakeGoogle, TrustedJwk } from './fakes/google.ts';
import { FakeClock, adapterHttpTo, bytesOf, canary, lent } from './kit/index.ts';
import type { FakeAdapterHttp } from './kit/index.ts';

const NOW = 1_700_000_000_000;
const PROVIDER = '//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-oidc';
const IDENTITY: BoxIdentity = { issuer: 'https://keys.box.example', audience: PROVIDER };
/** Key A acts as SA in kbox-test-proj; key B as OTHER_SA in kbox-test-two. */
const A = 'google/kbox-test-proj/FIRESTORE';
const B = 'google/kbox-test-two/OTHER';
const SA = 'kbox-test-relay@kbox-test-proj.iam.gserviceaccount.com';
const OTHER_SA = 'kbox-test-other@kbox-test-two.iam.gserviceaccount.com';
const ADMIN_ONE = 'kbox-keys@kbox-test-proj.iam.gserviceaccount.com';
const ADMIN_TWO = 'kbox-keys@kbox-test-two.iam.gserviceaccount.com';
const DATASTORE = 'https://www.googleapis.com/auth/datastore';
const STORAGE = 'https://www.googleapis.com/auth/devstorage.read_write';
const CLOUD_PLATFORM = 'https://www.googleapis.com/auth/cloud-platform';
const READ_ONLY = 'https://www.googleapis.com/auth/cloud-platform.read-only';
const STORED: ReadonlyMap<string, StoredKey> = new Map([
  [A, { scopeItems: ['sa:kbox-test-proj/kbox-test-relay'], location: {} }],
  [B, { scopeItems: ['sa:kbox-test-two/kbox-test-other'], location: {} }],
]);

/** A signing key as the vault holds it: the P-256 private scalar, 43 base64url characters, derived from a fixed test seed. */
interface TestKey {
  readonly value: string;
  readonly lent: Lent;
  /** The public half, computed here on the test's own path (OpenSSL ECDH), not by the code under test. */
  readonly x: string;
  readonly y: string;
  /** RFC 7638 thumbprint, computed here. */
  readonly kid: string;
}

function testKey(seed: string): TestKey {
  const d = createHash('sha256').update(`kbox-test-signing-${seed}`).digest();
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  const kid = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url');
  const value = d.toString('base64url');
  return { value, lent: lent(Buffer.from(value), `google/box/SIGNING:${seed}`), x, y, kid };
}

const KEY = testKey('1');
const NEXT_KEY = testKey('2');
const trusted = (k: TestKey): TrustedJwk => ({ kid: k.kid, kty: 'EC', crv: 'P-256', x: k.x, y: k.y });

interface Recorded {
  readonly keyref: string;
  readonly value: string;
  readonly expiresAt: number;
}

function recordingSink(): MintedSink & { readonly added: Recorded[] } {
  const added: Recorded[] = [];
  return { added, add: (keyref, value, expiresAt) => void added.push({ keyref, value: Buffer.from(value).toString('utf8'), expiresAt }) };
}

interface World {
  readonly google: FakeGoogle;
  readonly http: FakeAdapterHttp;
  readonly sink: ReturnType<typeof recordingSink>;
  /** Every keyref the minter reported a successful mint exchange for (KBOX-55 `onExchanged`), in order. */
  readonly exchanged: readonly string[];
  mint(request: MintRequest): ReturnType<ReturnType<typeof createMinter>['mint']>;
  federate(identity: BoxIdentity, key: Lent): ReturnType<ReturnType<typeof createMinter>['federate']>;
}

/** The minter over a fake Google that trusts KEY and lets the box impersonate both stored targets and both projects' kbox-keys. */
async function world(t: TestContext, options: { readonly keyInfo?: RegistryDeps['keyInfo']; readonly omit?: 'identity' | 'minted' | 'keyInfo' } = {}): Promise<World> {
  const google = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  google.trust([trusted(KEY)]);
  google.creatorOn([SA, OTHER_SA, ADMIN_ONE, ADMIN_TWO]);
  const http = adapterHttpTo(google);
  const sink = recordingSink();
  const exchanged: string[] = [];
  const minter = createMinter({
    http,
    clock: new FakeClock(NOW),
    onExchanged: (keyref) => void exchanged.push(keyref),
    ...(options.omit === 'identity' ? {} : { identity: IDENTITY }),
    ...(options.omit === 'minted' ? {} : { minted: sink }),
    ...(options.omit === 'keyInfo' ? {} : { keyInfo: options.keyInfo ?? ((keyref: string) => STORED.get(keyref)) }),
  });
  return { google, http, sink, exchanged, mint: (request) => minter.mint(request, KEY.lent), federate: (identity, key) => minter.federate(identity, key) };
}

const relay = (patch: Partial<Extract<MintRequest, { use: 'relay' }>> = {}): MintRequest => ({ use: 'relay', keyref: A, scopes: [DATASTORE], profileScopes: [DATASTORE, STORAGE], ...patch });

const segment = (s: string | undefined): Record<string, unknown> => JSON.parse(Buffer.from(s ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;

/** Every place a thrown error could show text: its message, name, string form, JSON, inspection and cause. */
const surfacesOf = (error: unknown): Record<string, string> => ({
  message: error instanceof Error ? error.message : '',
  string: String(error),
  json: JSON.stringify(error) ?? '',
  inspect: inspect(error, { depth: 5 }),
  cause: error instanceof Error ? inspect(error.cause) : '',
});

async function refusal(promise: Promise<unknown>): Promise<GoogleError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof GoogleError, `a GoogleError, got ${inspect(error)}`);
    return error;
  }
  throw new assert.AssertionError({ message: 'expected a refusal' });
}

const impersonated = (w: World): string[] =>
  w.http.sent.filter((s) => s.originalHost === 'iamcredentials.googleapis.com').map((s) => /serviceAccounts\/([^:]+):generateAccessToken$/.exec(s.target)?.[1] ?? s.target);

// --- the OIDC documents ---------------------------------------------------------------------------------------------------------------

test('KBOX-41 the discovery document names the issuer, a JWKS under it and ES256 as the only signing algorithm', () => {
  const doc = discoveryDocument('https://keys.box.example');
  assert.equal(doc['issuer'], 'https://keys.box.example');
  assert.equal(doc['jwks_uri'], 'https://keys.box.example/.well-known/jwks.json');
  assert.deepEqual(doc['id_token_signing_alg_values_supported'], ['ES256']);
  assert.deepEqual(doc['subject_types_supported'], ['public']);
  assert.deepEqual(doc['response_types_supported'], ['id_token']);
});

test('KBOX-41 the JWKS lists each signing key as a public P-256 key with its RFC 7638 thumbprint as kid, and never the private part', async () => {
  const jwks = await jwksDocument([KEY.lent, NEXT_KEY.lent]);
  assert.deepEqual(jwks, {
    keys: [
      { kty: 'EC', crv: 'P-256', x: KEY.x, y: KEY.y, kid: KEY.kid, alg: 'ES256', use: 'sig' },
      { kty: 'EC', crv: 'P-256', x: NEXT_KEY.x, y: NEXT_KEY.y, kid: NEXT_KEY.kid, alg: 'ES256', use: 'sig' },
    ],
  });
  assert.equal(JSON.stringify(jwks).includes(KEY.value), false, 'the private scalar is not in the document');
});

test('KBOX-41 the assertion is an ES256 JWT that an independent verifier (WebCrypto) accepts with the JWKS key its kid names', async () => {
  const jwt = await signAssertion(IDENTITY, KEY.lent, NOW);
  const [h, p, s, extra] = jwt.split('.');
  assert.equal(extra, undefined);
  assert.deepEqual(segment(h), { alg: 'ES256', typ: 'JWT', kid: KEY.kid });
  const [jwk] = (await jwksDocument([KEY.lent])).keys;
  assert.ok(jwk !== undefined);
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(s ?? '', 'base64url'), Buffer.from(`${h}.${p}`)), true);
  const other = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: NEXT_KEY.x, y: NEXT_KEY.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, other, Buffer.from(s ?? '', 'base64url'), Buffer.from(`${h}.${p}`)), false, 'another key does not verify it');
});

test('KBOX-41 the assertion carries exactly the fixed claims: iss, sub, the provider as audience, iat and a short exp', async () => {
  const jwt = await signAssertion(IDENTITY, KEY.lent, NOW + 999);
  const iat = Math.floor((NOW + 999) / 1000);
  assert.deepEqual(segment(jwt.split('.')[1]), { iss: 'https://keys.box.example', sub: BOX_SUBJECT, aud: `https:${PROVIDER}`, iat, exp: iat + ASSERTION_LIFETIME_S });
  assert.ok(ASSERTION_LIFETIME_S > 0 && ASSERTION_LIFETIME_S <= 600, 'a short JWT (Google allows up to 24 h; the box asks minutes)');
});

test('KBOX-41 a request to change the audience or the subject of the assertion is refused', async () => {
  for (const asked of [{ audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/other/providers/other' }, { subject: 'someone-else' }, { audience: PROVIDER, subject: 'x' }]) {
    const error = await refusal(signAssertion(IDENTITY, KEY.lent, NOW, asked));
    assert.equal(error.code, 'claims_fixed');
  }
});

test('KBOX-41 an identity whose audience is not a workload identity provider is refused before anything is signed', async () => {
  for (const audience of ['https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q', '//iam.googleapis.com/projects/abc/locations/global/workloadIdentityPools/pool/providers/prov', `${PROVIDER}/extra`, '']) {
    const error = await refusal(signAssertion({ ...IDENTITY, audience }, KEY.lent, NOW));
    assert.equal(error.code, 'identity_malformed');
  }
});

test('KBOX-41 KBOX-18 a signing key that is not a 43-character base64url P-256 scalar is refused with a fixed code that does not carry it', async () => {
  const bad = ['A'.repeat(42), `${KEY.value}A`, `${KEY.value.slice(0, 42)}+`, `${KEY.value.slice(0, 42)}=`, 'A'.repeat(43)];
  for (const value of bad) {
    const error = await refusal(signAssertion(IDENTITY, lent(Buffer.from(value), 'bad:1'), NOW));
    assert.equal(error.code, 'signing_key_unreadable');
    for (const [where, text] of Object.entries(surfacesOf(error))) assert.equal(text.includes(value), false, `the value is not in the error's ${where}`);
  }
});

test('KBOX-18 the signing key shape takes a real-format key and refuses near misses; a box-made key is watched windowed', () => {
  assert.equal(matchesShape(SIGNING_KEY_SHAPE, KEY.value), true);
  assert.equal(matchesShape(SIGNING_KEY_SHAPE, KEY.value.slice(0, 42)), false, 'short core');
  assert.equal(matchesShape(SIGNING_KEY_SHAPE, `${KEY.value}A`), false, 'long core');
  assert.equal(matchesShape(SIGNING_KEY_SHAPE, `${KEY.value.slice(0, 42)}/`), false, 'wrong alphabet');
  assert.equal(assess({ shape: SIGNING_KEY_SHAPE, value: KEY.value, origin: 'pasted' }).tier, 'windowed');
});

// --- the target: one `sa:` item of the stored scope ----------------------------------------------------------------------------------

test('KBOX-41 targetOf: exactly one well-formed sa:<project>/<account> item names the service account; none or several is target_count', () => {
  assert.deepEqual(targetOf(['sa:kbox-test-proj/kbox-test-relay']), { ok: true, target: { email: SA, project: 'kbox-test-proj' } });
  assert.deepEqual(targetOf(['api:firestore.googleapis.com', 'sa:kbox-test-two/kbox-test-other']), { ok: true, target: { email: OTHER_SA, project: 'kbox-test-two' } });
  for (const items of [[], ['api:firestore.googleapis.com'], ['sa:kbox-test-proj/kbox-test-relay', 'sa:kbox-test-two/kbox-test-other'], ['sa:kbox-test-proj/kbox-test-relay', 'sa:kbox-test-proj/kbox-test-relay']]) {
    assert.deepEqual(targetOf(items), { ok: false, code: 'target_count' }, JSON.stringify(items));
  }
});

test('KBOX-41 targetOf: each part is 6 to 30 characters, a lower-case letter first, no hyphen last; anything else is target_malformed', () => {
  const ok = (project: string, account: string): void => assert.deepEqual(targetOf([`sa:${project}/${account}`]), { ok: true, target: { email: `${account}@${project}.iam.gserviceaccount.com`, project } });
  const malformed = (item: string): void => assert.deepEqual(targetOf([item]), { ok: false, code: 'target_malformed' }, item);
  ok('a12345', 'b-2345');
  ok(`p${'x'.repeat(28)}9`, `a${'y'.repeat(28)}z`);
  for (const item of [
    'sa:a1234/kbox-test-relay',
    `sa:p${'x'.repeat(29)}9/kbox-test-relay`,
    'sa:kbox-test-proj/b2345',
    `sa:kbox-test-proj/a${'y'.repeat(29)}z`,
    'sa:1box-test-proj/kbox-test-relay',
    'sa:Kbox-test-proj/kbox-test-relay',
    'sa:kbox-test-proj/kbox-test-relay-',
    'sa:kbox-test-proj-/kbox-test-relay',
    'sa:kbox-test-proj',
    'sa:/kbox-test-relay',
    'sa:kbox-test-proj/kbox-test-relay/x',
    'sa:kbox-test-proj/kbox-test-relay@kbox-test-proj.iam.gserviceaccount.com',
    'sa:kbox_test_proj/kbox-test-relay',
    'sa:',
  ]) {
    malformed(item);
  }
});

test('KBOX-41 targetOf: the box\'s own admin account kbox-keys is never a key\'s target (target_reserved)', () => {
  assert.deepEqual(targetOf(['sa:kbox-test-proj/kbox-keys']), { ok: false, code: 'target_reserved' });
  assert.deepEqual(targetOf(['sa:kbox-test-proj/kbox-keys2']), { ok: true, target: { email: 'kbox-keys2@kbox-test-proj.iam.gserviceaccount.com', project: 'kbox-test-proj' } });
});

test('KBOX-24 actsAs: a scope with any item starting sa:, well-formed or not, makes the box act as a service account', () => {
  assert.equal(actsAs(['sa:kbox-test-proj/kbox-test-relay']), true);
  assert.equal(actsAs(['api:firestore.googleapis.com', 'sa:']), true, 'a malformed sa: item still acts (fail closed)');
  assert.equal(actsAs([]), false);
  assert.equal(actsAs(['api:firestore.googleapis.com']), false);
  assert.equal(actsAs(['xsa:kbox-test-proj/kbox-test-relay', 'SA:kbox-test-proj/kbox-test-relay']), false);
});

// --- the minter ----------------------------------------------------------------------------------------------------------------------

test('KBOX-41 the minter exchanges a fresh assertion at STS with the verified field names, then asks generateAccessToken for the key\'s stored target with only the asked scopes', async (t) => {
  const w = await world(t);
  const minted = await w.mint(relay({ scopes: [DATASTORE, STORAGE] }));
  assert.deepEqual(
    w.http.sent.map((s) => `${s.method} ${s.originalHost}${s.target}`),
    ['POST sts.googleapis.com/v1/token', `POST iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SA}:generateAccessToken`],
  );
  const [sts, impersonate] = w.http.sent;
  assert.ok(sts !== undefined && impersonate !== undefined);
  assert.equal(sts.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(sts.headers['authorization'], undefined, 'STS takes no credential but the assertion');
  const form = new URLSearchParams(Buffer.from(sts.body).toString('utf8'));
  assert.deepEqual([...form.keys()].sort(), ['audience', 'grant_type', 'requested_token_type', 'scope', 'subject_token', 'subject_token_type']);
  assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
  assert.equal(form.get('audience'), PROVIDER);
  assert.equal(form.get('requested_token_type'), 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(form.get('subject_token_type'), 'urn:ietf:params:oauth:token-type:jwt');
  assert.equal(form.get('scope'), CLOUD_PLATFORM, 'the federated token, used only inside core for the one generateAccessToken call');
  assert.deepEqual(w.google.lastClaims, { iss: IDENTITY.issuer, sub: BOX_SUBJECT, aud: `https:${PROVIDER}`, iat: NOW / 1000, exp: NOW / 1000 + ASSERTION_LIFETIME_S });
  assert.equal(impersonate.headers['authorization'], 'Bearer kbox-test-federated-1');
  assert.equal(impersonate.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(Buffer.from(impersonate.body).toString('utf8')), { scope: [DATASTORE, STORAGE], lifetime: `${MINTED_LIFETIME_S}s` });
  assert.equal(Buffer.from(await bytesOf(minted.token)).toString('utf8'), 'ya29.kbox-test-sa-2');
  assert.deepEqual(minted.target, { email: SA, project: 'kbox-test-proj' });
});

test('KBOX-41 KBOX-14 both minted tokens join the scanner\'s match set before the token is handed out, each until it expires', async (t) => {
  const w = await world(t);
  const minted = await w.mint(relay());
  assert.deepEqual(w.sink.added, [
    { keyref: A, value: 'kbox-test-federated-1', expiresAt: NOW + 3599_000 },
    { keyref: A, value: 'ya29.kbox-test-sa-2', expiresAt: Date.parse('2023-11-14T23:13:20Z') },
  ]);
  assert.equal(minted.expiresAt, Date.parse('2023-11-14T23:13:20Z'));
});

test('KBOX-41 each key mints only for its own stored target: key A gets A\'s service account while key B is stored, and B gets B\'s', async (t) => {
  const w = await world(t);
  assert.deepEqual((await w.mint(relay())).target, { email: SA, project: 'kbox-test-proj' });
  assert.deepEqual((await w.mint({ use: 'grant-check', keyref: B })).target, { email: OTHER_SA, project: 'kbox-test-two' });
  assert.deepEqual(impersonated(w), [SA, OTHER_SA]);
});

test('KBOX-41 a key with no stored record mints nothing (no_key_info), and a stored scope with no, two or a reserved or malformed sa: item mints nothing, before any call', async (t) => {
  const stored = new Map<string, StoredKey>([
    ['google/p/NONE', { scopeItems: ['api:firestore.googleapis.com'], location: {} }],
    ['google/p/TWO', { scopeItems: ['sa:kbox-test-proj/kbox-test-relay', 'sa:kbox-test-two/kbox-test-other'], location: {} }],
    ['google/p/RESERVED', { scopeItems: ['sa:kbox-test-proj/kbox-keys'], location: {} }],
    ['google/p/BAD', { scopeItems: ['sa:kbox-test-proj/x'], location: {} }],
  ]);
  const w = await world(t, { keyInfo: (keyref) => stored.get(keyref) });
  for (const [keyref, code] of [['google/p/NOPE', 'no_key_info'], ['google/p/NONE', 'target_count'], ['google/p/TWO', 'target_count'], ['google/p/RESERVED', 'target_reserved'], ['google/p/BAD', 'target_malformed']] as const) {
    assert.equal((await refusal(w.mint(relay({ keyref })))).code, code, keyref);
    assert.equal((await refusal(w.mint({ use: 'grant-check', keyref }))).code, code, keyref);
  }
  assert.equal(w.http.sent.length, 0);
});

test('KBOX-41 a minter built without the box identity, the scanner sink or the stored-record reader refuses every use (identity_unconfigured) before any call', async (t) => {
  for (const omit of ['identity', 'minted', 'keyInfo'] as const) {
    const w = await world(t, { omit });
    for (const request of [relay(), { use: 'grant-check', keyref: A }, { use: 'admin', at: { project: 'kbox-test-proj' } }] as const) {
      assert.equal((await refusal(w.mint(request))).code, 'identity_unconfigured', `${omit} ${request.use}`);
    }
    assert.equal(w.http.sent.length, 0, omit);
  }
});

test('KBOX-41 a token request for the relay that carries cloud-platform is refused, even when the profile names it', async (t) => {
  const w = await world(t);
  for (const request of [relay({ scopes: [CLOUD_PLATFORM] }), relay({ scopes: [DATASTORE, CLOUD_PLATFORM], profileScopes: [DATASTORE, CLOUD_PLATFORM] })]) {
    assert.equal((await refusal(w.mint(request))).code, 'cloud_platform_for_relay');
  }
  assert.equal(w.http.sent.length, 0);
});

test('KBOX-41 the relay gets only scopes its profile names: another scope, a malformed one, a repeat or none is refused before any call', async (t) => {
  const w = await world(t);
  assert.equal((await refusal(w.mint(relay({ scopes: ['https://www.googleapis.com/auth/iam'] })))).code, 'scope_not_in_profile');
  for (const scopes of [['datastore'], [`${DATASTORE}/`], ['https://www.googleapis.com/auth/Datastore'], [DATASTORE, DATASTORE], []]) {
    assert.equal((await refusal(w.mint(relay({ scopes, profileScopes: [...scopes, DATASTORE] })))).code, 'scope_malformed', JSON.stringify(scopes));
  }
  assert.equal(w.http.sent.length, 0);
});

test('KBOX-24 the grant check\'s token is asked for the stored target with the read-only scope only', async (t) => {
  const w = await world(t);
  await w.mint({ use: 'grant-check', keyref: A });
  const impersonate = w.http.sent.find((s) => s.originalHost === 'iamcredentials.googleapis.com');
  assert.ok(impersonate !== undefined);
  assert.deepEqual((JSON.parse(Buffer.from(impersonate.body).toString('utf8')) as { scope: unknown }).scope, [READ_ONLY]);
});

// --- the admin token -----------------------------------------------------------------------------------------------------------------

test('KBOX-41 an admin token is minted for kbox-keys@<the call\'s project> with cloud-platform: with two projects stored, each call names exactly its own', async (t) => {
  const w = await world(t);
  const two = await w.mint({ use: 'admin', at: { project: 'kbox-test-two' } });
  const one = await w.mint({ use: 'admin', at: { project: 'kbox-test-proj' } });
  assert.deepEqual(impersonated(w), [ADMIN_TWO, ADMIN_ONE]);
  assert.deepEqual([two.target, one.target], [{ email: ADMIN_TWO, project: 'kbox-test-two' }, { email: ADMIN_ONE, project: 'kbox-test-proj' }]);
  for (const s of w.http.sent.filter((r) => r.originalHost === 'iamcredentials.googleapis.com')) {
    assert.deepEqual((JSON.parse(Buffer.from(s.body).toString('utf8')) as { scope: unknown }).scope, [CLOUD_PLATFORM]);
  }
});

test('KBOX-57 KBOX-41 an admin mint whose location names no project id (none, a number, a path, upper case, too short) is bad_location, before any call', async (t) => {
  const w = await world(t);
  for (const at of [{}, { region: 'eu' }, { project: '' }, { project: '123456789012' }, { project: 'Kbox-test-proj' }, { project: 'kbox-test-proj/x' }, { project: 'a1234' }, { project: 'kbox-test-proj-' }, { project: 'kbox-test-proj\n' }]) {
    assert.equal((await refusal(w.mint({ use: 'admin', at }))).code, 'bad_location', JSON.stringify(at));
  }
  assert.equal(w.http.sent.length, 0);
});

// --- Google's answers ----------------------------------------------------------------------------------------------------------------

test('KBOX-41 an STS refusal is a fixed error and no impersonation is asked; an assertion signed by a key Google does not trust is refused there', async (t) => {
  const w = await world(t);
  w.google.trust([trusted(NEXT_KEY)]);
  const error = await refusal(w.mint(relay()));
  assert.equal(error.code, 'sts_refused');
  assert.equal(error.status, 400);
  assert.deepEqual(w.http.sent.map((s) => s.originalHost), ['sts.googleapis.com']);
  assert.equal(w.sink.added.length, 0);
});

test('KBOX-41 a service account the principal holds no Token Creator on is refused by IAM and the minter says impersonation_refused', async (t) => {
  const w = await world(t);
  w.google.creatorOn([]);
  const error = await refusal(w.mint(relay()));
  assert.equal(error.code, 'impersonation_refused');
  assert.equal(error.status, 403);
});

test('KBOX-41 each way a Google host fails maps to one fixed code: a 5xx, a hung or refused connection, a cut answer, an answer without the token', async (t) => {
  const w = await world(t);
  const cases: [Parameters<FakeGoogle['override']>, string][] = [
    [['sts', { kind: 'status', status: 503, body: '{}' }], 'sts_failed'],
    [['sts', { kind: 'cut' }], 'unreachable'],
    [['sts', { kind: 'status', status: 200, body: '{"access_token":"kbox-test-x"}' }], 'bad_answer'],
    [['sts', { kind: 'status', status: 200, body: '{"access_token":"","expires_in":3600}' }], 'bad_answer'],
    [['sts', { kind: 'status', status: 200, body: 'not json' }], 'bad_answer'],
    [['impersonate', { kind: 'status', status: 500, body: '{}' }], 'impersonation_failed'],
    [['impersonate', { kind: 'status', status: 200, body: '{"accessToken":"ya29.kbox-test-x"}' }], 'bad_answer'],
    [['impersonate', { kind: 'status', status: 200, body: '{"accessToken":"ya29.kbox-test-x","expireTime":"tomorrow"}' }], 'bad_answer'],
    [['impersonate', { kind: 'cut' }], 'unreachable'],
  ];
  for (const [[route, override], code] of cases) {
    w.google.override(route, override);
    assert.equal((await refusal(w.mint(relay()))).code, code, `${route} ${JSON.stringify(override)}`);
    w.google.override(route, undefined);
  }
  const hung = createMinter({ http: { request: (req) => w.http.request({ ...req, timeoutMs: 50 }) }, clock: new FakeClock(NOW), identity: IDENTITY, minted: w.sink, keyInfo: (keyref) => STORED.get(keyref) });
  w.google.override('sts', { kind: 'hang' });
  assert.equal((await refusal(hung.mint(relay(), KEY.lent))).code, 'unreachable');
});

test('KBOX-14 a minted token planted as a canary, and an error body quoting it, never reach the error the minter throws', async (t) => {
  const w = await world(t);
  const planted = canary();
  const token = `ya29.${Buffer.from(planted.bytes).toString('base64url')}`;
  w.google.override('impersonate', { kind: 'status', status: 200, body: JSON.stringify({ accessToken: token, expireTime: 'never' }) });
  const malformed = await refusal(w.mint(relay()));
  planted.assertAbsent(surfacesOf(malformed));
  w.google.override('impersonate', { kind: 'status', status: 401, body: JSON.stringify({ error: { message: `Request had invalid authentication credentials: ${token}` } }) });
  const quoted = await refusal(w.mint(relay()));
  planted.assertAbsent(surfacesOf(quoted));
  w.google.override('sts', { kind: 'status', status: 400, body: JSON.stringify({ error: 'invalid_grant', error_description: token }) });
  planted.assertAbsent(surfacesOf(await refusal(w.mint(relay()))));
});

// --- KBOX-55: the proof of a signing key, and the mint's report ----------------------------------------------------------------------

/** KBOX-55: the box's signing key, `keyrefOf('google', [], 'OIDC_SIGNING_KEY')`. */
const SIGNING_REF = 'google/p/OIDC_SIGNING_KEY';

test('KBOX-55 a successful mint exchange is reported once for the signing key; one STS refused is not; one IAM refused after STS accepted still is', async (t) => {
  const w = await world(t);
  await w.mint(relay());
  assert.deepEqual(w.exchanged, [SIGNING_REF]);
  w.google.creatorOn([]);
  await refusal(w.mint(relay()));
  assert.deepEqual(w.exchanged, [SIGNING_REF, SIGNING_REF], 'STS took the assertion: the key is proven whatever IAM says next');
  w.google.trust([trusted(NEXT_KEY)]);
  assert.equal((await refusal(w.mint(relay()))).code, 'sts_refused');
  assert.deepEqual(w.exchanged, [SIGNING_REF, SIGNING_REF], 'a refused assertion proves nothing');
});

test('KBOX-55 federate exchanges one assertion signed with the key it is handed, for the identity it is handed, at STS only: no impersonation, nothing in the sink, no mint reported', async (t) => {
  // Built without the box identity, the sink or the stored-record reader: federate needs none of them.
  const w = await world(t, { omit: 'identity' });
  w.google.trust([trusted(KEY), trusted(NEXT_KEY)]);
  const federated = await w.federate(IDENTITY, NEXT_KEY.lent);
  assert.deepEqual(w.http.sent.map((s) => `${s.method} ${s.originalHost}${s.target}`), ['POST sts.googleapis.com/v1/token']);
  assert.equal(w.google.lastHeader?.['kid'], NEXT_KEY.kid, 'signed with the key handed in, not another');
  assert.deepEqual(w.google.lastClaims, { iss: IDENTITY.issuer, sub: BOX_SUBJECT, aud: `https:${PROVIDER}`, iat: NOW / 1000, exp: NOW / 1000 + ASSERTION_LIFETIME_S });
  assert.equal(Buffer.from(await bytesOf(federated.token)).toString('utf8'), 'kbox-test-federated-1');
  assert.equal(federated.expiresAt, NOW + 3599_000);
  assert.deepEqual(w.sink.added, []);
  assert.deepEqual(w.exchanged, [], 'a proof is not a mint: the orchestrator marks the generation it proved');
});

test('KBOX-55 federate with a key Google has not taken is sts_refused, and no other call follows', async (t) => {
  const w = await world(t);
  assert.equal((await refusal(w.federate(IDENTITY, NEXT_KEY.lent))).code, 'sts_refused');
  assert.deepEqual(w.http.sent.map((s) => s.originalHost), ['sts.googleapis.com']);
});

/** The google entry's box key over a fake Google that trusts KEY only, built with no identity, sink or stored-record reader of its own. */
async function prover(t: TestContext): Promise<{ readonly google: FakeGoogle; readonly http: FakeAdapterHttp; readonly sink: ReturnType<typeof recordingSink>; prove(key: TestKey, identity?: BoxIdentity): Promise<string> }> {
  const google = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  google.trust([trusted(KEY)]);
  const http = adapterHttpTo(google);
  const sink = recordingSink();
  const box = createGoogleEntry({ http, clock: new FakeClock(NOW) }).boxKey;
  assert.ok(box !== undefined);
  return { google, http, sink, prove: (key, identity = IDENTITY) => box.prove(key.lent, identity, sink) };
}

test('KBOX-55 KBOX-14 prove: STS accepting the new key is ok, and the federated token it bought is held by the scanner under the signing key until it expires', async (t) => {
  const p = await prover(t);
  assert.equal(await p.prove(KEY), 'ok');
  assert.deepEqual(p.sink.added, [{ keyref: SIGNING_REF, value: 'kbox-test-federated-1', expiresAt: NOW + 3599_000 }]);
  assert.deepEqual(p.http.sent.map((s) => s.originalHost), ['sts.googleapis.com']);
});

test('KBOX-55 prove: a key Google has not taken is rejected; a 5xx, a cut answer or a 200 without a token is unreachable; nothing is held for any of them', async (t) => {
  const p = await prover(t);
  assert.equal(await p.prove(NEXT_KEY), 'rejected');
  const unanswered: Parameters<FakeGoogle['override']>[1][] = [
    { kind: 'status', status: 503, body: '{}' },
    { kind: 'cut' },
    { kind: 'status', status: 200, body: '{"access_token":"kbox-test-x"}' },
  ];
  for (const override of unanswered) {
    p.google.override('sts', override);
    assert.equal(await p.prove(KEY), 'unreachable', JSON.stringify(override));
  }
  assert.deepEqual(p.sink.added, []);
  assert.ok(p.http.sent.every((s) => s.originalHost === 'sts.googleapis.com'), 'a proof never impersonates');
});

test('KBOX-55 prove: an audience that is no workload identity provider is refused before any call (identity_malformed), never retried as unreachable', async (t) => {
  const p = await prover(t);
  await assert.rejects(p.prove(KEY, { issuer: IDENTITY.issuer, audience: 'projects/123' }), (e: unknown) => e instanceof GoogleError && e.code === 'identity_malformed');
  assert.equal(p.http.sent.length, 0);
});

// --- the entry ----------------------------------------------------------------------------------------------------------------------

test('KBOX-41 KBOX-23 the google entry declares the hosts its own calls reach (sts, iamcredentials and cloudresourcemanager for the identity half, apikeys and secretmanager for KBOX-59), and the API-key issuer states the class and shape of its keys', async (t) => {
  const google = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  google.trust([trusted(KEY)]);
  google.creatorOn([SA]);
  const http = adapterHttpTo(google);
  const entry = createGoogleEntry({ http, clock: new FakeClock(NOW), identity: IDENTITY, minted: recordingSink(), keyInfo: (keyref) => STORED.get(keyref) });
  assert.equal(entry.id, 'google');
  assert.ok(entry.grantCheck !== undefined && entry.identity !== undefined);
  assert.deepEqual(await entry.grantCheck.check({ keyref: A, at: {} }, KEY.lent), { verdict: 'pass' });
  assert.deepEqual([...(entry.hosts ?? [])].sort(), ['apikeys.googleapis.com', 'cloudresourcemanager.googleapis.com', 'iamcredentials.googleapis.com', 'secretmanager.googleapis.com', 'sts.googleapis.com']);
  assert.deepEqual([...new Set(http.sent.map((s) => s.originalHost))].sort(), ['cloudresourcemanager.googleapis.com', 'iamcredentials.googleapis.com', 'sts.googleapis.com'], 'the grant check reaches the identity half\'s three');
  assert.notStrictEqual(entry.issuer, undefined, 'the API-key issuer is google-b\'s');
  assert.equal(entry.shape, undefined, 'one source of a shape: the issuer\'s');
  assert.equal(entry.classify, undefined, 'one source of a class: the issuer\'s');
});

test('KBOX-24 the entry\'s grant check applies only to a key that acts as a service account', () => {
  const entry = createGoogleEntry({ http: { request: () => Promise.reject(new Error('no call')) }, clock: new FakeClock(NOW) });
  assert.ok(entry.grantCheck !== undefined);
  assert.equal(entry.grantCheck.appliesTo(['sa:kbox-test-proj/kbox-test-relay']), true);
  assert.equal(entry.grantCheck.appliesTo(['api:firestore.googleapis.com']), false);
});

test('KBOX-3 KBOX-41 the relay\'s registry hands the google entry no identity, sink or stored-record reader, so every grant check there refuses before any call', async (t) => {
  const google = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  google.trust([trusted(KEY)]);
  google.creatorOn([SA]);
  const http = adapterHttpTo(google);
  const [entry] = createRelayRegistry(new FakeClock(NOW), (deps) => [createGoogleEntry({ ...deps, http })]);
  assert.ok(entry?.grantCheck !== undefined);
  assert.deepEqual(await entry.grantCheck.check({ keyref: A, at: {} }, KEY.lent), { verdict: 'refused', code: 'grant_check_no_identity' });
  assert.equal(http.sent.length, 0);
});
