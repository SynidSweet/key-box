// KBOX-40: the two paste-only platforms, Anthropic and Stripe. Each entry states its own shape and class (no issuer); verifier statuses,
// the Anthropic lister and the retire-after-paste-rotation call run over fakes that play the platform as docs/probes/{anthropic,stripe}.md
// describe it, reached through the real adapter port (`adapterHttpTo`). Values are synthetic (`kbox-test` filler).
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { ANTHROPIC_SHAPE, createAnthropicEntry, createAnthropicLister, createAnthropicRetirer } from '../src/platforms/anthropic/index.ts';
import { STRIPE_SHAPE, STRIPE_VERIFY_CALLS, createStripeEntry } from '../src/platforms/stripe/index.ts';
import type { HttpResponse } from '../src/ports/http.ts';
import { HttpTransportError } from '../src/ports/http.ts';
import type { Issuer, IssuerCapabilities, KeyLister, Verifier } from '../src/ports/issuer.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import type { Lent } from '../src/ports/types.ts';
import { matchesShape } from '../src/pure/class.ts';
import { classifierOf, shapeOf } from '../src/pure/platform-shape.ts';
import { checkRegistry } from '../src/pure/profile.ts';
import { adapterHttpTo, bytesOf, canary, lent } from './kit/index.ts';
import type { FakeAdapterHttp } from './kit/index.ts';
import { fakeAnthropic } from './fakes/anthropic-api.ts';
import type { FakeAnthropic } from './fakes/anthropic-api.ts';
import type { Teardown } from './fakes/loopback.ts';
import { sourceOf } from './fakes/platform-entry.ts';
import { fakeStripe } from './fakes/stripe-api.ts';
import type { FakeStripe } from './fakes/stripe-api.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { verifierContract } from './contracts/verifier.contract.ts';
import { routesWorld } from './support/routes-world.ts';
import type { PasteView, RoutesWorld } from './support/routes-world.ts';

const clock = { now: () => 0 };
const L = (text: string): Lent => lent(Buffer.from(text), 'test:1');
/** A synthetic ordinary Anthropic key; `tag` (4 characters) is the end of the value, so it is what `partial_key_hint` tells keys apart by. */
const ordinary = (tag: string): string => `sk-ant-api03-kbox-test-${'x'.repeat(40)}${tag}`;
const ADMIN = `sk-ant-admin01-kbox-test-${'y'.repeat(40)}`;
const restricted = (tag: string): string => `rk_live_kbox${'T'.repeat(30)}${tag}`;
const ANTHROPIC = { platform: 'anthropic' };
const STRIPE = { platform: 'stripe' };

interface Anthropic {
  readonly api: FakeAnthropic;
  readonly http: FakeAdapterHttp;
  readonly entry: PlatformEntry;
}
async function anthropic(t: Teardown): Promise<Anthropic> {
  const api = await fakeAnthropic(t);
  api.admins.add(ADMIN);
  const http = adapterHttpTo(api);
  return { api, http, entry: createAnthropicEntry({ http, clock }) };
}
async function stripe(t: Teardown): Promise<{ api: FakeStripe; http: FakeAdapterHttp; entry: PlatformEntry }> {
  const api = await fakeStripe(t);
  const http = adapterHttpTo(api);
  return { api, http, entry: createStripeEntry({ http, clock }) };
}
const verifierOf = (entry: PlatformEntry): Verifier => {
  if (entry.verifier === undefined) throw new RangeError('entry has no verifier');
  return entry.verifier;
};
const listerOf = (entry: PlatformEntry): KeyLister => {
  if (entry.lister === undefined) throw new RangeError('entry has no lister');
  return entry.lister;
};
/** An adapter port that answers every call with one status and body, for the answers a real platform gives rarely. */
const answering = (status: number, body = '{}'): { request: () => Promise<HttpResponse> } => ({
  request: () => Promise.resolve({ status, headers: {}, body: Buffer.from(body) }),
});
const ALL_ROUTES = new Set(STRIPE_VERIFY_CALLS.map((c) => c.path.split('?')[0] ?? ''));

// --- shape and class ----------------------------------------------------------------------------------------------------------------

test('KBOX-40 KBOX-12 Anthropic shape: the ordinary and the admin prefix with a real-format core are accepted; wrong prefix, short core and wrong alphabet are refused', () => {
  assert.equal(matchesShape(ANTHROPIC_SHAPE, ordinary('AbCd')), true);
  assert.equal(matchesShape(ANTHROPIC_SHAPE, ADMIN), true);
  assert.equal(matchesShape(ANTHROPIC_SHAPE, ordinary('AbCd').replace('sk-ant-', 'sk-oai-')), false, 'wrong prefix');
  assert.equal(matchesShape(ANTHROPIC_SHAPE, `sk-ant-api03-${'a'.repeat(10)}`), false, 'short core');
  assert.equal(matchesShape(ANTHROPIC_SHAPE, `sk-ant-api03-${'a'.repeat(39)} a`), false, 'a space in the core');
  assert.equal(matchesShape(ANTHROPIC_SHAPE, `sk-ant-api03-${'a'.repeat(39)}+/`), false, 'standard base64 characters');
  assert.equal(matchesShape(ANTHROPIC_SHAPE, ''), false);
});

test('KBOX-40 KBOX-12 Stripe shape: rk_live_ with a base62 core is accepted; test keys, secret keys, short cores and other characters are refused', () => {
  assert.equal(matchesShape(STRIPE_SHAPE, restricted('AbCd')), true);
  assert.equal(matchesShape(STRIPE_SHAPE, restricted('AbCd').replace('rk_live_', 'rk_test_')), false, 'a test-mode key');
  assert.equal(matchesShape(STRIPE_SHAPE, restricted('AbCd').replace('rk_live_', 'sk_live_')), false, 'a secret key');
  assert.equal(matchesShape(STRIPE_SHAPE, 'rk_live_short'), false, 'short core');
  assert.equal(matchesShape(STRIPE_SHAPE, `rk_live_${'a'.repeat(30)}-_`), false, 'a character outside base62');
});

test('KBOX-40 KBOX-15 each entry has no issuer and states its own shape and class: Anthropic by scope, Stripe never ordinary', async (t) => {
  const a = await anthropic(t);
  const s = await stripe(t);
  for (const entry of [a.entry, s.entry]) {
    assert.equal(entry.issuer, undefined);
    assert.notEqual(shapeOf(entry), undefined);
    assert.notEqual(classifierOf(entry), undefined);
  }
  const classify = classifierOf(a.entry);
  assert.equal(classify?.({ items: ['admin'] }), 'master');
  assert.equal(classify?.({ items: ['read', 'admin'] }), 'master');
  assert.equal(classify?.({ items: ['read'] }), 'ordinary');
  assert.equal(classify?.({ items: [] }), 'ordinary');
  assert.equal(classifierOf(s.entry)?.({ items: ['balance'] }), 'admin');
});

test('KBOX-40 KBOX-23 neither entry has a relay profile or a deny list, both pass the registry check, and the hosts are exactly the management hosts', async (t) => {
  const a = await anthropic(t);
  const s = await stripe(t);
  for (const entry of [a.entry, s.entry]) {
    assert.equal(entry.relay, undefined);
    assert.equal(entry.denyOnly, undefined);
  }
  assert.equal(checkRegistry([a.entry, s.entry]).ok, true);
  assert.deepEqual(a.entry.hosts, ['api.anthropic.com']);
  assert.deepEqual(s.entry.hosts, ['api.stripe.com']);
  assert.equal(a.entry.keyPageUrl, 'https://platform.claude.com/settings/keys');
  assert.equal(s.entry.keyPageUrl, 'https://dashboard.stripe.com/apikeys');
  assert.notEqual(a.entry.lister, undefined, 'Anthropic lists keys');
  assert.equal(s.entry.lister, undefined);
});

// --- Anthropic verifier -------------------------------------------------------------------------------------------------------------

test('KBOX-40 Anthropic verifier: 200 ok, 401 and 403 rejected, a cut connection unreachable; it sends the key and the version header to /v1/models', async (t) => {
  const { api, http, entry } = await anthropic(t);
  const verifier = verifierOf(entry);
  const live = ordinary('LIVE');
  api.add(live, 'live');
  assert.equal(await verifier.verify(L(live), ANTHROPIC), 'ok');
  const sent = http.sent[0];
  assert.equal(sent?.originalHost, 'api.anthropic.com');
  assert.equal(sent?.method, 'GET');
  assert.equal(sent?.target, '/v1/models?limit=1');
  assert.equal(sent?.headers['x-api-key'], live);
  assert.equal(sent?.headers['anthropic-version'], '2023-06-01');
  assert.equal(await verifier.verify(L(ordinary('NONE')), ANTHROPIC), 'rejected', '401: never issued');
  api.add(ordinary('OFFF'), 'off', 'inactive');
  assert.equal(await verifier.verify(L(ordinary('OFFF')), ANTHROPIC), 'rejected', '401: a retired key');
  api.admins.add(ordinary('ADM1'));
  assert.equal(await verifier.verify(L(ordinary('ADM1')), ANTHROPIC), 'rejected', '403 (the fake answers an admin key on /v1/models so)');
  api.down = true;
  assert.equal(await verifier.verify(L(live), ANTHROPIC), 'unreachable', 'a cut connection');
});

test('KBOX-40 KBOX-14 Anthropic verifier: every transport failure code is unreachable, and an answer that says nothing about the key (404, 429, 5xx) is unreachable too', async () => {
  for (const code of ['refused', 'unreachable', 'timeout', 'too_large', 'malformed'] as const) {
    const down = { request: () => Promise.reject(new HttpTransportError(code)) };
    assert.equal(await verifierOf(createAnthropicEntry({ http: down, clock })).verify(L(ordinary('ABCD')), ANTHROPIC), 'unreachable', code);
  }
  for (const status of [404, 429, 500, 503]) {
    assert.equal(await verifierOf(createAnthropicEntry({ http: answering(status), clock })).verify(L(ordinary('ABCD')), ANTHROPIC), 'unreachable', String(status));
  }
});

test('KBOX-40 Anthropic verifier: the admin key is verified on the organization key list, not on /v1/models', async (t) => {
  const { api, http, entry } = await anthropic(t);
  assert.equal(await verifierOf(entry).verify(L(ADMIN), ANTHROPIC), 'ok');
  assert.equal(http.sent[0]?.target, '/v1/organizations/api_keys?limit=1');
  assert.deepEqual(api.log, ['GET /v1/organizations/api_keys?limit=1']);
  assert.equal(await verifierOf(entry).verify(L(ADMIN.replace('kbox', 'kbxx')), ANTHROPIC), 'rejected', 'an admin key the platform never issued');
});

test('KBOX-40 KBOX-14 a value that cannot be a header (a newline, a space, a control character, a non-ASCII letter) is rejected with no call', async (t) => {
  const a = await anthropic(t);
  const s = await stripe(t);
  for (const bad of ['sk-ant-api03-a\nb', 'sk-ant-api03-a b', 'sk-ant-api03-\u0001x', 'sk-ant-api03-é']) {
    assert.equal(await verifierOf(a.entry).verify(L(bad), ANTHROPIC), 'rejected');
    assert.equal(await verifierOf(s.entry).verify(L(bad), STRIPE), 'rejected');
  }
  assert.equal(a.http.sent.length + s.http.sent.length, 0);
});

// --- Stripe verifier ----------------------------------------------------------------------------------------------------------------

test('KBOX-40 Stripe verifier: 200 ok, 401 rejected, a 403 moves on to the next call of the adapter list, a cut connection is unreachable', async (t) => {
  const { api, http, entry } = await stripe(t);
  const verifier = verifierOf(entry);
  const last = (STRIPE_VERIFY_CALLS[STRIPE_VERIFY_CALLS.length - 1]?.path ?? '').split('?')[0] ?? '';
  api.allowed.set(restricted('ONLY'), new Set([last]));
  assert.equal(await verifier.verify(L(restricted('ONLY')), STRIPE), 'ok', 'permitted only on the last call of the list');
  assert.equal(http.sent.length, STRIPE_VERIFY_CALLS.length, 'each earlier call answered 403 and the next was tried');
  assert.equal(http.sent[0]?.headers['authorization'], `Bearer ${restricted('ONLY')}`);
  assert.equal(http.sent[0]?.originalHost, 'api.stripe.com');
  assert.equal(http.sent[0]?.method, 'GET');
  api.allowed.set(restricted('FULL'), ALL_ROUTES);
  const before = http.sent.length;
  assert.equal(await verifier.verify(L(restricted('FULL')), STRIPE), 'ok');
  assert.equal(http.sent.length, before + 1, 'the first call settles a key that may make it');
  assert.equal(await verifier.verify(L(restricted('NONE')), STRIPE), 'rejected', '401 on the first call stops the walk');
  assert.equal(http.sent.length, before + 2);
  api.down = true;
  assert.equal(await verifier.verify(L(restricted('FULL')), STRIPE), 'unreachable');
});

test('KBOX-40 KBOX-14 Stripe verifier: every transport failure code and an answer that says nothing about the key (404, 429, 5xx) is unreachable', async () => {
  for (const code of ['refused', 'unreachable', 'timeout', 'too_large', 'malformed'] as const) {
    const down = { request: () => Promise.reject(new HttpTransportError(code)) };
    assert.equal(await verifierOf(createStripeEntry({ http: down, clock })).verify(L(restricted('ABCD')), STRIPE), 'unreachable', code);
  }
  for (const status of [404, 429, 500, 503]) {
    assert.equal(await verifierOf(createStripeEntry({ http: answering(status), clock })).verify(L(restricted('ABCD')), STRIPE), 'unreachable', String(status));
  }
});

test('KBOX-40 Stripe verifier: a key refused by every call of the list as lacking permission is alive (403 follows authentication): ok', async (t) => {
  const { api, entry } = await stripe(t);
  // UNVERIFIED (stripe.verify-calls): the answer of a restricted key with none of the candidate permissions is assumed to be 403, after auth.
  api.allowed.set(restricted('NOPE'), new Set());
  assert.equal(await verifierOf(entry).verify(L(restricted('NOPE')), STRIPE), 'ok');
});

test('KBOX-40 the Stripe adapter list names each call with the permission it needs, for the paste page to offer', () => {
  assert.ok(STRIPE_VERIFY_CALLS.length >= 3);
  for (const call of STRIPE_VERIFY_CALLS) {
    assert.match(call.path, /^\/v1\/[a-z_]+(\?limit=1)?$/);
    assert.ok(call.permission.length > 0);
  }
});

// --- the verifier and lister contract suites ------------------------------------------------------------------------------------------

const ANTHROPIC_CAPS: IssuerCapabilities = {
  create: 'paste',
  revoke: 'paste',
  selfRotate: false,
  overlap: true,
  set: 'none',
  revealOnce: false,
  scopeSchema: { fields: ['items'] },
  shape: ANTHROPIC_SHAPE,
  classify: () => 'ordinary',
};

/** The platform's own dashboard, as a contract suite's issuer: a key made there lands on the fake, and one the owner retires there goes inactive. */
function dashboard(api: FakeAnthropic): Issuer {
  let n = 0;
  return {
    platform: 'anthropic',
    capabilities: () => ANTHROPIC_CAPS,
    issue: (_req, intent) => {
      const value = ordinary(`d${String(++n).padStart(3, '0')}`);
      return Promise.resolve({ value: L(value), platformKeyId: api.add(value, intent) });
    },
    revoke: (id) => {
      const key = api.keys.get(id);
      if (key === undefined) return Promise.resolve('absent' as const);
      key.status = 'inactive';
      return Promise.resolve('revoked' as const);
    },
  };
}

const shared = await anthropic({ after });
const anthropicSubject = () => {
  shared.api.keys.clear();
  shared.api.down = false;
  return {
    issuer: dashboard(shared.api),
    verifier: verifierOf(shared.entry),
    lister: listerOf(shared.entry),
    master: L(ADMIN),
    wrongMaster: L(ordinary('WRNG')),
    stranger: L(ordinary('STRN')),
    setUnreachable: (down: boolean): void => void (shared.api.down = down),
  };
};
verifierContract('anthropic paste adapter', anthropicSubject);
listerContract('anthropic paste adapter', anthropicSubject);

const sharedStripe = await stripe({ after });
verifierContract('stripe paste adapter', () => {
  sharedStripe.api.allowed.clear();
  sharedStripe.api.down = false;
  let n = 0;
  const issuer: Issuer = {
    platform: 'stripe',
    capabilities: () => ({ ...ANTHROPIC_CAPS, shape: STRIPE_SHAPE }),
    issue: () => {
      const value = restricted(`d${String(++n).padStart(3, '0')}`);
      sharedStripe.api.allowed.set(value, ALL_ROUTES);
      return Promise.resolve({ value: L(value), platformKeyId: value });
    },
    revoke: (id) => Promise.resolve(sharedStripe.api.allowed.delete(id) ? ('revoked' as const) : ('absent' as const)),
  };
  return {
    issuer,
    verifier: verifierOf(sharedStripe.entry),
    master: L('unused'),
    stranger: L(restricted('STRN')),
    setUnreachable: (down: boolean): void => void (sharedStripe.api.down = down),
  };
});

// --- the Anthropic lister -----------------------------------------------------------------------------------------------------------

test('KBOX-40 Anthropic lister: every page is read, a key the platform holds switched off is disabled, and the location asked is the location answered', async (t) => {
  const { api, http } = await anthropic(t);
  const lister = createAnthropicLister(http, { pageSize: 2 });
  api.add(ordinary('0001'), 'one');
  api.add(ordinary('0002'), 'two', 'inactive');
  api.add(ordinary('0003'), 'three', 'archived');
  api.add(ordinary('0004'), 'four', 'expired');
  api.add(ordinary('0005'), 'five');
  const listing = await lister.listAt({ project: 'shop' }, L(ADMIN));
  assert.equal(listing.complete, true);
  assert.deepEqual(listing.at, { project: 'shop' });
  assert.deepEqual(listing.keys.map((k) => [k.name, k.disabled === true]), [['one', false], ['two', true], ['three', true], ['four', true], ['five', false]]);
  assert.equal(api.log.filter((l) => l.startsWith('GET /v1/organizations/api_keys')).length, 3, 'three pages of two');
  assert.match(api.log[1] ?? '', /after_id=apikey_fake0002/);
  assert.deepEqual((await lister.list(L(ADMIN))).map((k) => k.name), ['one', 'five'], 'the plain list is the live keys');
});

test('KBOX-40 Anthropic lister: a page that cannot be read after the first makes the listing incomplete, keeping what was read; the first page failing throws', async (t) => {
  const { api, http } = await anthropic(t);
  const lister = createAnthropicLister(http, { pageSize: 1 });
  api.add(ordinary('0001'), 'one');
  api.add(ordinary('0002'), 'two');
  api.failPagesFrom(2);
  const listing = await lister.listAt({}, L(ADMIN));
  assert.equal(listing.complete, false);
  assert.deepEqual(listing.keys.map((k) => k.name), ['one']);
  api.failPagesFrom(1);
  await assert.rejects(() => lister.listAt({}, L(ADMIN)), /http_error/);
  api.down = true;
  await assert.rejects(() => lister.listAt({}, L(ADMIN)), /unreachable/);
});

test('KBOX-40 Anthropic lister: an answer with no usable page (not JSON, a key with no id) throws a fixed error and says no key is absent', async () => {
  for (const body of ['not json', '{"data":[{"name":"x"}],"has_more":false}', '{"data":"no"}']) {
    const lister = createAnthropicLister(answering(200, body));
    await assert.rejects(() => lister.listAt({}, L(ADMIN)), /bad_answer/);
  }
});

// --- retire after a paste rotation (KBOX-51 step 10) --------------------------------------------------------------------------------

test('KBOX-40 KBOX-51 the old key is found by its partial_key_hint among the live keys and set inactive; the verifier then rejects it while the new key still verifies', async (t) => {
  const { api, http, entry } = await anthropic(t);
  const retirer = createAnthropicRetirer({ http });
  const oldKey = ordinary('OLD1');
  const newKey = ordinary('NEW1');
  api.add(ordinary('OTH1'), 'other');
  const oldId = api.add(oldKey, 'old');
  api.add(newKey, 'new');
  const verifier = verifierOf(entry);
  assert.equal(await verifier.verify(L(oldKey), ANTHROPIC), 'ok', 'during the grace the old key still works');
  api.log.length = 0;
  assert.equal(await retirer.retire(L(oldKey), L(ADMIN)), 'retired');
  assert.deepEqual(api.log, ['GET /v1/organizations/api_keys?status=active&limit=1000', `POST /v1/organizations/api_keys/${oldId}`], 'list, then one update');
  assert.deepEqual(JSON.parse(Buffer.from(http.sent[http.sent.length - 1]?.body ?? new Uint8Array()).toString('utf8')), { status: 'inactive' });
  assert.equal(http.sent[http.sent.length - 1]?.headers['x-api-key'], ADMIN, 'the admin key makes the call');
  assert.equal(await verifier.verify(L(oldKey), ANTHROPIC), 'rejected', 'only now is the old key proven dead');
  assert.equal(await verifier.verify(L(newKey), ANTHROPIC), 'ok');
  assert.equal(api.keys.get(oldId)?.status, 'inactive');
});

test('KBOX-40 a hint that matches two live keys retires nothing and says so (ambiguous); a hint that matches none is absent and changes nothing', async (t) => {
  const { api, http } = await anthropic(t);
  const retirer = createAnthropicRetirer({ http });
  const oldKey = ordinary('TWIN');
  const twin = `${oldKey.slice(0, 14)}-another-middle-${oldKey.slice(-4)}`;
  api.add(oldKey, 'old');
  api.add(twin, 'twin');
  await assert.rejects(() => retirer.retire(L(oldKey), L(ADMIN)), /ambiguous/);
  assert.equal(api.log.some((l) => l.startsWith('POST')), false, 'no key was changed');
  assert.equal([...api.keys.values()].every((k) => k.status === 'active'), true);
  api.log.length = 0;
  assert.equal(await retirer.retire(L(ordinary('GONE')), L(ADMIN)), 'absent');
  assert.equal(api.log.some((l) => l.startsWith('POST')), false);
});

test('KBOX-40 a key that is already switched off is not a candidate: the live key with the same hint is the one retired', async (t) => {
  const { api, http } = await anthropic(t);
  const retirer = createAnthropicRetirer({ http });
  const oldKey = ordinary('SAME');
  api.add(`${oldKey.slice(0, 14)}-an-old-one-${oldKey.slice(-4)}`, 'earlier', 'inactive');
  const id = api.add(oldKey, 'current');
  assert.equal(await retirer.retire(L(oldKey), L(ADMIN)), 'retired');
  assert.equal(api.keys.get(id)?.status, 'inactive');
});

test('KBOX-40 the retire call: a refused admin key throws rejected, an update answered 404 is absent, an unreachable platform throws unreachable', async (t) => {
  const { api, http } = await anthropic(t);
  const retirer = createAnthropicRetirer({ http });
  const oldKey = ordinary('OLD2');
  const id = api.add(oldKey, 'old');
  await assert.rejects(() => retirer.retire(L(oldKey), L(ordinary('NOAD'))), /rejected/);
  assert.equal(api.keys.get(id)?.status, 'active');
  const racing = createAnthropicRetirer({
    http: {
      request: async (req) => {
        const answer = await http.request(req);
        if (req.method === 'POST') return { ...answer, status: 404 };
        return answer;
      },
    },
  });
  assert.equal(await racing.retire(L(oldKey), L(ADMIN)), 'absent');
  api.down = true;
  await assert.rejects(() => retirer.retire(L(oldKey), L(ADMIN)), /unreachable/);
});

// --- the value rules (KBOX-14) ------------------------------------------------------------------------------------------------------

test('KBOX-14 a platform answer that quotes the key never reaches an error: verifier, lister and retire over a 401 and a 500 that echo it', async (t) => {
  const { api, http, entry } = await anthropic(t);
  const stripeWorld = await stripe(t);
  const c = canary(24);
  const secret = `sk-ant-admin01-${Buffer.from(c.bytes).toString('hex')}`;
  const surfaces: Record<string, string> = {};
  const note = (name: string, value: unknown): void => void (surfaces[name] = typeof value === 'string' ? value : JSON.stringify(value));
  const caught = async (name: string, call: () => Promise<unknown>): Promise<void> => {
    try {
      note(name, await call());
    } catch (error) {
      assert.ok(error instanceof Error);
      note(name, [error.name, error.message, error.stack ?? '', JSON.stringify(error), String(error.cause ?? '')].join('|'));
    }
  };
  await caught('anthropic verify', () => verifierOf(entry).verify(L(secret), ANTHROPIC));
  await caught('anthropic list', () => listerOf(entry).list(L(secret)));
  await caught('anthropic listAt', () => listerOf(entry).listAt({}, L(secret)));
  await caught('anthropic retire', () => createAnthropicRetirer({ http }).retire(L(ordinary('OLD3')), L(secret)));
  api.admins.add(secret);
  api.add(ordinary('OLD3'), 'old');
  api.failPagesFrom(1);
  await caught('anthropic list 500', () => listerOf(entry).list(L(secret)));
  await caught('anthropic retire 500', () => createAnthropicRetirer({ http }).retire(L(ordinary('OLD3')), L(secret)));
  await caught('stripe verify', () => verifierOf(stripeWorld.entry).verify(L(`rk_live_${Buffer.from(c.bytes).toString('hex')}`), STRIPE));
  assert.ok(api.log.length > 0 && stripeWorld.api.log.length > 0, 'the fakes were reached');
  c.assertAbsent(surfaces);
});

// --- the paste flow end to end through the real /p/<id> route -----------------------------------------------------------------

/** The world's own source (its master key, its destination kinds) with the platforms of `entries` registered over it. */
const HOST_SOURCE = (entries: readonly PlatformEntry[]) => (real: PlatformSource): PlatformSource => {
  const own = sourceOf(entries);
  return { ...real, platform: (id) => own.platform(id) ?? real.platform(id) };
};
/**
 * A paste task for an `add_key` of a paste-only platform, opened as mission control would. Anthropic's admin key is class master, which
 * `POST /api/keys` refuses (`master_not_issuable`; the master is pasted at setup), so the task is opened with `mark_admin`, as a key the
 * owner holds as admin.
 */
const openTask = (w: RoutesWorld, platform: string, name: string, items: string[]): string =>
  w.rotation.paste.open({ action: { kind: 'add_key', platform, name, projects: ['shop'], scope: { items }, mark_admin: true }, requester: { kind: 'token', label: 'mission-control' } }).paste_id;
async function pasteThrough(w: RoutesWorld, platform: string, name: string, items: string[], value: string): Promise<{ status: number; body: string }> {
  const id = openTask(w, platform, name, items);
  const cookie = await w.view();
  const page = await w.call(`/p/${id}`, { cookie });
  assert.equal(page.status, 200, page.body);
  const view = page.json() as PasteView;
  const stored = await w.call(`/p/${id}`, { json: { value, proof: w.pasteProof(view) }, cookie });
  return { status: stored.status, body: stored.body };
}

test('KBOX-40 KBOX-12 an Anthropic admin key is pasted through /p/<id>: shape, then the real verifier call, stored as admin (raised by mark_admin)', async (t) => {
  const { api, entry } = await anthropic(t);
  const w = await routesWorld(t, { source: HOST_SOURCE([entry]) });
  api.admins.add(ADMIN.replace('kbox', 'pstd'));
  const value = ADMIN.replace('kbox', 'pstd');
  const refusedShape = await pasteThrough(w, 'anthropic', 'ANTHROPIC_ADMIN', ['read'], 'sk-ant-admin01-short-but-sixteen-bytes');
  assert.equal(refusedShape.status, 422);
  assert.match(refusedShape.body, /bad_shape/);
  assert.deepEqual(api.log, [], 'a bad shape makes no platform call');
  const wrong = await pasteThrough(w, 'anthropic', 'ANTHROPIC_OTHER', ['read'], ADMIN.replace('kbox', 'nope'));
  assert.equal(wrong.status, 422);
  assert.match(wrong.body, /verifier_rejected/);
  const stored = await pasteThrough(w, 'anthropic', 'ANTHROPIC_ADMIN2', ['read'], value);
  assert.equal(stored.status, 201, stored.body);
  const keyref = 'anthropic/shop/ANTHROPIC_ADMIN2';
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.class, 'admin');
  assert.equal(Buffer.from(await bytesOf(w.parts.vault.lend(keyref, 1))).toString('utf8'), value);
  assert.equal((await w.api('/api/keys', { json: { platform: 'anthropic', name: 'ORD', projects: ['shop'], scope: { items: ['read'] } } })).status, 422, 'an ordinary key is not the box\'s business');
});

test('KBOX-40 KBOX-12 a Stripe restricted key is pasted through /p/<id>: shape, then the real verifier walk, stored as admin; an unreachable platform stores nothing', async (t) => {
  const { api, entry } = await stripe(t);
  const w = await routesWorld(t, { source: HOST_SOURCE([entry]) });
  const value = restricted('PSTD');
  api.allowed.set(value, new Set(['/v1/products']));
  const refusedShape = await pasteThrough(w, 'stripe', 'STRIPE_RK', ['products'], restricted('PSTD').replace('rk_live_', 'rk_test_'));
  assert.equal(refusedShape.status, 422);
  assert.match(refusedShape.body, /bad_shape/);
  api.down = true;
  const unreachable = await pasteThrough(w, 'stripe', 'STRIPE_RK2', ['products'], value);
  assert.equal(unreachable.status, 422);
  assert.match(unreachable.body, /verifier_unreachable/);
  assert.equal(w.rotation.store.key('stripe/shop/STRIPE_RK2'), undefined, 'nothing stored');
  api.down = false;
  const stored = await pasteThrough(w, 'stripe', 'STRIPE_RK3', ['products'], value);
  assert.equal(stored.status, 201, stored.body);
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === 'stripe/shop/STRIPE_RK3')?.class, 'admin');
});

test('KBOX-40 the paste page of each platform offers that platform\'s own key page', async (t) => {
  const a = await anthropic(t);
  const s = await stripe(t);
  const w = await routesWorld(t, { source: HOST_SOURCE([a.entry, s.entry]) });
  for (const [platform, items, link] of [['anthropic', ['read'], 'https://platform.claude.com/settings/keys'], ['stripe', ['products'], 'https://dashboard.stripe.com/apikeys']] as const) {
    const id = openTask(w, platform, 'PAGE_KEY', [...items]);
    const page = await w.call(`/p/${id}`, { cookie: await w.view() });
    assert.equal((page.json() as { platform_link?: string }).platform_link, link);
  }
});
