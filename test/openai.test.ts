// KBOX-38: the OpenAI adapter, over a stateful fake of the platform as docs/probes/openai.md describes it. The contract suites of the
// issuer, lister, verifier and relay profile run against the adapter; the rest pins what the contracts cannot say: the service account
// kept across a rotation, the fixed errors, the canary, the shape, the deny list and the replacement of a 401 that quotes a key.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import type { TestContext } from 'node:test';
import { inspect } from 'node:util';
import type { IssueRequest, Issuer } from '../src/ports/issuer.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { AllowRule, DenyRule, RelayProfile } from '../src/ports/relay-profile.ts';
import type { Lent } from '../src/ports/types.ts';
import { createOpenAiEntry } from '../src/platforms/openai/index.ts';
import { createRegistry } from '../src/platforms/registry.ts';
import { checkRegistry, compileProfile, refuseWidening } from '../src/pure/profile.ts';
import { shapeOf } from '../src/pure/platform-shape.ts';
import { scanForms } from '../src/pure/forms.ts';
import { upstreamRefusedBody } from '../src/pure/relay-errors.ts';
import { parseRelayTarget } from '../src/pure/target-parse.ts';
import { assess } from '../src/pure/coverage.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { relayProfileContract } from './contracts/relay-profile.contract.ts';
import { verifierContract } from './contracts/verifier.contract.ts';
import { fakeOpenAi } from './fakes/openai.ts';
import type { FakeOpenAi } from './fakes/openai.ts';
import { TEST_REGISTRY } from './fixtures/profiles.ts';
import { adapterHttpTo, bytesOf, canary, lent } from './kit/index.ts';
import { relayWorld } from './support/relay-world.ts';

const ADMIN = 'sk-admin-kbox-test-0123456789abcdefghijklmnopqrstuvwxyz';
const PROJECT = 'proj_kbox_test';
const AT = { project: PROJECT };
const REQ = { scope: {}, at: AT };
const DAY = 86_400;
const FILLER = 'kbox-test-filler-0123456789abcdefghijklmnopqrstuvwxyz';

const master = (): Lent => lent(Buffer.from(ADMIN), 'master:1');
const stranger = (): Lent => lent(Buffer.from(`sk-svcacct-kbox-test-stranger-${FILLER}`), 'stranger:1');
const wrongMaster = (): Lent => lent(Buffer.from(`sk-admin-kbox-test-wrong-${FILLER}`), 'wrong:1');
const text = (l: Lent): Promise<string> => bytesOf(l).then((b) => Buffer.from(b).toString('utf8'));

function adapterOver(fake: FakeOpenAi): { readonly entry: PlatformEntry; readonly issuer: Issuer; readonly http: ReturnType<typeof adapterHttpTo> } {
  const http = adapterHttpTo(fake);
  const entry = createOpenAiEntry({ http, clock: { now: () => 0 } });
  assert.ok(entry.issuer !== undefined && entry.lister !== undefined && entry.verifier !== undefined);
  return { entry, issuer: entry.issuer, http };
}

/** A fresh fake and the adapter over it for one test. */
async function fresh(t: TestContext): Promise<ReturnType<typeof adapterOver> & { readonly fake: FakeOpenAi }> {
  const fake = await fakeOpenAi({ adminKey: ADMIN });
  t.after(() => fake.close());
  return { fake, ...adapterOver(fake) };
}

const must = <T>(v: T | undefined): T => {
  if (v === undefined) throw new Error('missing');
  return v;
};

// --- the contract suites: one shared fake (they build their subject synchronously) --------------------------------------------

let shared: FakeOpenAi | undefined;
before(async () => {
  shared = await fakeOpenAi({ adminKey: ADMIN });
});
after(async () => {
  await must(shared).close();
});

/** The suites ask for a key at no location: this issuer stores the test project as its location. */
const withProject = (issuer: Issuer): Issuer => ({ ...issuer, issue: (req, intent, m) => issuer.issue({ scope: req.scope, at: AT }, intent, m) });

const entryOfShared = (): PlatformEntry => adapterOver(must(shared)).entry;

issuerContract('openai', () => {
  const entry = entryOfShared();
  return { issuer: withProject(must(entry.issuer)), master: master(), wrongMaster: wrongMaster(), lister: must(entry.lister) };
});

listerContract('openai', () => {
  const entry = entryOfShared();
  return { issuer: withProject(must(entry.issuer)), lister: must(entry.lister), master: master(), wrongMaster: wrongMaster() };
});

verifierContract('openai', () => {
  const entry = entryOfShared();
  return {
    issuer: withProject(must(entry.issuer)),
    verifier: must(entry.verifier),
    master: master(),
    stranger: stranger(),
    setUnreachable: (down) => must(shared).setMode(down ? 'drop' : 'ok'),
  };
});

relayProfileContract('openai', () => must(entryOfShared().relay));

// --- the issuer ---------------------------------------------------------------------------------------------------------------

test('KBOX-38 a rotation keeps the service account and changes only its key: the second issue under the same stem adds a key to the same account', async (t) => {
  const { fake, issuer } = await fresh(t);
  const first = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  const second = await issuer.issue(REQ, 'kbox_shop_g2_bbbb2222', master());
  assert.deepEqual(fake.serviceAccounts(PROJECT).map((a) => a.name), ['kbox_shop']);
  assert.deepEqual(fake.keysOf(PROJECT).map((k) => k.name), ['kbox_shop_g1_aaaa1111', 'kbox_shop_g2_bbbb2222']);
  assert.notEqual(first.platformKeyId, second.platformKeyId);
});

test('KBOX-38 the key the platform makes with a new service account is deleted at once: the account holds only the key the box asked for, with an expiry', async (t) => {
  const { fake, issuer } = await fresh(t);
  const issued = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  const keys = fake.keysOf(PROJECT);
  assert.equal(keys.length, 1);
  assert.equal(keys[0]?.expiresInSeconds, 90 * DAY);
  assert.equal(issued.platformKeyId, `${PROJECT}/${must(keys[0]).id}`);
  assert.equal(issued.expiresAt, (1_000 + 90 * DAY) * 1000);
});

test('KBOX-38 KBOX-57 issue is refused with a fixed error for a request with no project, a project that is not an id, a master scope and any `project:` item; nothing is sent', async (t) => {
  const { fake, issuer } = await fresh(t);
  const refused: readonly IssueRequest[] = [
    { scope: {}, at: {} },
    { scope: {}, at: { region: 'eu' } },
    { scope: {}, at: { project: '../organization' } },
    { scope: {}, at: { project: 'a/b' } },
    { scope: {}, at: { project: '' } },
    { scope: { items: ['organization:admin'] }, at: AT },
    { scope: { items: [`project:${PROJECT}`] }, at: AT },
    { scope: { items: [`project:${PROJECT}`] }, at: {} },
    { scope: { items: ['project:proj_a', 'project:proj_b'] }, at: AT },
  ];
  for (const req of refused) {
    await assert.rejects(() => issuer.issue(req, 'kbox_x_g1_aaaa1111', master()), /^OpenAiError: openai: bad_scope$/, JSON.stringify(req));
  }
  assert.equal(fake.calls.length, 0);
});

test('KBOX-38 KBOX-57 the entry declares the project as its one location field, required of ordinary and admin keys, with the id pattern', async (t) => {
  const { entry } = await fresh(t);
  const field = entry.location?.project;
  assert.deepEqual(field?.requiredFor, ['ordinary', 'admin']);
  assert.ok(field?.pattern.test(PROJECT) === true && field.pattern.test('../x') === false);
  assert.equal(entry.location?.region, undefined);
});

test('KBOX-38 KBOX-57 the project the key is made in is the stored location, and no other', async (t) => {
  const { fake, issuer } = await fresh(t);
  const other = await fakeOpenAi({ adminKey: ADMIN, projects: ['proj_other'] });
  t.after(() => other.close());
  await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  assert.equal(fake.keysOf(PROJECT).length, 1);
  await assert.rejects(() => adapterOver(other).issuer.issue(REQ, 'kbox_x_g1_aaaa1111', master()), /openai: not_found/);
  assert.equal(other.keysOf('proj_other').length, 0);
});

test('KBOX-38 a project the platform does not know is a fixed not_found; a refused master is rejected, an answer of 500 is upstream_error', async (t) => {
  const { fake, issuer } = await fresh(t);
  await assert.rejects(() => issuer.issue({ scope: {}, at: { project: 'proj_nowhere' } }, 'kbox_x_g1_aaaa1111', master()), /openai: not_found/);
  await assert.rejects(() => issuer.issue(REQ, 'kbox_x_g1_aaaa1111', wrongMaster()), /openai: rejected/);
  fake.setMode('500');
  await assert.rejects(() => issuer.issue(REQ, 'kbox_x_g1_aaaa1111', master()), /openai: upstream_error/);
});

test('KBOX-38 a platform that cannot be reached is a thrown fixed error naming nothing of the transport', async (t) => {
  const { fake, issuer } = await fresh(t);
  fake.setMode('drop');
  await assert.rejects(
    () => issuer.revoke(`${PROJECT}/key_0001`, master()),
    (e: unknown) => e instanceof Error && e.message === 'openai: unreachable',
  );
});

test('KBOX-38 a revoke of an id that is not <project>/<key> in the platform alphabet is absent and sends nothing (no path can be built from it)', async (t) => {
  const { fake, issuer } = await fresh(t);
  for (const id of ['', 'key_1', '/key_1', `${PROJECT}/`, 'a/b/c', `${PROJECT}/../x`, `${PROJECT}/key_1?x=1`, `${PROJECT}/key%2F1`, `..%2f/key_1`]) {
    assert.equal(await issuer.revoke(id, master()), 'absent', id);
  }
  assert.equal(fake.calls.length, 0);
});

test('KBOX-38 a revoke the platform answers 404 is absent, one it answers 500 throws, and a revoked key is gone from the platform', async (t) => {
  const { fake, issuer } = await fresh(t);
  const issued = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  assert.equal(await issuer.revoke(`${PROJECT}/key_9999`, master()), 'absent');
  fake.setMode('500');
  await assert.rejects(() => issuer.revoke(issued.platformKeyId, master()), /openai: upstream_error/);
  fake.setMode('ok');
  assert.equal(await issuer.revoke(issued.platformKeyId, master()), 'revoked');
  assert.deepEqual(fake.keysOf(PROJECT), []);
});

test('KBOX-38 the capabilities: api create and revoke, overlap, reveal once, no set, scope items, class by scope (an organization admin scope is master)', async (t) => {
  const { issuer } = await fresh(t);
  const caps = issuer.capabilities();
  assert.deepEqual([caps.create, caps.revoke, caps.overlap, caps.set, caps.revealOnce, caps.scopeSchema.fields], ['api', 'api', true, 'none', true, ['items']]);
  assert.equal(caps.classify({}, AT), 'ordinary');
  assert.equal(caps.classify({ items: ['organization:admin'] }, AT), 'master');
  assert.equal(caps.classify({}, {}), 'ordinary');
  assert.equal(issuer.set, undefined);
});

// --- the lister -----------------------------------------------------------------------------------------------------------------

test('KBOX-38 KBOX-51 a listing reads every page of a project: five keys over pages of two are complete, each located at the project', async (t) => {
  const { entry, issuer } = await fresh(t);
  const lister = must(entry.lister);
  for (let i = 1; i <= 4; i += 1) await issuer.issue(REQ, `kbox_shop_g${i}_aaaa1111`, master());
  await issuer.issue(REQ, 'kbox_other_g1_aaaa1111', master());
  const listing = await lister.listAt({ project: PROJECT }, master());
  assert.equal(listing.complete, true);
  assert.deepEqual(listing.at, { project: PROJECT });
  assert.equal(listing.keys.length, 5);
  assert.ok(listing.keys.every((k) => k.location?.project === PROJECT && k.platformKeyId.startsWith(`${PROJECT}/`)));
});

test('KBOX-38 KBOX-51 a listing whose platform keeps saying there is more on the same cursor is incomplete, never complete', async (t) => {
  const { fake, entry, issuer } = await fresh(t);
  await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  fake.setMode('stuck-pages');
  const listing = await must(entry.lister).listAt({ project: PROJECT }, master());
  assert.equal(listing.complete, false);
});

test('KBOX-38 KBOX-51 a listing the platform could not answer (500, dropped connection) is incomplete; a refused master throws', async (t) => {
  const { fake, entry } = await fresh(t);
  const lister = must(entry.lister);
  for (const mode of ['500', 'drop'] as const) {
    fake.setMode(mode);
    const listing = await lister.listAt({ project: PROJECT }, master());
    assert.deepEqual([mode, listing.complete, listing.keys.length], [mode, false, 0]);
  }
  fake.setMode('ok');
  await assert.rejects(() => lister.listAt({ project: PROJECT }, wrongMaster()), /openai: rejected/);
});

test('KBOX-38 KBOX-51 a project the platform no longer has lists complete and empty: its keys are gone with it', async (t) => {
  const { entry } = await fresh(t);
  const listing = await must(entry.lister).listAt({ project: 'proj_gone' }, master());
  assert.deepEqual([listing.complete, listing.keys.length], [true, 0]);
});

test('KBOX-38 a location whose project is not an id is a fixed bad_scope and sends nothing', async (t) => {
  const { fake, entry } = await fresh(t);
  await assert.rejects(() => must(entry.lister).listAt({ project: '../organization' }, master()), /openai: bad_scope/);
  assert.equal(fake.calls.length, 0);
});

// --- the verifier ---------------------------------------------------------------------------------------------------------------

test('KBOX-38 the verifier calls GET /v1/models with the key as bearer; a 401 is rejected, a 500 is unreachable', async (t) => {
  const { fake, entry, issuer, http } = await fresh(t);
  const issued = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  const verifier = must(entry.verifier);
  assert.equal(await verifier.verify(issued.value, { platform: 'openai', at: AT }), 'ok');
  const call = must(http.sent[http.sent.length - 1]);
  assert.deepEqual([call.method, call.target, call.originalHost, call.headers['authorization']], ['GET', '/v1/models', 'api.openai.com', `Bearer ${await text(issued.value)}`]);
  assert.equal(await verifier.verify(stranger(), { platform: 'openai', at: AT }), 'rejected');
  fake.setMode('500');
  assert.equal(await verifier.verify(issued.value, { platform: 'openai', at: AT }), 'unreachable');
  fake.setMode('401-echo');
  assert.equal(await verifier.verify(issued.value, { platform: 'openai', at: AT }), 'rejected');
});

// --- the value rules (KBOX-14) --------------------------------------------------------------------------------------------------

test('KBOX-14 a platform that quotes the key it was sent in a 401, or the key it would have issued in a 500, shows it in no error of any operation', async (t) => {
  const { fake, entry, issuer } = await fresh(t);
  const c = canary(40);
  const hex = Buffer.from(c.bytes).toString('hex');
  const planted = lent(Buffer.from(`sk-admin-kbox-test-${hex}`), 'planted:1');
  /** Everything a failed call shows: the error as inspected, and its message, stack and cause. A call that does not fail fails the test. */
  const errorText = async (call: () => Promise<unknown>): Promise<string> => {
    try {
      await call();
    } catch (e) {
      return [inspect(e, { depth: 6 }), e instanceof Error ? `${e.message} ${String(e.stack)} ${inspect(e.cause)}` : String(e)].join('\n');
    }
    throw new Error('the call was expected to fail and did not');
  };
  fake.setMode('401-echo');
  const failures = [
    await errorText(() => issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', planted)),
    await errorText(() => issuer.revoke(`${PROJECT}/key_1`, planted)),
    await errorText(() => must(entry.lister).list(planted)),
    await errorText(() => must(entry.lister).listAt({ project: PROJECT }, planted)),
  ];
  assert.equal(await must(entry.verifier).verify(planted, { platform: 'openai', at: AT }), 'rejected');
  c.assertAbsent({ errors: failures.join('\n') });

  // the key the platform would issue, echoed by a failing create and carried by a create answer that is cut short of its id
  const issuedFake = await fakeOpenAi({ adminKey: `sk-admin-kbox-test-${hex}` });
  t.after(() => issuedFake.close());
  const over = adapterOver(issuedFake);
  const later: string[] = [];
  for (const mode of ['create-500-echo', 'create-bad-shape'] as const) {
    issuedFake.setMode(mode);
    later.push(await errorText(() => over.issuer.issue(REQ, `kbox_shop_${mode.replaceAll('-', '_')}_g1_aaaa1111`, planted)));
  }
  for (const fakeValue of [...later]) assert.equal(fakeValue.includes('sk-svcacct-'), false, 'a key the platform would have issued is in an error');
});

test('KBOX-14 an issued value is a Lent: printing, inspecting and JSON of the issued key show no key text', async (t) => {
  const { issuer } = await fresh(t);
  const issued = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  const value = await text(issued.value);
  for (const shown of [String(issued.value), inspect(issued), JSON.stringify(issued)]) assert.equal(shown.includes(value), false);
});

test('KBOX-14 a create answer with no usable value or id is a fixed bad_response', async (t) => {
  const { fake, issuer } = await fresh(t);
  fake.setMode('create-bad-shape');
  await assert.rejects(() => issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master()), /^OpenAiError: openai: bad_response/);
});

// --- the shape ------------------------------------------------------------------------------------------------------------------

const shape = (): NonNullable<ReturnType<typeof shapeOf>> => must(shapeOf(adapterOver(must(shared)).entry));
/** The box's strict shape check on a pasted value: it has a tier (KBOX-18) only when prefix, alphabet and core length fit. */
const accepts = (value: string): boolean => assess({ shape: shape(), value, origin: 'pasted' }).tier !== 'none';

test('KBOX-18 KBOX-38 shape: an sk-admin- and an sk-svcacct- key of real format are accepted; a wrong prefix, a short core and a wrong alphabet are refused', () => {
  const core = 'AbCdEfGh0123456789_-'.repeat(8);
  assert.equal(accepts(`sk-admin-${core}`), true);
  assert.equal(accepts(`sk-svcacct-${core}`), true);
  assert.equal(accepts(`pk-admin-${core}`), false);
  assert.equal(accepts(`sk_admin_${core}`), false);
  assert.equal(accepts('sk-admin-short'), false);
  assert.equal(accepts(`sk-admin-${core.slice(0, 20)}`), false);
  assert.equal(accepts(`sk-admin-${core} ${core}`), false);
  assert.equal(accepts(`sk-admin-${core.slice(0, 60)}!${core.slice(0, 20)}`), false);
  assert.equal(accepts(`sk-admin-${'A'.repeat(300)}`), false);
});

test('KBOX-18 KBOX-38 shape: a long random key of this shape is windowed, as the spec says of an admin key', () => {
  const sample = `sk-admin-${'AbCdEfGh0123456789_-'.repeat(5)}`;
  assert.equal(assess({ shape: shape(), value: sample, origin: 'pasted' }).tier, 'windowed');
});

// --- the entry ------------------------------------------------------------------------------------------------------------------

test('KBOX-23 KBOX-38 the entry: id, the one host, the key page, the verifier-and-create items still unverified, and the registry passes its checks', () => {
  const registry = createRegistry({ http: adapterHttpTo({ url: 'http://127.0.0.1:1' }), clock: { now: () => 0 } });
  const entry = must(registry.find((e) => e.id === 'openai'));
  assert.deepEqual(entry.hosts, ['api.openai.com']);
  assert.match(entry.keyPageUrl ?? '', /^https:\/\/platform\.openai\.com\//);
  assert.deepEqual([...entry.unverified].sort(), ['openai.admin-key-length', 'openai.create-key-body', 'openai.svcacct-key-length', 'openai.verifier-call']);
  assert.equal(entry.shape, undefined, 'an entry with an issuer takes its shape from the issuer');
  assert.deepEqual(checkRegistry(registry), { ok: true });
  const report = readFileSync(new URL('../docs/probes/openai.md', import.meta.url), 'utf8');
  for (const id of entry.unverified) assert.match(report, new RegExp(`\`${id}\`[^\\n]*STILL UNVERIFIED`));
});

test('KBOX-38 every network call the adapter made went to api.openai.com over the https URL it was given', async (t) => {
  const { entry, issuer, http } = await fresh(t);
  const issued = await issuer.issue(REQ, 'kbox_shop_g1_aaaa1111', master());
  await must(entry.lister).list(master());
  await must(entry.verifier).verify(issued.value, { platform: 'openai', at: AT });
  await issuer.revoke(issued.platformKeyId, master());
  assert.ok(http.sent.length > 4);
  assert.ok(http.sent.every((r) => r.originalHost === 'api.openai.com'));
});

// --- the relay profile ----------------------------------------------------------------------------------------------------------

const profile = (): RelayProfile => must(adapterOver(must(shared)).entry.relay);
const OPENAI_REF = 'openaikey1';

const engineOf = (p: RelayProfile) => {
  const compiled = compileProfile(p);
  if (!compiled.ok) throw new Error(`profile refused: ${compiled.code}`);
  return compiled.engine;
};

test('KBOX-38 the openai profile allows exactly the listed operations and no other', () => {
  const p = profile();
  assert.equal(p.origin.kind === 'fixed' && p.origin.host, 'api.openai.com');
  assert.deepEqual(
    p.allow.map((r) => `${r.method} ${r.pathTemplate}`).sort(),
    ['GET /v1/models', 'POST /v1/audio/speech', 'POST /v1/audio/transcriptions', 'POST /v1/audio/translations', 'POST /v1/chat/completions', 'POST /v1/embeddings', 'POST /v1/responses'],
  );
  assert.deepEqual(p.tailRules, []);
  assert.deepEqual(
    p.mustDeny.map((d) => d.id),
    ['organization', 'realtime-client-secrets', 'realtime-translation-secrets', 'realtime-transcription-sessions', 'realtime-sessions', 'chatkit-sessions', 'chatkit-session-cancel', 'webhook-endpoints'],
  );
  assert.deepEqual(p.envForClients('https://api.keys.box.example/r/abc123'), { OPENAI_BASE_URL: 'https://api.keys.box.example/r/abc123/v1', OPENAI_API_KEY: '<pass>' });
});

/** The relay target of a sample: its raw path under the key (never URL-normalised). */
const targetOf = (url: string): string => `/r/${OPENAI_REF}${url.slice(url.indexOf('/', 'https://'.length))}`;

const BROAD = ['/{rest:**}', '/v1/{rest:**}', '/v1/organization/{rest:**}', '/v1/organization/projects/{rest:**}', '/v1/realtime/{rest:**}', '/v1/chatkit/{rest:**}', '/v1/chatkit/sessions/{rest:**}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}/{b:[A-Za-z0-9_.-]{1,128}}'];

/** The profile with every broad rule added that the widening check still accepts: as wide as the registry permits. */
function widened(p: RelayProfile): RelayProfile {
  const engine = engineOf(p);
  const added: AllowRule[] = [];
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const [i, pathTemplate] of BROAD.entries()) {
      const rule: AllowRule = { id: `wide-${method.toLowerCase()}-${i}`, method, host: 'api.openai.com', pathTemplate, query: {} };
      if (refuseWidening(engine, [rule], [rule.id]).ok) added.push(rule);
    }
  }
  assert.ok(added.length > 0, 'the widening added rules');
  return { ...p, allow: [...p.allow, ...added], tailRules: [...p.tailRules, ...added.map((r) => r.id)] };
}

/** Sends every sample through a running relay whose openai entry carries `p`; returns each one that got anything but 400 or 403, or reached upstream. */
async function leaks(t: TestContext, p: RelayProfile, rules: readonly DenyRule[]): Promise<string[]> {
  const base = must(adapterOver(must(shared)).entry);
  const w = await relayWorld(t, { registry: [...TEST_REGISTRY, { ...base, relay: p }] });
  w.lend.addKey({ keyref: OPENAI_REF, value: Buffer.from(`sk-admin-kbox-test-${Buffer.from(w.canary.bytes).toString('hex')}`), platform: 'openai', grants: ['laptop'] });
  const through: string[] = [];
  for (const rule of rules) {
    for (const sample of rule.samples) {
      const before = w.upstream.requests.length;
      const reply = await w.call(targetOf(sample.url), { method: sample.method });
      if ((reply.status !== 400 && reply.status !== 403) || w.upstream.requests.length !== before) through.push(`${rule.id} ${sample.method} ${sample.url} -> ${reply.status}`);
    }
  }
  return through;
}

test('KBOX-13 KBOX-25 KBOX-38 every mustDeny sample of the openai profile and every canonicalisation variant is 400 or 403 with no upstream call, default and widened', async (t) => {
  const p = profile();
  assert.ok(p.mustDeny.every((d) => d.samples.length >= 10), 'each rule carries the KBOX-13 variants');
  assert.deepEqual(await leaks(t, p, p.mustDeny), []);
  assert.deepEqual(await leaks(t, widened(p), p.mustDeny), []);
});

test('KBOX-23 KBOX-38 positive control: a profile that allows POST /v1/organization/{rest:**} fails the registry check against these mustDeny samples', () => {
  const p = profile();
  const leaky: RelayProfile = { ...p, allow: [...p.allow, { id: 'org-anything', method: 'POST', host: 'api.openai.com', pathTemplate: '/v1/organization/{rest:**}', query: {} }], tailRules: ['org-anything'] };
  const base = must(adapterOver(must(shared)).entry);
  assert.deepEqual(checkRegistry([{ ...base, relay: leaky }]), { ok: false, code: 'allow_matches_must_deny', platform: 'openai' });
});

test('KBOX-38 every operation of the profile reaches upstream with the key injected, the pass dropped and nothing else of the caller\'s authority', async (t) => {
  const p = profile();
  const w = await relayWorld(t, { registry: [...TEST_REGISTRY, must(adapterOver(must(shared)).entry)] });
  const value = `sk-admin-kbox-test-${Buffer.from(w.canary.bytes).toString('hex')}`;
  w.lend.addKey({ keyref: OPENAI_REF, value: Buffer.from(value), platform: 'openai', grants: ['laptop'] });
  for (const rule of p.allow) {
    const before = w.upstream.requests.length;
    const reply = await w.call(`/r/${OPENAI_REF}${rule.pathTemplate}`, { method: rule.method });
    assert.equal(reply.status, 200, rule.id);
    const seen = must(w.upstream.requests[before]);
    assert.equal(seen.headers['authorization'], `Bearer ${value}`, rule.id);
    assert.equal(w.upstream.requests.length, before + 1);
  }
  assert.equal((await w.call(`/r/${OPENAI_REF}/v1/models`, { method: 'DELETE' })).status, 403);
});

test('KBOX-14 KBOX-38 an upstream 401 that quotes the key masked is replaced end to end through the relay: the caller gets the fixed body and 401', async (t) => {
  const w = await relayWorld(t, { registry: [...TEST_REGISTRY, must(adapterOver(must(shared)).entry)] });
  const value = `sk-admin-kbox-test-${Buffer.from(w.canary.bytes).toString('hex')}`;
  w.lend.addKey({ keyref: OPENAI_REF, value: Buffer.from(value), platform: 'openai', grants: ['laptop'] });
  w.upstream.respond((_req, res) => {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${value.slice(0, 8)}******${value.slice(-4)}.`, type: 'invalid_request_error', param: null, code: 'invalid_api_key' } }));
  });
  const reply = await w.call(`/r/${OPENAI_REF}/v1/models`);
  assert.deepEqual([reply.status, reply.body.toString()], [401, upstreamRefusedBody()]);
  w.canary.assertAbsent({ body: reply.body, headers: JSON.stringify(reply.headers) });
  const forms = scanForms(value);
  assert.ok(forms.ok);
  assert.equal(forms.forms.some((f) => reply.body.includes(Buffer.from(f.bytes))), false);
});

const sdkRequest = JSON.parse(readFileSync(new URL('./fixtures/openai-sdk-request.json', import.meta.url), 'utf8')) as {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
};

test('KBOX-32 KBOX-38 the OpenAI SDK request shape (client.models.list under baseURL <relay>/v1) replayed through the relay reaches the models rule', async (t) => {
  const p = profile();
  const parsed = parseRelayTarget(`/r/abc123/v1${sdkRequest.path}`);
  assert.ok(parsed.ok);
  assert.equal(engineOf(p).decide(sdkRequest.method, parsed.value).ok, true);
  const w = await relayWorld(t, { registry: [...TEST_REGISTRY, must(adapterOver(must(shared)).entry)] });
  const value = `sk-admin-kbox-test-${Buffer.from(w.canary.bytes).toString('hex')}`;
  w.lend.addKey({ keyref: OPENAI_REF, value: Buffer.from(value), platform: 'openai', grants: ['laptop'] });
  const headers = { ...sdkRequest.headers, authorization: `Bearer ${w.pass}` };
  const reply = await w.call(`/r/${OPENAI_REF}/v1${sdkRequest.path}`, { method: sdkRequest.method, headers });
  assert.equal(reply.status, 200);
  const seen = must(w.upstream.requests[0]);
  assert.equal(seen.headers['authorization'], `Bearer ${value}`);
});
