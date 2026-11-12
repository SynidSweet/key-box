// KBOX-37 on KBOX-57: the Supabase adapter, over a loopback fake of the Management API (test/fakes/supabase.ts) through `adapterHttpTo`, its
// location prover through the real `POST /api/keys` route, and its relay profile through the running relay. Values are synthetic (`kbox-test`).
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import type { TestContext } from 'node:test';
import { HttpTransportError } from '../src/ports/http.ts';
import type { AdapterHttp } from '../src/ports/http.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { AllowRule, DenyRule, RelayProfile } from '../src/ports/relay-profile.ts';
import type { KeyLocation, Lent } from '../src/ports/types.ts';
import { assess } from '../src/pure/coverage.ts';
import { checkLocation } from '../src/pure/location.ts';
import { checkRegistry, compileProfile, refuseWidening } from '../src/pure/profile.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import { classify } from '../src/platforms/supabase/scope.ts';
import { createSupabaseEntry, createPasswordSetter } from '../src/platforms/supabase/index.ts';
import { SupabaseError } from '../src/platforms/supabase/errors.ts';
import { createManagement } from '../src/platforms/supabase/management.ts';
import { supabaseProfile } from '../src/platforms/supabase/relay.ts';
import { destinationContract } from './contracts/destination.contract.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { relayProfileContract } from './contracts/relay-profile.contract.ts';
import { MASTER_TEXT, OTHER_REF, REF, WRONG_TEXT, startFakeSupabase } from './fakes/supabase.ts';
import { TEST_REGISTRY, variants } from './fixtures/profiles.ts';
import { adapterHttpTo, bytesOf, canary, lent } from './kit/index.ts';
import type { FakeAdapterHttp } from './kit/index.ts';
import { relayWorld } from './support/relay-world.ts';
import { routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';

const fake = await startFakeSupabase();
after(() => fake.close());

const master = (): Lent => lent(Buffer.from(MASTER_TEXT), 'master:1');
const stranger = (): Lent => lent(Buffer.from(WRONG_TEXT), 'stranger:1');
const textOf = async (v: Lent): Promise<string> => Buffer.from(await bytesOf(v)).toString('utf8');
const entryOver = (http: AdapterHttp): PlatformEntry => createSupabaseEntry({ http, clock: { now: () => 0 } });

/** A fresh fake and the entry over it. `http` is replaceable so a test can make the transport fail. */
function subject(http?: AdapterHttp) {
  fake.reset();
  const recording: FakeAdapterHttp = adapterHttpTo(fake);
  const entry = entryOver(http ?? recording);
  const { issuer, lister, destinations, locationProver } = entry;
  if (issuer === undefined || lister === undefined || locationProver === undefined || destinations?.[0] === undefined) throw new Error('entry incomplete');
  return { entry, issuer, lister, prover: locationProver, destination: destinations[0].destination, http: recording };
}

const codeOf = async (run: () => Promise<unknown>): Promise<string> =>
  run().then(
    () => 'no error',
    (e: unknown) => (e instanceof SupabaseError ? e.code : `other: ${String(e)}`),
  );

const DOWN: AdapterHttp = { request: () => Promise.reject(new HttpTransportError('unreachable')) };
const AT: KeyLocation = { project: REF };
const SECRET = { items: ['secret'] };

// ---------------------------------------------------------------- the contract suites

issuerContract('supabase', () => {
  const s = subject();
  return { issuer: s.issuer, master: master(), wrongMaster: stranger(), lister: s.lister };
}, AT);
listerContract('supabase', () => {
  const s = subject();
  return { issuer: s.issuer, lister: s.lister, master: master(), wrongMaster: stranger() };
}, AT);
destinationContract('supabase', () => {
  const s = subject();
  return {
    destination: s.destination,
    target: { kind: 'supabase-secret', id: REF },
    master: master(),
    valueOne: lent(Buffer.from('kbox-test-value-one'), 'one:1'),
    valueTwo: lent(Buffer.from('kbox-test-value-two'), 'two:1'),
    has: (name) => fake.secrets.get(REF)?.has(name) === true,
  };
});
relayProfileContract('supabase', () => supabaseProfile);

// ---------------------------------------------------------------- the entry and its placement (KBOX-57)

test('KBOX-37 KBOX-57 the entry declares the project as its one location: 20 lower-case letters, required of ordinary and admin keys, naming the relay host', () => {
  const { entry } = subject();
  assert.deepEqual(entry.location, { project: { pattern: /^[a-z]{20}$/, requiredFor: ['ordinary', 'admin'], namesHost: true } });
  for (const klass of ['ordinary', 'admin'] as const) {
    assert.equal(checkLocation(entry.location, AT, klass, []), 'ok', klass);
    assert.equal(checkLocation(entry.location, {}, klass, []), 'location_missing', klass);
  }
  assert.equal(checkLocation(entry.location, {}, 'master', []), 'ok', 'a personal access token belongs to no project');
  for (const bad of ['abcdefghijklmnopqrs', 'abcdefghijklmnopqrstu', 'Abcdefghijklmnopqrst', 'abcdefghijklmnopqrs1', `${REF}.supabase.co`, `x${REF}`, ''])
    assert.equal(checkLocation(entry.location, { project: bad }, 'admin', []), 'location_bad_value', JSON.stringify(bad));
  assert.equal(checkLocation(entry.location, { project: REF, region: 'eu' }, 'admin', []), 'location_field_unknown');
  assert.equal(checkLocation(entry.location, AT, 'admin', [`project:${REF}`]), 'location_in_scope', 'a project: scope item is a second placement source');
});

test('KBOX-37 the entry states what it is: hosts, an issuer that reveals once with a lister, a location prover, no verifier, one secrets destination readable by api, and it passes the registry checks', () => {
  const s = subject();
  assert.deepEqual(s.entry.hosts, ['api.supabase.com']);
  assert.equal(s.issuer.capabilities().revealOnce, true);
  assert.equal(s.entry.verifier, undefined);
  assert.equal(s.destination.kind, 'supabase-secret');
  assert.deepEqual(s.destination.properties(), { readableBy: 'api', needsRedeploy: false });
  assert.deepEqual(s.entry.relay?.origin, { kind: 'project-host', domain: 'supabase.co', refLength: 20 });
  assert.equal(s.entry.unverified.includes('supabase.project-get-shape'), true);
  assert.deepEqual(checkRegistry([s.entry]), { ok: true });
});

// ---------------------------------------------------------------- the location prover (KBOX-57 Proof)

test('KBOX-57 the prover asks GET /v1/projects/{ref} on the Management API with the master as bearer, and a 200 naming that project is seen', async () => {
  const s = subject();
  assert.equal(await s.prover.prove(AT, master()), 'seen');
  assert.deepEqual(s.http.sent.map((r) => [r.method, r.originalHost, r.target, r.headers['authorization']]), [['GET', 'api.supabase.com', `/v1/projects/${REF}`, `Bearer ${MASTER_TEXT}`]]);
});

test('KBOX-57 the prover answers unseen for a project the master cannot see: 404 (no such project for this account) and 403 (not this account)', async () => {
  const s = subject();
  assert.equal(await s.prover.prove({ project: OTHER_REF }, master()), 'unseen', '404');
  fake.mode = 'gone-project';
  assert.equal(await s.prover.prove(AT, master()), 'unseen', '404 for a project that went');
  fake.mode = '403';
  assert.equal(await s.prover.prove(AT, master()), 'unseen', '403');
});

test('KBOX-57 every other prover answer throws, never seen or unseen: 401, 429, 5xx, transport failure, a malformed body, a 200 naming another project or none', async () => {
  const s = subject();
  assert.equal(await codeOf(() => s.prover.prove(AT, stranger())), 'rejected', '401');
  for (const [mode, code] of [['429', 'rate_limited'], ['500', 'server'], ['malformed', 'bad_answer'], ['other-ref', 'bad_answer'], ['no-ref', 'bad_answer']] as const) {
    fake.mode = mode;
    assert.equal(await codeOf(() => s.prover.prove(AT, master())), code, mode);
  }
  assert.equal(await codeOf(() => subject(DOWN).prover.prove(AT, master())), 'unreachable');
});

test('KBOX-57 the prover refuses a location with no project or a value that is not a ref before any call', async () => {
  const s = subject();
  for (const at of [{}, { project: 'short' }, { project: `${REF}.evil` }, { project: '../projects' }, { region: REF }])
    assert.equal(await codeOf(() => s.prover.prove(at, master())), 'bad_project', JSON.stringify(at));
  assert.equal(s.http.sent.length, 0);
});

// ---------------------------------------------------------------- the prover at the route (POST /api/keys)

/** The route world with this file's Supabase entry registered as itself, its master the fake's PAT. */
async function supabaseRoutes(t: TestContext): Promise<{ readonly w: RoutesWorld; readonly http: FakeAdapterHttp }> {
  fake.reset();
  const http = adapterHttpTo(fake);
  const entry = entryOver(http);
  const box: { w?: RoutesWorld } = {};
  const w = await routesWorld(t, {
    source: (real) => ({
      ...real,
      platform: (id) => {
        if (id !== 'supabase') return real.platform(id);
        assert.ok(box.w);
        const routes = box.w;
        return createPlatformSource({ registry: [entry], meta: routes.parts.meta, vault: routes.parts.vault, keyInfo: (keyref) => routes.rotation.store.keyInfo(keyref) }).platform(id);
      },
      master: (platform, at, items) => (platform === 'supabase' ? { ok: true, value: master() } : real.master(platform, at, items)),
    }),
  });
  box.w = w;
  return { w, http };
}
const supabaseKey = (over: object): object => ({ platform: 'supabase', name: 'SUPABASE_KEY', projects: ['shop'], scope: { items: ['publishable'] }, ...over });
const rowsOf = (w: RoutesWorld): string => JSON.stringify([w.parts.db.prepare('SELECT * FROM keys').all(), w.parts.db.prepare('SELECT * FROM rotation_keys').all()]);
const openedIn = (w: RoutesWorld): number => (w.parts.db.prepare('SELECT (SELECT count(*) FROM approvals) + (SELECT count(*) FROM paste_tasks) AS n').get() as { n: number }).n;
const detailOf = (reply: { json(): unknown }): string | undefined => (reply.json() as { error?: { detail?: { code?: string } } }).error?.detail?.code;

test('KBOX-57 at the route, a project the master cannot see (404 or 403) is rejected location_unknown: nothing written, opened or made, and no key call', async (t) => {
  const { w, http } = await supabaseRoutes(t);
  const before = rowsOf(w);
  for (const [mode, project] of [['ok', OTHER_REF], ['403', REF]] as const) {
    fake.mode = mode;
    for (const scope of [{ items: ['publishable'] }, SECRET]) {
      const reply = await w.api('/api/keys', { json: supabaseKey({ scope, location: { project } }) });
      assert.deepEqual([reply.status, detailOf(reply)], [422, 'location_unknown'], `${mode} ${project}: ${reply.body}`);
    }
  }
  assert.equal(rowsOf(w), before);
  assert.equal(openedIn(w), 0);
  assert.deepEqual(http.sent.map((r) => [r.method, r.target]), [['GET', `/v1/projects/${OTHER_REF}`], ['GET', `/v1/projects/${OTHER_REF}`], ['GET', `/v1/projects/${REF}`], ['GET', `/v1/projects/${REF}`]], 'only the proof was asked');
});

test('KBOX-57 at the route, a prover that throws (401, 5xx, a 200 about another project, transport) makes the proposal unavailable: nothing written or opened', async (t) => {
  const { w } = await supabaseRoutes(t);
  const before = rowsOf(w);
  for (const mode of ['500', 'other-ref', 'malformed'] as const) {
    fake.mode = mode;
    const reply = await w.api('/api/keys', { json: supabaseKey({ location: AT }) });
    assert.deepEqual([reply.status, (reply.json() as { error: { code: string } }).error.code], [503, 'unavailable'], `${mode}: ${reply.body}`);
  }
  fake.mode = 'ok';
  fake.masterText = WRONG_TEXT;
  const refused = await w.api('/api/keys', { json: supabaseKey({ location: AT }) });
  assert.equal(refused.status, 503, `401: ${refused.body}`);
  assert.equal(rowsOf(w), before);
  assert.equal(openedIn(w), 0);
});

test('KBOX-57 at the route, a proven project is where the key is made: the proof and the create name the same stored project, and a project: scope item is refused before any call', async (t) => {
  const { w, http } = await supabaseRoutes(t);
  fake.projects.push(OTHER_REF);
  const inScope = await w.api('/api/keys', { json: supabaseKey({ scope: { items: ['publishable', `project:${OTHER_REF}`] }, location: AT }) });
  assert.deepEqual([inScope.status, detailOf(inScope)], [422, 'location_in_scope'], inScope.body);
  assert.equal(http.sent.length, 0);
  const made = await w.api('/api/keys', { json: supabaseKey({ location: { project: OTHER_REF } }) });
  assert.equal(made.status, 201, made.body);
  assert.deepEqual(http.sent.map((r) => [r.method, r.target]), [['GET', `/v1/projects/${OTHER_REF}`], ['POST', `/v1/projects/${OTHER_REF}/api-keys?reveal=true`]]);
  assert.equal(fake.keys.get(OTHER_REF)?.length, 1);
  assert.equal(fake.keys.get(REF), undefined, 'nothing was made in the other project the master sees');
});

// ---------------------------------------------------------------- the issuer

test('KBOX-37 a create asks reveal=true with the type and the intent name, and the value is the answer api_key; the key id carries the project', async () => {
  const s = subject();
  const issued = await s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_shop_g2_ab12cd34', master());
  const sent = s.http.sent[0];
  assert.equal(sent?.method, 'POST');
  assert.equal(sent?.target, `/v1/projects/${REF}/api-keys?reveal=true`);
  assert.equal(sent?.originalHost, 'api.supabase.com');
  assert.deepEqual(JSON.parse(Buffer.from(sent?.body ?? []).toString('utf8')), { type: 'secret', name: 'kbox_shop_g2_ab12cd34' });
  assert.equal(sent?.headers['authorization'], `Bearer ${MASTER_TEXT}`);
  assert.match(await textOf(issued.value), /^sb_secret_kbox-test_/);
  assert.equal(issued.platformKeyId.startsWith(`${REF}:`), true);
  assert.equal(issued.location, undefined, 'the create answer names no project: the call path fixes it, and the request is never copied back');
});

test('KBOX-57 the project comes only from the stored location: it picks the project among several the master sees, and with none the issue is refused before any call (no fallback to a sole project)', async () => {
  const s = subject();
  fake.projects.push(OTHER_REF);
  const named = await s.issuer.issue({ scope: SECRET, at: { project: OTHER_REF } }, 'kbox_abcd', master());
  assert.equal(named.platformKeyId.startsWith(`${OTHER_REF}:`), true);
  assert.deepEqual(s.http.sent.map((r) => r.target), [`/v1/projects/${OTHER_REF}/api-keys?reveal=true`]);
  fake.projects.splice(0, fake.projects.length, REF);
  for (const at of [{}, { project: 'SHORT' }, { project: `${REF}x` }, { region: REF }])
    assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at }, 'kbox_abce', master())), 'bad_project', JSON.stringify(at));
  assert.equal(s.http.sent.length, 1, 'no call for a location without a project, even when the master sees exactly one');
});

test('KBOX-57 a project: scope item is bad_scope before any call, even naming the stored project; so are the master item and an unknown item', async () => {
  const s = subject();
  for (const items of [[`project:${REF}`], ['secret', `project:${REF}`], [`project:${OTHER_REF}`, 'publishable'], ['access-token'], ['secret', 'access-token'], ['secret', 'admin']])
    assert.equal(await codeOf(() => s.issuer.issue({ scope: { items }, at: AT }, 'kbox_abcd', master())), 'bad_scope', JSON.stringify(items));
  assert.equal(await codeOf(() => s.issuer.issue({ scope: { items: `project:${REF}` }, at: AT }, 'kbox_abcd', master())), 'bad_scope', 'a single item as a string');
  assert.equal(s.http.sent.length, 0);
});

test('KBOX-37 KBOX-57 the master item access-token is master whatever else is asked; secret is admin and the default; publishable is ordinary only alone; the location never changes the class', () => {
  for (const at of [{}, AT, { project: OTHER_REF }]) {
    assert.equal(classify({ items: ['access-token'] }, at), 'master');
    assert.equal(classify({ items: ['publishable', 'access-token'] }, at), 'master');
    assert.equal(classify({ items: 'access-token' }, at), 'master');
    assert.equal(classify({ items: ['secret'] }, at), 'admin');
    assert.equal(classify({ items: [] }, at), 'admin');
    assert.equal(classify({ access: 'read' }, at), 'admin');
    assert.equal(classify({ items: ['publishable'] }, at), 'ordinary');
    assert.equal(classify({ items: 'publishable' }, at), 'ordinary');
    assert.equal(classify({ items: ['publishable', 'secret'] }, at), 'admin');
  }
});

test('KBOX-37 a publishable create sends type publishable', async () => {
  const s = subject();
  await s.issuer.issue({ scope: { items: ['publishable'] }, at: AT }, 'kbox_abcd', master());
  assert.equal(JSON.parse(Buffer.from(s.http.sent.at(-1)?.body ?? []).toString('utf8')).type, 'publishable');
});

test('KBOX-37 a reveal answer with api_key null is a fixed error, nothing is stored, and the key the platform made is revoked again', async () => {
  const s = subject();
  fake.mode = 'null-key';
  assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master())), 'no_key_value');
  assert.equal(fake.keys.get(REF)?.length, 0, 'the orphan was revoked');
});

test('KBOX-37 when the orphan of a null reveal cannot be revoked either, the error says so', async () => {
  const s = subject();
  const failingDelete: AdapterHttp = { request: (r) => (r.method === 'DELETE' ? Promise.reject(new HttpTransportError('timeout')) : s.http.request(r)) };
  const t = subject(failingDelete);
  fake.mode = 'null-key';
  assert.equal(await codeOf(() => t.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master())), 'no_key_value_not_cleaned');
});

// ---------------------------------------------------------------- failure shapes

test('KBOX-14 a refusing platform is rejected, a limit is rate_limited, a fault is server, junk is bad_answer: fixed codes whatever the body says', async () => {
  const s = subject();
  assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', stranger())), 'rejected');
  fake.mode = '429';
  assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master())), 'rate_limited');
  assert.equal(await codeOf(() => s.lister.list(master())), 'rate_limited');
  fake.mode = '500';
  assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master())), 'server');
  assert.equal(await codeOf(() => s.issuer.revoke(`${REF}:00000000-0000-4000-8000-000000000001`, master())), 'server');
  fake.mode = 'malformed';
  assert.equal(await codeOf(() => s.lister.list(master())), 'bad_answer');
});

test('KBOX-14 a transport failure is unreachable for issuer and lister, and a push that could not be answered is unknown, never refused', async () => {
  const s = subject(DOWN);
  assert.equal(await codeOf(() => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master())), 'unreachable');
  assert.equal(await codeOf(() => s.issuer.revoke(`${REF}:00000000-0000-4000-8000-000000000001`, master())), 'unreachable');
  assert.equal(await codeOf(() => s.lister.listAt(AT, master())), 'unreachable');
  const pushed = await s.destination.push({ kind: 'supabase-secret', id: REF }, 'API_KEY', lent(Buffer.from('kbox-test-v'), 'v:1'), 'ordinary', master());
  assert.deepEqual(pushed, { outcome: 'unknown' });
});

test('KBOX-14 the canary: a key echoed by a create answer and a 401 body that quotes the master show in no error, cause or result', async () => {
  const s = subject();
  const c = canary();
  const hex = Buffer.from(c.bytes).toString('hex');
  fake.plant = hex;
  const issued = await s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcd', master());
  const listed = await s.lister.list(master());
  c.assertAbsent({ issued: JSON.stringify(issued) + String(issued.value), listed: JSON.stringify(listed) });
  const bad = lent(Buffer.from(hex), 'canary:1');
  const thrown: unknown[] = [];
  for (const run of [
    () => s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abce', bad),
    () => s.issuer.revoke(issued.platformKeyId, bad),
    () => s.lister.list(bad),
    () => s.prover.prove(AT, bad),
    () => s.destination.remove({ kind: 'supabase-secret', id: REF }, 'API_KEY', bad),
  ]) {
    thrown.push(await run().then(() => undefined, (e: unknown) => e));
  }
  assert.equal(thrown.every((e) => e instanceof SupabaseError), true);
  fake.mode = '500';
  thrown.push(await s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcf', bad).then(() => undefined, (e: unknown) => e));
  thrown.push(await s.prover.prove(AT, bad).then(() => undefined, (e: unknown) => e));
  for (const e of thrown) {
    const err = e as SupabaseError;
    c.assertAbsent({ message: err.message, stack: err.stack ?? '', cause: String(err.cause), json: JSON.stringify(err) });
  }
  // The master itself is a lent value too: a failing call leaves it in no error.
  fake.mode = 'ok';
  const text = await s.issuer.issue({ scope: SECRET, at: AT }, 'kbox_abcg', stranger()).catch((e: Error) => `${e.message} ${e.stack}`);
  assert.equal(String(text).includes(WRONG_TEXT), false);
  assert.equal(String(text).includes(MASTER_TEXT), false);
});

// ---------------------------------------------------------------- the lister

test('KBOX-51 KBOX-57 a listing of one project keeps that project as each key\'s location; one of a project the platform does not know is empty and not complete; a legacy key with no id is left out', async () => {
  const s = subject();
  fake.mode = 'gone-project';
  assert.deepEqual(await s.lister.listAt(AT, master()), { complete: false, at: AT, keys: [] });
  fake.mode = 'ok';
  fake.keys.set(REF, [
    { id: '00000000-0000-4000-8000-0000000000aa', name: 'kbox_x', type: 'secret', value: 'unused' },
    { id: '', name: 'legacy', type: 'legacy', value: 'unused' },
  ]);
  const listing = await s.lister.listAt(AT, master());
  assert.deepEqual(listing.keys.map((k) => [k.platformKeyId, k.name, k.location]), [[`${REF}:00000000-0000-4000-8000-0000000000aa`, 'kbox_x', { project: REF }]]);
  assert.equal(await codeOf(() => s.lister.listAt({ project: 'nope' }, master())), 'bad_project');
});

test('KBOX-51 KBOX-57 a listing of every place reads each project the master sees and locates each key at its own project', async () => {
  const s = subject();
  fake.projects.push(OTHER_REF);
  fake.keys.set(REF, [{ id: '00000000-0000-4000-8000-0000000000aa', name: 'kbox_a', type: 'secret', value: 'unused' }]);
  fake.keys.set(OTHER_REF, [{ id: '00000000-0000-4000-8000-0000000000bb', name: 'kbox_b', type: 'secret', value: 'unused' }]);
  const listing = await s.lister.listAt({}, master());
  assert.deepEqual(listing.keys.map((k) => [k.name, k.location]), [['kbox_a', { project: REF }], ['kbox_b', { project: OTHER_REF }]]);
  assert.equal(listing.complete, true);
});

test('KBOX-51 a revoke of an id that cannot be a key of this platform is absent without a call', async () => {
  const s = subject();
  for (const id of ['', 'pk-1', `${REF}`, `${REF}:not-a-uuid`, `BAD:00000000-0000-4000-8000-000000000001`]) assert.equal(await s.issuer.revoke(id, master()), 'absent', id);
  assert.equal(s.http.sent.length, 0);
});

// ---------------------------------------------------------------- the key shape

test('KBOX-18 a real-format synthetic secret key has a tier; a wrong prefix, a short core and a wrong alphabet have none', () => {
  const shape = subject().issuer.capabilities().shape;
  const tier = (value: string): string => assess({ shape, value, origin: 'pasted' }).tier;
  assert.notEqual(tier('sb_secret_kbox-test_000000000000000000000001'), 'none');
  assert.notEqual(tier(`sb_secret_${'A1b2C3d4'.repeat(4)}`), 'none');
  assert.equal(tier('sb_publishable_kbox-test_000000000000000001'), 'none', 'wrong prefix');
  assert.equal(tier('sbp_kbox-test_00000000000000000000000001'), 'none', 'wrong prefix');
  assert.equal(tier(`sb_secret_${'a'.repeat(19)}`), 'none', 'core one short');
  assert.equal(tier(`sb_secret_${'a'.repeat(65)}`), 'none', 'core one long');
  assert.equal(tier(`sb_secret_${'a'.repeat(19)}+`), 'none', 'wrong alphabet');
  assert.equal(tier(`sb_secret_${'a'.repeat(19)} `), 'none', 'wrong alphabet');
});

// ---------------------------------------------------------------- the database password

test('KBOX-37 the database password call is PATCH /database/password with {password}; a value that is not 43 base64url characters, or a missing project, is refused before any call', async () => {
  const s = subject();
  const setPassword = createPasswordSetter(createManagement(s.http));
  const good = 'A'.repeat(43);
  await setPassword(lent(Buffer.from(good), 'pw:1'), AT, master());
  assert.equal(fake.passwords.get(REF), good);
  assert.equal(s.http.sent.at(-1)?.method, 'PATCH');
  assert.equal(s.http.sent.at(-1)?.target, `/v1/projects/${REF}/database/password`);
  await setPassword(lent(Buffer.from(good), 'pw:1'), AT, master());
  const before = s.http.sent.length;
  for (const bad of ['', 'A'.repeat(42), 'A'.repeat(44), `${'A'.repeat(42)}+`, `${'A'.repeat(42)}"`]) assert.equal(await codeOf(() => setPassword(lent(Buffer.from(bad), 'pw:1'), AT, master())), 'bad_password');
  assert.equal(await codeOf(() => setPassword(lent(Buffer.from(good), 'pw:1'), {}, master())), 'bad_project');
  assert.equal(await codeOf(() => setPassword(lent(Buffer.from(good), 'pw:1'), { project: 'x' }, master())), 'bad_project');
  assert.equal(s.http.sent.length, before);
  assert.equal(await codeOf(() => setPassword(lent(Buffer.from(good), 'pw:1'), AT, stranger())), 'rejected');
});

// ---------------------------------------------------------------- the secrets destination

test('KBOX-37 KBOX-2 a push posts [{name, value}] and its receipt names the secret, not the value; names that are SUPABASE_*, empty, over 256 or malformed, and a target that is not a ref, are refused before any call', async () => {
  const s = subject();
  const target = { kind: 'supabase-secret', id: REF } as const;
  const v = lent(Buffer.from('kbox-test-value'), 'v:1');
  const first = await s.destination.push(target, 'API_KEY', v, 'ordinary', master());
  assert.deepEqual(JSON.parse(Buffer.from(s.http.sent[0]?.body ?? []).toString('utf8')), [{ name: 'API_KEY', value: 'kbox-test-value' }]);
  const other = await s.destination.push(target, 'API_KEY', lent(Buffer.from('kbox-test-other'), 'v:2'), 'ordinary', master());
  assert.deepEqual(other, first, 'the same secret has the same receipt whatever value it holds');
  assert.notDeepEqual(await s.destination.push(target, 'OTHER_KEY', v, 'ordinary', master()), first, 'another secret has another receipt');
  const before = s.http.sent.length;
  for (const name of ['SUPABASE_URL', '', 'A'.repeat(257), '1A', 'A B', 'A"B']) assert.equal(await codeOf(() => s.destination.push(target, name, v, 'ordinary', master())), 'bad_secret_name', name);
  assert.equal(await codeOf(() => s.destination.push({ kind: 'supabase-secret', id: 'x' }, 'A', v, 'ordinary', master())), 'bad_project');
  assert.equal(await codeOf(() => s.destination.push({ kind: 'vercel-env', id: REF }, 'A', v, 'ordinary', master())), 'bad_project');
  assert.equal(s.http.sent.length, before);
  assert.equal((await s.destination.push(target, 'A'.repeat(256), v, 'ordinary', master())).outcome, 'applied');
});

test('KBOX-37 a push the platform refuses (auth) says refused, one that failed on its side or was rate limited says unknown; a remove of an absent secret or a 404 is done', async () => {
  const s = subject();
  const target = { kind: 'supabase-secret', id: REF } as const;
  const v = lent(Buffer.from('kbox-test-value'), 'v:1');
  assert.deepEqual(await s.destination.push(target, 'API_KEY', v, 'ordinary', stranger()), { outcome: 'refused' });
  fake.mode = '500';
  assert.deepEqual(await s.destination.push(target, 'API_KEY', v, 'ordinary', master()), { outcome: 'unknown' });
  fake.mode = '429';
  assert.deepEqual(await s.destination.push(target, 'API_KEY', v, 'ordinary', master()), { outcome: 'unknown' });
  assert.equal(await codeOf(() => s.destination.remove(target, 'API_KEY', master())), 'rate_limited');
  fake.mode = 'gone-project';
  await s.destination.remove(target, 'API_KEY', master());
});

// ---------------------------------------------------------------- the relay profile, through the running relay

const REF_HOST = `${REF}.supabase.co`;
const OTHER_HOST = `${OTHER_REF}.supabase.co`;
const KEYREF = 'supakey001';

/** `https://<host><tail>` to the relay target of the key: the host is the key's own project, so it is not in the path. */
const targetOf = (url: string): string => `/r/${KEYREF}${url.slice(`https://${REF_HOST}`.length)}`;

/**
 * The relay with this entry registered, and key `supakey001` stored at `at` (null: no stored record) while its `projects` name `projects`:
 * names for people, never placement (the negative control).
 */
async function supabaseWorld(t: TestContext, options: { readonly profile?: RelayProfile; readonly at?: KeyLocation | null; readonly projects?: readonly string[] } = {}) {
  const entry = { ...entryOver(adapterHttpTo(fake)), relay: options.profile ?? supabaseProfile };
  const w = await relayWorld(t, { registry: [...TEST_REGISTRY, entry] });
  const at = options.at === undefined ? AT : options.at;
  w.lend.addKey({ keyref: KEYREF, platform: 'supabase', projects: options.projects ?? [OTHER_REF], value: w.value, grants: ['laptop'], ...(at === null ? {} : { at }) });
  return w;
}

test('KBOX-57 KBOX-13 negative control: a key whose projects name another valid ref is relayed to its stored project host only; stored there, it goes there', async (t) => {
  const w = await supabaseWorld(t, { at: AT, projects: [OTHER_REF] });
  assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items?select=*`)).status, 200);
  assert.deepEqual(w.connects, [REF_HOST]);
  assert.deepEqual(w.upstream.requests.map((r) => r.headers['host']), [REF_HOST]);
  const swapped = await supabaseWorld(t, { at: { project: OTHER_REF }, projects: [REF] });
  assert.equal((await swapped.call(`/r/${KEYREF}/rest/v1/items`)).status, 200);
  assert.deepEqual(swapped.connects, [OTHER_HOST]);
});

test('KBOX-57 KBOX-13 a key with no stored project is 403 with no upstream call, even when its projects name a valid ref', async (t) => {
  const w = await supabaseWorld(t, { at: null, projects: [REF] });
  assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items`)).status, 403);
  assert.deepEqual([w.connects, w.upstream.requests.length], [[], 0]);
});

/** The mustDeny samples of the profile and the KBOX-13 canonicalisation variants of each, as `method url`. */
function denySamples(rules: readonly DenyRule[]): DenyRule[] {
  return rules.map((rule) => ({
    id: rule.id,
    samples: rule.samples.flatMap((s) => {
      const path = s.url.slice(`https://${REF_HOST}`.length).split('?')[0] ?? '';
      return [s, ...variants(s.method, REF_HOST, path)];
    }),
  }));
}

async function leaks(t: TestContext, profile: RelayProfile): Promise<string[]> {
  const w = await supabaseWorld(t, { profile });
  const through: string[] = [];
  for (const rule of denySamples(supabaseProfile.mustDeny)) {
    for (const sample of rule.samples) {
      const before = w.upstream.requests.length;
      const reply = await w.call(targetOf(sample.url), { method: sample.method });
      if ((reply.status !== 400 && reply.status !== 403) || w.upstream.requests.length !== before) through.push(`${rule.id} ${sample.method} ${sample.url} -> ${reply.status}`);
    }
  }
  return through;
}

const BROAD = ['/{rest:**}', '/rest/v1/{rest:**}', '/auth/v1/{rest:**}', '/storage/v1/{rest:**}', '/storage/v1/object/{rest:**}', '/storage/v1/object/{a:[A-Za-z0-9._-]{1,63}}/{rest:**}', '/storage/v1/object/{a:[A-Za-z0-9._-]{1,63}}/{b:[A-Za-z0-9._-]{1,63}}/{rest:**}', '/functions/v1/{rest:**}', '/realtime/v1/{rest:**}', '/pg/{rest:**}', '/{a:[a-z]{1,8}}/{b:[a-z0-9]{1,3}}/{rest:**}'];

function widened(): RelayProfile {
  const compiled = compileProfile(supabaseProfile);
  if (!compiled.ok) throw new Error('profile refused');
  const host = supabaseProfile.allow[0]?.host ?? '';
  const added: AllowRule[] = [];
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const [i, pathTemplate] of BROAD.entries()) {
      const rule: AllowRule = { id: `wide-${method.toLowerCase()}-${i}`, method, host, pathTemplate, query: {} };
      if (refuseWidening(compiled.engine, [rule], [rule.id]).ok) added.push(rule);
    }
  }
  assert.ok(added.length > 0, 'the widening added rules');
  return { ...supabaseProfile, allow: [...supabaseProfile.allow, ...added], tailRules: [...supabaseProfile.tailRules, ...added.map((r) => r.id)] };
}

test('KBOX-37 the profile names auth, pg, graphql, functions, storage sign, upload sign, bucket, realtime, the rest root and mcp as mustDeny', () => {
  assert.deepEqual(supabaseProfile.mustDeny.map((d) => d.id), ['auth', 'pg', 'graphql', 'functions', 'storage-sign', 'storage-upload-sign', 'storage-bucket', 'realtime', 'rest-root', 'mcp']);
});

test('KBOX-37 KBOX-13 every mustDeny sample and its canonicalisation variants is 400 or 403 with no upstream call, default profile', async (t) => {
  assert.deepEqual(await leaks(t, supabaseProfile), []);
});

test('KBOX-37 KBOX-25 the same with the widest allow set the registry still accepts', async (t) => {
  assert.deepEqual(await leaks(t, widened()), []);
});

test('KBOX-37 KBOX-13 an allowed read reaches the key own project host with the key in apikey only, and the caller Authorization is not forwarded', async (t) => {
  const w = await supabaseWorld(t);
  const reply = await w.call(`/r/${KEYREF}/rest/v1/items?select=*`);
  assert.equal(reply.status, 200);
  const sent = w.upstream.requests[0];
  assert.equal(sent?.url, '/rest/v1/items?select=%2A');
  assert.equal(sent?.headers['host'], REF_HOST);
  assert.equal(sent?.headers['apikey'], Buffer.from(w.value).toString('utf8'));
  assert.equal(sent?.headers['authorization'], undefined);
});

test('KBOX-37 KBOX-13 the other allowed operations pass (insert, rpc, authenticated download, listing) and a table filter key, limit or a row-changing method does not', async (t) => {
  const w = await supabaseWorld(t);
  const status = async (method: string, path: string): Promise<number> => (await w.call(`/r/${KEYREF}${path}`, { method })).status;
  assert.equal(await status('POST', '/rest/v1/items'), 200);
  assert.equal(await status('POST', '/rest/v1/rpc/do_it'), 200);
  assert.equal(await status('GET', '/storage/v1/object/authenticated/avatars/a/b.png'), 200);
  assert.equal(await status('POST', '/storage/v1/object/list/avatars'), 200);
  const before = w.upstream.requests.length;
  for (const [method, path] of [['GET', '/rest/v1/items?id=eq.1'], ['GET', '/rest/v1/items?limit=1'], ['PATCH', '/rest/v1/items'], ['DELETE', '/rest/v1/items'], ['PUT', '/storage/v1/object/avatars/a.png'], ['GET', '/rest/v1/items/extra']] as const) {
    assert.equal(await status(method, path), 403, `${method} ${path}`);
  }
  assert.equal(w.upstream.requests.length, before);
});

test('KBOX-37 KBOX-13 Accept-Profile and Content-Profile pass only as public: any other schema is 403 with no upstream call', async (t) => {
  const w = await supabaseWorld(t);
  const before = w.upstream.requests.length;
  for (const headers of [{ 'accept-profile': 'vault' }, { 'accept-profile': 'Public' }, { 'accept-profile': 'public,vault' }, { 'accept-profile': '' }]) {
    assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items`, { headers })).status, 403, JSON.stringify(headers));
  }
  assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items`, { method: 'POST', headers: { 'content-profile': 'auth' } })).status, 403);
  assert.equal(w.upstream.requests.length, before);
  assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items`, { headers: { 'accept-profile': 'public' } })).status, 200);
  assert.equal(w.upstream.requests.at(-1)?.headers['accept-profile'], 'public');
});

test('KBOX-37 KBOX-14 a PostgREST read stating its rows as Content-Range 0-24/* passes whole, the header not sent on; a bytes range is withheld', async (t) => {
  const w = await supabaseWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-range': '0-24/*' });
    res.end('[{"id":1}]');
  });
  const rows = await w.call(`/r/${KEYREF}/rest/v1/items?select=*`);
  assert.deepEqual([rows.status, rows.body.toString(), rows.headers['content-range']], [200, '[{"id":1}]', undefined]);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-range': 'bytes 0-24/25' });
    res.end('[{"id":1}]');
  });
  assert.equal((await w.call(`/r/${KEYREF}/rest/v1/items?select=*`)).status, 502);
});

test('KBOX-37 a host carried in the path is not a way to another project: it is a path segment and no rule matches it', async (t) => {
  const w = await supabaseWorld(t);
  const before = w.upstream.requests.length;
  assert.equal((await w.call(`/r/${KEYREF}/${OTHER_HOST}/rest/v1/items`)).status, 403);
  assert.equal(w.upstream.requests.length, before);
  assert.deepEqual(w.connects, []);
});
