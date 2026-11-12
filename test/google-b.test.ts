// KBOX-59: the Google API-key adapter. The issuer, lister, revoke and verifier rules, one test per row; every admin mint names the project of its
// call's stored location (two projects stored); the one name-to-id function; a canary value is absent from every error; the verifier never answers
// `rejected`; the Secret Manager destination and the relay profile; one rotation through core. Over the fake Google (test/fakes/google.ts,
// google-apis.ts) through the real minter, so what Google would refuse (another project's token) is refused here too. The fake's answers for the
// API Keys and Resource Manager v3 hosts are stated assumptions (docs/probes/google.md marks them STILL UNVERIFIED), never facts.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import type { TestContext } from 'node:test';
import { inspect } from 'node:util';
import type { Issuer, KeyLister, Verifier } from '../src/ports/issuer.ts';
import type { Destination, DestinationTarget } from '../src/ports/destination.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { RelayProfile } from '../src/ports/relay-profile.ts';
import type { KeyLocation, Lent } from '../src/ports/types.ts';
import { matchesShape } from '../src/pure/class.ts';
import { checkRegistry } from '../src/pure/profile.ts';
import { GoogleError } from '../src/platforms/google/errors.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { OPERATION_POLL_MS, OPERATION_WAIT_MS } from '../src/platforms/google/issuer.ts';
import { KEY_ID, composeId, numberReader, parseStoredId, storedIdOf } from '../src/platforms/google/key-name.ts';
import { googleRelayProfile } from '../src/platforms/google/relay.ts';
import { API_KEY_SHAPE } from '../src/platforms/google/scope.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import { bytesOf, canary, lent, seedFor, seededRandom } from './kit/index.ts';
import type { Override } from './fakes/google.ts';
import { NO_ISSUER_CLASSIFY, NO_ISSUER_SHAPE, TEST_REGISTRY } from './fixtures/profiles.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { IDENTITY, P1, P2, adminOf, googleWorld } from './support/google-world.ts';
import type { GoogleWorld } from './support/google-world.ts';
import { relayWorld } from './support/relay-world.ts';
import { HOUR, MINUTE, rotationWorld } from './support/rotation-world.ts';

const APIKEYS = 'apikeys.googleapis.com';
const CRM = 'cloudresourcemanager.googleapis.com';
const SECRETS = 'secretmanager.googleapis.com';
const FIRESTORE = 'api:firestore.googleapis.com';
const SCOPE = { items: [FIRESTORE] };

let w: GoogleWorld;
let entry: PlatformEntry;
const closers: (() => unknown)[] = [];
before(async () => {
  w = await googleWorld({ after: (fn) => void closers.push(fn) }, [P1, P2]);
  entry = createGoogleEntry({ http: w.http, clock: w.clock, identity: IDENTITY, minted: { add: () => undefined }, keyInfo: () => undefined, pause: w.pause });
});
after(async () => {
  for (const close of closers) await close();
});

const issuerOf = (): Issuer => {
  assert.ok(entry.issuer);
  return entry.issuer;
};
const listerOf = (): KeyLister => {
  assert.ok(entry.lister);
  return entry.lister;
};
const verifierOf = (): Verifier => {
  assert.ok(entry.verifier);
  return entry.verifier;
};
const destinationOf = (): Destination => {
  const kit = entry.destinations?.[0];
  assert.ok(kit);
  return kit.destination;
};
const at = (project: string): KeyLocation => ({ project });
const textOf = (value: Lent): Promise<string> => bytesOf(value).then((b) => Buffer.from(b).toString('utf8'));
/** What a call threw: its fixed code, `resolved` when it did not throw, or `other:<name>` for an error that is not the adapter's. */
const codeOf = (call: Promise<unknown>): Promise<string> =>
  call.then(
    () => 'resolved',
    (error: unknown) => (error instanceof GoogleError ? error.code : error instanceof Error ? `other:${error.name}` : 'other'),
  );
const CUT: Override = { kind: 'cut' };
const answer = (code: number, body: unknown = {}): Override => ({ kind: 'status', status: code, body: typeof body === 'string' ? body : JSON.stringify(body) });
const apikeysCalls = (): string[] => w.calls(APIKEYS).map((c) => `${c.method} ${c.target}`);
const deletes = (): string[] => apikeysCalls().filter((c) => c.startsWith('DELETE'));
/** The projects the adapters' calls name (a lookup and an Operation name none). */
const projectsNamed = (): string[] => [...new Set(w.calls().flatMap((c) => /\/projects\/([^/:?]+)/.exec(c.target)?.[1] ?? []))].filter((p) => p !== '-');
const issueOf = (project: string, name = 'kbox_x_g2_abcd1234') => issuerOf().issue({ scope: SCOPE, at: at(project) }, name, w.master);
const keyId = (n: number): string => `key-${n}`;
const stored = (id: string, project = P1): string => composeId(project, id);

// --- key-name: the one name-to-id function (M2) ----------------------------------------------------------------------------------------

test('KBOX-59 composeId and parseStoredId are one pair: the stored form is projects/<project>/locations/global/keys/<key id> and nothing else parses', () => {
  assert.equal(composeId(P1, 'key-1'), `projects/${P1}/locations/global/keys/key-1`);
  assert.deepEqual(parseStoredId(stored('key-1')), { project: P1, keyId: 'key-1' });
  const bad = ['never-issued', '', `projects/${P1}/locations/us/keys/k`, `projects/${P1}/locations/global/keys/K`, `projects/${P1}/locations/global/keys/k/x`, `projects/${P1}/locations/global/keys/`, 'projects/P1/locations/global/keys/k', `projects/${P1}/locations/global/keys/k\n`, ` projects/${P1}/locations/global/keys/k`, `projects/${P1}/locations/global/keys/${'a'.repeat(64)}`, 'projects/123456789/locations/global/keys/k'];
  for (const id of bad) assert.equal(parseStoredId(id), undefined, JSON.stringify(id));
  assert.ok(KEY_ID.test('a'.repeat(63)) && !KEY_ID.test('a'.repeat(64)) && !KEY_ID.test('-a') && !KEY_ID.test(''));
});

test('KBOX-59 storedIdOf: an answered name counts only as this project\'s key, by its id or by the number the stored project has; the id\'s project is always the argument', async () => {
  const number = '123456789012';
  const read = (): Promise<string | undefined> => Promise.resolve(number);
  const unreadable = (): Promise<string | undefined> => Promise.resolve(undefined);
  const table: readonly (readonly [string, unknown, () => Promise<string | undefined>, string | undefined])[] = [
    ['the stored id', `projects/${P1}/locations/global/keys/k1`, read, stored('k1')],
    ['the number the stored project has', `projects/${number}/locations/global/keys/k1`, read, stored('k1')],
    ['another number', 'projects/123456789013/locations/global/keys/k1', read, undefined],
    ['digits, the number read failing', `projects/${number}/locations/global/keys/k1`, unreadable, undefined],
    ['another project id', `projects/${P2}/locations/global/keys/k1`, read, undefined],
    ['another location', `projects/${P1}/locations/us/keys/k1`, read, undefined],
    ['a number in another location', `projects/${number}/locations/us/keys/k1`, read, undefined],
    ['a key id of the wrong form', `projects/${P1}/locations/global/keys/K_1`, read, undefined],
    ['an empty key id', `projects/${P1}/locations/global/keys/`, read, undefined],
    ['an extra segment', `projects/${P1}/locations/global/keys/k1/extra`, read, undefined],
    ['a missing segment', `projects/${P1}/keys/k1`, read, undefined],
    ['a trailing newline', `projects/${P1}/locations/global/keys/k1\n`, read, undefined],
    ['digits with a letter', `projects/${number}x/locations/global/keys/k1`, read, undefined],
    ['a project segment of 65 characters', `projects/${'1'.repeat(65)}/locations/global/keys/k1`, read, undefined],
    ['no text at all', undefined, read, undefined],
    ['a number', 5, read, undefined],
    ['null', null, read, undefined],
    ['an object', { name: stored('k1') }, read, undefined],
  ];
  for (const [what, name, numberOf, expected] of table) assert.equal(await storedIdOf(name, P1, numberOf), expected, what);
});

test('KBOX-59 storedIdOf reads the project number at most once per call, and never when the answer names the stored id', async () => {
  let reads = 0;
  const counting = (): Promise<string | undefined> => {
    reads += 1;
    return Promise.resolve('123456789012');
  };
  assert.equal(await storedIdOf(`projects/${P1}/locations/global/keys/k1`, P1, counting), stored('k1'));
  assert.equal(await storedIdOf(`projects/${P2}/locations/global/keys/k1`, P1, counting), undefined);
  assert.equal(reads, 0, 'an id never asks');
  const memo = numberReader(counting);
  assert.equal(await storedIdOf('projects/123456789012/locations/global/keys/a', P1, memo), stored('a'));
  assert.equal(await storedIdOf('projects/123456789012/locations/global/keys/b', P1, memo), stored('b'));
  assert.equal(await storedIdOf('projects/999/locations/global/keys/c', P1, memo), undefined);
  assert.equal(reads, 1, 'three names, one read');
});

test('KBOX-59 storedIdOf property: whatever the answer says, the id it gives names the stored project, and only a name of the stored project (by id or its number) gives one', async () => {
  const seed = seedFor(process.env);
  const rng = seededRandom(seed);
  const number = '123456789012';
  const projects = [P1, P2, number, '999', '', 'a/b', `${number}0`, 'p-proj1\n', '..', '%70-proj1'];
  const locations = ['global', 'us', '', 'global/x'];
  const keyIds = ['k1', 'key-77', 'K', '', 'a'.repeat(64), '../k', 'k%31'];
  const pick = <T,>(xs: readonly T[]): T => xs[rng.int(xs.length)] as T;
  for (let run = 0; run < 400; run += 1) {
    const [project, location, id] = [pick(projects), pick(locations), pick(keyIds)];
    const name = `projects/${project}/locations/${location}/keys/${id}`;
    const got = await storedIdOf(name, P1, () => Promise.resolve(number));
    const namesTheStoredProject = (project === P1 || project === number) && location === 'global' && KEY_ID.test(id);
    assert.equal(got, namesTheStoredProject ? `projects/${P1}/locations/global/keys/${id}` : undefined, `seed ${seed}: ${JSON.stringify(name)}`);
  }
});

// --- the issuer: each outcome of the rule's issuer table ------------------------------------------------------------------------------

test('KBOX-59 the issuer\'s capabilities: api create and revoke, overlap, no self-rotate, no set, revealed once (the lister finds it), the API-key shape, always ordinary', () => {
  const caps = issuerOf().capabilities();
  assert.deepEqual([caps.create, caps.revoke, caps.selfRotate, caps.overlap, caps.set, caps.revealOnce], ['api', 'api', false, true, 'none', true]);
  assert.deepEqual(caps.shape, API_KEY_SHAPE);
  assert.deepEqual(API_KEY_SHAPE, { prefix: 'AIza', alphabet: 'base64url', coreLength: { min: 35, max: 35 }, random: true });
  for (const items of [[], [FIRESTORE], ['sa:p-proj1/acct1x'], ['master'], [FIRESTORE, 'admin']]) {
    for (const where of [{}, at(P1)]) assert.equal(caps.classify({ items }, where), 'ordinary', JSON.stringify(items));
  }
  assert.equal(caps.classify({ access: 'read' }, {}), 'ordinary');
});

test('KBOX-59 issue: an Operation, then the key string, makes an AIza key at the stored project; every call names it and one admin mint is made for it', async () => {
  w.reset();
  const issued = await issueOf(P1);
  assert.equal(issued.platformKeyId, stored(keyId(1)));
  assert.deepEqual(issued.location, at(P1));
  const value = await textOf(issued.value);
  assert.ok(matchesShape(API_KEY_SHAPE, value));
  assert.equal(w.fake.apis.keysOf(P1)[0]?.keyString, value);
  assert.deepEqual(apikeysCalls(), [`POST /v2/projects/${P1}/locations/global/keys`, 'GET /v2/operations/op-1', `GET /v2/projects/${P1}/locations/global/keys/key-1/keyString`]);
  assert.deepEqual(w.minted(), [adminOf(P1)], 'one mint, for the stored project');
  assert.deepEqual(projectsNamed(), [P1]);
  assert.deepEqual(w.calls(CRM).map((c) => `${c.method} ${c.target}`), [`GET /v3/projects/${P1}`], 'the answer named the project by number: one read of the stored project\'s number');
});

test('KBOX-59 issue: the key is restricted to the scope\'s services (each once) and named by the intent; an intent of 64 characters is cut to 63 (UNVERIFIED limit), a shorter one is sent whole; an answer naming the project by id needs no number', async () => {
  w.reset();
  w.fake.apis.knobs.nameAs = 'id';
  const long = `kbox_${'x'.repeat(59)}`;
  assert.equal(long.length, 64);
  await issuerOf().issue({ scope: { items: [FIRESTORE, 'api:storage-component.googleapis.com', FIRESTORE] }, at: at(P1) }, long, w.master);
  const [made] = w.fake.apis.keysOf(P1);
  assert.equal(made?.displayName, long.slice(0, 63));
  assert.deepEqual(made?.restrictions, { apiTargets: [{ service: 'firestore.googleapis.com' }, { service: 'storage-component.googleapis.com' }] });
  assert.equal(w.calls(CRM).length, 0);
  await issueOf(P1, 'kbox_short_g2_abcd1234');
  assert.equal(w.fake.apis.keysOf(P1)[1]?.displayName, 'kbox_short_g2_abcd1234');
});

test('KBOX-59 issue refuses before any call, and before any mint: a location that is no project id is bad_location; a scope with no api: item, an sa: item, any other item or a service outside googleapis.com is bad_scope', async () => {
  w.reset();
  for (const where of [{}, at('P1'), at('p1'), at(`${P1}/x`), at('-'), { region: 'global' }]) assert.equal(await codeOf(issuerOf().issue({ scope: SCOPE, at: where }, 'kbox_a', w.master)), 'bad_location', JSON.stringify(where));
  assert.equal(w.sent().length, 0);
  const scopes = [{ access: 'read' }, { items: [] }, { items: ['sa:p-proj1/acct1x'] }, { items: [FIRESTORE, 'sa:p-proj1/acct1x'] }, { items: [FIRESTORE, 'read'] }, { items: ['api:firestore.example.com'] }, { items: ['api:'] }, { items: ['api:FIRESTORE.googleapis.com'] }, { items: 'read' }];
  for (const scope of scopes) assert.equal(await codeOf(issuerOf().issue({ scope, at: at(P1) }, 'kbox_a', w.master)), 'bad_scope', JSON.stringify(scope));
  assert.equal(w.sent().length, 0, 'no mint and no call: the box never makes an unrestricted key');
});

test('KBOX-59 issue waits for the Operation by polling with a pause: it is done on the third read, and one key is made', async () => {
  w.reset();
  w.fake.apis.knobs.operationPolls = 2;
  const issued = await issueOf(P1);
  assert.equal(issued.platformKeyId, stored(keyId(1)));
  assert.deepEqual(w.pauses, [OPERATION_POLL_MS, OPERATION_POLL_MS]);
  assert.equal(apikeysCalls().filter((c) => c.startsWith('GET /v2/operations/')).length, 3);
  assert.equal(w.fake.apis.keysOf(P1).length, 1);
});

test('KBOX-59 issue: an Operation not done in 60 s on the injected clock is unreachable, with no DELETE (no key id is known); the key it may have made is left for the next sweep', async () => {
  w.reset();
  w.fake.apis.knobs.neverDone = true;
  assert.equal(await codeOf(issueOf(P1)), 'unreachable');
  assert.deepEqual(deletes(), []);
  const waited = w.pauses.reduce((a, b) => a + b, 0);
  assert.ok(waited >= OPERATION_WAIT_MS && waited < OPERATION_WAIT_MS + OPERATION_POLL_MS, `waited ${waited} ms`);
  assert.equal(w.fake.apis.keysOf(P1).length, 1, 'the fake made it: the sweep finds it by its kbox_ name');
});

test('KBOX-59 issue: a done Operation with an error is apikeys_refused, a create answered 4xx apikeys_refused, 5xx apikeys_failed, a cut answer unreachable; none deletes anything', async () => {
  w.reset();
  w.fake.apis.knobs.operationError = true;
  assert.equal(await codeOf(issueOf(P1)), 'apikeys_refused');
  w.reset();
  for (const [what, code, override] of [['403', 'apikeys_refused', answer(403)], ['400', 'apikeys_refused', answer(400)], ['500', 'apikeys_failed', answer(500)], ['cut', 'unreachable', CUT]] as const) {
    w.fake.override('create-key', override);
    assert.equal(await codeOf(issueOf(P1)), code, what);
  }
  w.fake.override('create-key', undefined);
  assert.deepEqual(deletes(), []);
});

test('KBOX-59 issue: an answer that is no Operation, a name that is not operations/<id>, an Operation read answered 5xx or not an object, or a done Operation without a key name each fail without a second call that names anything but the stored project, and delete nothing', async () => {
  for (const body of ['{}', '{"name":5}', '{"name":"../keys"}', '{"name":"operations/a/b"}', '[]', 'text']) {
    w.reset();
    w.fake.override('create-key', answer(200, body));
    assert.equal(await codeOf(issueOf(P1)), 'bad_answer', body);
    assert.equal(apikeysCalls().length, 1, `${body}: nothing is read after it`);
  }
  w.reset();
  w.fake.override('operation', answer(503));
  assert.equal(await codeOf(issueOf(P1)), 'apikeys_failed');
  for (const body of ['[]', 'text', '{"done":true}', '{"done":true,"response":{}}', '{"done":true,"response":{"name":5}}']) {
    w.reset();
    w.fake.override('operation', answer(200, body));
    assert.equal(await codeOf(issueOf(P1)), 'bad_answer', body);
  }
  assert.deepEqual(deletes(), []);
});

test('KBOX-59 issue: an answer naming another project, another location or a number the stored project does not have never names a call: it fails location_unconfirmed, nothing is deleted, and no call names the other project', async () => {
  const names: readonly (readonly [string, (project: string, id: string) => string])[] = [
    ['another project id', (_p, id) => `projects/${P2}/locations/global/keys/${id}`],
    ['another location', (p, id) => `projects/${p}/locations/us/keys/${id}`],
    ['the number of another project', (_p, id) => `projects/999999999999/locations/global/keys/${id}`],
    ['digits that are not a number', (_p, id) => `projects/123/locations/global/keys/${id}`],
  ];
  for (const [what, nameAs] of names) {
    w.reset();
    w.fake.apis.knobs.nameAs = nameAs;
    assert.equal(await codeOf(issueOf(P1)), 'location_unconfirmed', what);
    assert.deepEqual(deletes(), [], `${what}: no DELETE by an id built from the answer`);
    assert.deepEqual(projectsNamed(), [P1], what);
    assert.equal(w.fake.apis.keysOf(P1).length, 1, `${what}: the key Google made is left`);
    assert.ok(!apikeysCalls().some((c) => c.includes('keyString')), `${what}: its value is never read`);
  }
  w.reset();
  w.fake.apis.knobs.nameAs = 'number';
  w.fake.override('project', answer(500));
  assert.equal(await codeOf(issueOf(P1)), 'location_unconfirmed', 'a number that cannot be read counts for nothing');
  assert.deepEqual(deletes(), []);
});

test('KBOX-59 issue: a key id of the wrong form in the answer is bad_answer; nothing is deleted', async () => {
  for (const id of ['Key_1', 'k'.repeat(64), '-k']) {
    w.reset();
    w.fake.apis.knobs.nameAs = (_p, _id, number) => `projects/${number}/locations/global/keys/${id}`;
    assert.equal(await codeOf(issueOf(P1)), 'bad_answer', id);
  }
  assert.deepEqual(deletes(), []);
});

test('KBOX-59 issue: a key string that is not of the API-key shape, or is not read, deletes the key made (the composed id, in the stored project) and fails bad_answer; a DELETE that fails changes neither the code nor the throw', async () => {
  const bad = ['AIzashort', `ya29.${'a'.repeat(35)}`, `AIza${'a'.repeat(36)}`, `AIza${'a'.repeat(34)}+`, `AIza${'a'.repeat(34)}\n`, ''];
  for (const keyString of bad) {
    w.reset();
    w.fake.apis.knobs.nextKeyString = keyString;
    assert.equal(await codeOf(issueOf(P1)), 'bad_answer', JSON.stringify(keyString));
    assert.deepEqual(deletes(), [`DELETE /v2/projects/${P1}/locations/global/keys/key-1`], JSON.stringify(keyString));
    assert.equal(w.fake.apis.keysOf(P1).length, 0, 'the key is gone');
  }
  for (const [what, override] of [['404', answer(404)], ['no member', answer(200, '{}')], ['not text', answer(200, '{"keyString":5}')], ['not JSON', answer(200, 'text')]] as const) {
    w.reset();
    w.fake.override('key-string', override);
    assert.equal(await codeOf(issueOf(P1)), 'bad_answer', what);
    assert.deepEqual(deletes(), [`DELETE /v2/projects/${P1}/locations/global/keys/key-1`], what);
  }
  w.reset();
  w.fake.apis.knobs.nextKeyString = 'AIzashort';
  w.fake.override('delete-key', answer(500));
  assert.equal(await codeOf(issueOf(P1)), 'bad_answer', 'the failed DELETE is not the error');
  assert.equal(w.fake.apis.keysOf(P1).length, 1, 'the key is left, for the next sweep');
});

// --- revoke -------------------------------------------------------------------------------------------------------------------------

test('KBOX-59 revoke reads the project from the stored id and fails closed on any other form: bad_key_id, no mint, no call', async () => {
  w.reset();
  for (const id of ['never-issued', '', `projects/${P1}/locations/us/keys/k`, `projects/${P1}/locations/global/keys/K`, `projects/${P1}/locations/global/keys/k/x`, 'projects/123456789012/locations/global/keys/k', `projects/${P1}/locations/global/keys/../keys/k`]) {
    assert.equal(await codeOf(issuerOf().revoke(id, w.master)), 'bad_key_id', JSON.stringify(id));
  }
  assert.equal(w.sent().length, 0);
});

test('KBOX-59 revoke: DELETE of the stored id is revoked, once; a 404 is absent (not proof); other answers throw; the mint is for the id\'s project', async () => {
  w.reset();
  const issued = await issueOf(P1);
  w.forgetCalls();
  assert.equal(await issuerOf().revoke(issued.platformKeyId, w.master), 'revoked');
  assert.deepEqual(apikeysCalls(), [`DELETE /v2/projects/${P1}/locations/global/keys/key-1`]);
  assert.deepEqual(w.minted(), [adminOf(P1)]);
  assert.equal(await issuerOf().revoke(issued.platformKeyId, w.master), 'absent');
  for (const [code, expected] of [[403, 'apikeys_refused'], [400, 'apikeys_refused'], [500, 'apikeys_failed'], [302, 'apikeys_failed']] as const) {
    w.fake.override('delete-key', answer(code));
    assert.equal(await codeOf(issuerOf().revoke(issued.platformKeyId, w.master)), expected, String(code));
  }
  w.fake.override('delete-key', CUT);
  assert.equal(await codeOf(issuerOf().revoke(issued.platformKeyId, w.master)), 'unreachable');
  w.fake.override('delete-key', undefined);
  assert.equal(await codeOf(issuerOf().revoke(issued.platformKeyId, w.wrongMaster)), 'sts_refused');
});

// --- the lister: listAt rows --------------------------------------------------------------------------------------------------------

test('KBOX-59 the lister has no platform-wide list (a place no one master sees whole): only listAt', () => {
  assert.equal(listerOf().list, undefined);
});

test('KBOX-59 listAt: the keys of the stored project with their displayName, in the stored form, complete; a soft-deleted key is disabled; no key value is read; the listing says where it is of', async () => {
  w.reset();
  const live = w.fake.apis.plant(P1, { id: 'live-1', displayName: 'kbox_a_g1_aaaaaaaa' });
  w.fake.apis.plant(P1, { id: 'dead-1', displayName: 'kbox_b_g1_bbbbbbbb', deleteTime: '2026-11-13T10:00:00Z' });
  w.fake.apis.plant(P1, { id: 'nameless-1', displayName: '' });
  w.fake.apis.plant(P2, { id: 'other-1', displayName: 'kbox_other' });
  w.fake.apis.knobs.listIncludesDeleted = true;
  const listing = await listerOf().listAt(at(P1), w.master);
  assert.deepEqual(listing.at, at(P1));
  assert.equal(listing.complete, true);
  assert.deepEqual(
    listing.keys.map((k) => [k.platformKeyId, k.name, k.disabled, k.location]),
    [
      [stored('live-1'), 'kbox_a_g1_aaaaaaaa', undefined, at(P1)],
      [stored('dead-1'), 'kbox_b_g1_bbbbbbbb', true, at(P1)],
      [stored('nameless-1'), '', undefined, at(P1)],
    ],
  );
  assert.equal(JSON.stringify(listing).includes(live), false, 'no key value in a listing');
  assert.ok(!apikeysCalls().some((c) => c.includes('keyString')));
  assert.deepEqual(w.minted(), [adminOf(P1)]);
  assert.deepEqual(apikeysCalls(), [`GET /v2/projects/${P1}/locations/global/keys`], 'no showDeleted: the default omits deleted keys');
});

test('KBOX-59 listAt follows every page; a later page that fails, a repeated token or a malformed one gives complete:false with what was read; a first page that fails throws', async () => {
  const plant = (): void => {
    for (const n of [1, 2, 3]) w.fake.apis.plant(P1, { id: `k${n}`, displayName: `kbox_${n}` });
  };
  w.reset();
  plant();
  w.fake.apis.knobs.pageSize = 1;
  const all = await listerOf().listAt(at(P1), w.master);
  assert.deepEqual([all.complete, all.keys.map((k) => k.name)], [true, ['kbox_1', 'kbox_2', 'kbox_3']]);
  assert.deepEqual(apikeysCalls().map((c) => c.split('?')[1]), [undefined, 'pageToken=page-1', 'pageToken=page-2']);
  w.reset();
  plant();
  w.fake.apis.knobs.pageSize = 1;
  w.fake.apis.knobs.failAfterPages = 1;
  const cut = await listerOf().listAt(at(P1), w.master);
  assert.deepEqual([cut.complete, cut.keys.map((k) => k.name)], [false, ['kbox_1']]);
  for (const tokens of ['repeat', 'malformed'] as const) {
    w.reset();
    plant();
    w.fake.apis.knobs.tokens = tokens;
    const odd = await listerOf().listAt(at(P1), w.master);
    assert.equal(odd.complete, false, tokens);
    assert.ok(odd.keys.length >= 3, tokens);
  }
  w.reset();
  w.fake.override('list-keys', answer(500));
  assert.equal(await codeOf(listerOf().listAt(at(P1), w.master)), 'apikeys_failed');
  for (const body of ['[]', 'text', '{"keys":5}']) {
    w.fake.override('list-keys', answer(200, body));
    assert.equal(await codeOf(listerOf().listAt(at(P1), w.master)), 'bad_answer', body);
  }
});

test('KBOX-59 listAt: a key whose name is not this project\'s (another project, location or number, a bad id, no text) is left out and the listing is not complete; a bad location is refused with no call', async () => {
  w.reset();
  w.fake.apis.plant(P1, { id: 'mine-1', displayName: 'kbox_mine' });
  w.fake.override('list-keys', answer(200, { keys: [{ name: `projects/${P2}/locations/global/keys/x1`, displayName: 'kbox_theirs' }, { name: 'projects/999/locations/global/keys/x2', displayName: 'kbox_n' }, { name: `projects/${P1}/locations/us/keys/x3` }, { name: 5 }, { name: `projects/${P1}/locations/global/keys/OK` }, { name: `projects/${P1}/locations/global/keys/mine-1`, displayName: 7 }] }));
  const listing = await listerOf().listAt(at(P1), w.master);
  assert.equal(listing.complete, false);
  assert.deepEqual(listing.keys.map((k) => [k.platformKeyId, k.name]), [[stored('mine-1'), '']], 'the one key that names the stored project; a displayName that is no text is empty');
  assert.deepEqual(projectsNamed(), [P1]);
  w.reset();
  for (const where of [{}, at('P1'), at('-'), { region: 'global' }]) assert.equal(await codeOf(listerOf().listAt(where, w.master)), 'bad_location', JSON.stringify(where));
  assert.equal(w.sent().length, 0);
});

// --- the verifier: rows 1 to 10 -----------------------------------------------------------------------------------------------------

const verify = (value: string, where: KeyLocation = at(P1), master: Lent | 'none' = w.master): Promise<'ok' | 'rejected' | 'unreachable'> =>
  verifierOf().verify(lent(Buffer.from(value), 'value'), { platform: 'google', at: where, ...(master === 'none' ? {} : { master }) });
const lookupTarget = (value: string): string => `/v2/keys:lookupKey?keyString=${encodeURIComponent(value)}`;
/** Two key values of the API-key shape, one per project, so a lookup finds one key. */
const LIVE = `AIza${'Lk3_-'.repeat(7)}`;
const THEIRS = `AIza${'Qz9-_'.repeat(7)}`;
const planted = (project = P1, key: { id?: string; deleteTime?: string } = {}): string =>
  w.fake.apis.plant(project, { id: key.id ?? 'live-1', displayName: 'kbox_v', keyString: project === P1 ? LIVE : THEIRS, ...(key.deleteTime === undefined ? {} : { deleteTime: key.deleteTime }) });
/** A clean fake with one live key of the first project; its value. */
const fresh = (): string => (w.reset(), planted());

test('KBOX-58 KBOX-59 the verifier needs the master and applies only to a key with a stored project and no sa: item', () => {
  const verifier = verifierOf();
  assert.equal(verifier.needsMaster, true);
  assert.ok(verifier.appliesTo !== undefined);
  assert.equal(verifier.appliesTo({ items: [FIRESTORE] }, at(P1)), true);
  assert.equal(verifier.appliesTo({ items: [] }, at(P1)), true);
  assert.equal(verifier.appliesTo({ items: [] }, {}), false, 'the signing key: no project');
  assert.equal(verifier.appliesTo({ items: [FIRESTORE] }, {}), false);
  assert.equal(verifier.appliesTo({ items: ['sa:p-proj1/acct1x'] }, at(P1)), false);
  assert.equal(verifier.appliesTo({ items: [FIRESTORE, 'sa:p-proj1/acct1x'] }, at(P1)), false);
});

test('KBOX-59 verifier rows 1 to 3 make no call and no mint: no master, a stored project that is no project id, a value not of the shape', async () => {
  const value = fresh();
  assert.equal(await verify(value, at(P1), 'none'), 'unreachable');
  for (const where of [{}, at('P1'), at('-'), at(`${P1}/x`), { region: 'global' }]) assert.equal(await verify(value, where), 'unreachable', JSON.stringify(where));
  for (const odd of ['', 'AIza', `ya29.${'a'.repeat(35)}`, `${value}x`, value.slice(0, -1), `${value}\n`, ` ${value}`, `AIza${'a'.repeat(34)}&`, `AIza${'a'.repeat(34)}%`, 'AIzaé'.padEnd(39, 'a')]) assert.equal(await verify(odd), 'unreachable', JSON.stringify(odd));
  assert.equal(w.sent().length, 0);
});

test('KBOX-59 verifier row 4: an admin token that cannot be minted is unreachable, and the lookup is never made', async () => {
  const value = fresh();
  assert.equal(await verify(value, at(P1), w.wrongMaster), 'unreachable');
  assert.deepEqual(w.calls().map((c) => c.host), ['sts.googleapis.com']);
  assert.ok(!w.fake.requests.some((r) => r.path.includes(value)));
});

test('KBOX-59 verifier row 8: a key the lookup finds and the stored project has, not deleted, is ok; the lookup query is the percent-encoded value; the key is then read at the stored project; the mint is for it', async () => {
  const value = fresh();
  assert.equal(await verify(value), 'ok');
  assert.deepEqual(apikeysCalls(), [`GET ${lookupTarget(value)}`, `GET /v2/projects/${P1}/locations/global/keys/live-1`]);
  assert.deepEqual(w.minted(), [adminOf(P1)]);
  assert.deepEqual(w.calls(CRM).map((c) => c.target), [`/v3/projects/${P1}`], 'the lookup named the project by number: one read');
  fresh();
  w.fake.apis.knobs.nameAs = 'id';
  w.fake.override('lookup-key', answer(200, { name: `projects/${P1}/locations/global/keys/live-1` }));
  assert.equal(await verify(value), 'ok');
  assert.equal(w.calls(CRM).length, 0, 'named by id: no number read');
  fresh();
  w.fake.override('get-key', answer(200, { name: stored('live-1'), deleteTime: '' }));
  assert.equal(await verify(value), 'ok', 'an empty deleteTime is not deleted');
});

test('KBOX-59 verifier row 5: a lookup that fails, answers other than 200 or answers a non-object is unreachable, and nothing is read after it', async () => {
  const value = LIVE;
  const lookups: readonly (readonly [string, Override])[] = [['404', answer(404)], ['403', answer(403)], ['500', answer(500)], ['301', answer(301)], ['cut', CUT], ['array', answer(200, '[]')], ['text', answer(200, 'text')], ['empty', answer(200, '')]];
  for (const [what, override] of lookups) {
    fresh();
    w.fake.override('lookup-key', override);
    assert.equal(await verify(value), 'unreachable', what);
    assert.equal(apikeysCalls().length, 1, `${what}: only the lookup`);
  }
});

test('KBOX-59 verifier rows 6 and 7: a lookup with no name, an empty one or one that is not the stored project\'s (another project, location or number, a bad id) is unreachable; never rejected', async () => {
  const value = LIVE;
  const names: readonly [string, unknown][] = [
    ['no member', undefined],
    ['empty', ''],
    ['a number', 5],
    ['null', null],
    ['another project', `projects/${P2}/locations/global/keys/live-1`],
    ['another number', 'projects/999999999999/locations/global/keys/live-1'],
    ['digits only', 'projects/123/locations/global/keys/live-1'],
    ['another location', `projects/${P1}/locations/us/keys/live-1`],
    ['a bad key id', `projects/${P1}/locations/global/keys/LIVE`],
    ['an extra segment', `projects/${P1}/locations/global/keys/live-1/x`],
  ];
  for (const [what, name] of names) {
    fresh();
    w.fake.override('lookup-key', answer(200, name === undefined ? {} : { name }));
    assert.equal(await verify(value), 'unreachable', what);
    assert.equal(apikeysCalls().length, 1, `${what}: the key is not read`);
  }
  fresh();
  w.fake.override('project', answer(500));
  assert.equal(await verify(value), 'unreachable', 'a number that cannot be read');
});

test('KBOX-59 verifier: a key of another project is never read at that project, whatever the lookup says (M2: an answered project never names a call)', async () => {
  w.reset();
  const theirs = planted(P2, { id: 'theirs-1' });
  assert.equal(await verify(theirs, at(P1)), 'unreachable');
  assert.deepEqual(projectsNamed().filter((p) => p !== P1), []);
  assert.deepEqual(w.minted(), [adminOf(P1)]);
});

test('KBOX-59 verifier rows 9 and 10: a key read with a deleteTime, or answered 404, 403, 5xx, cut or not an object is unreachable (a probed death answer is a later unit\'s)', async () => {
  const value = LIVE;
  w.reset();
  planted(P1, { deleteTime: '2026-11-13T10:00:00Z' });
  assert.equal(await verify(value), 'unreachable', 'deleteTime');
  const reads: readonly (readonly [string, Override])[] = [['404', answer(404)], ['403', answer(403)], ['500', answer(500)], ['cut', CUT], ['array', answer(200, '[]')], ['text', answer(200, 'text')], ['null deleteTime', answer(200, { deleteTime: null })], ['numeric deleteTime', answer(200, { deleteTime: 5 })]];
  for (const [what, override] of reads) {
    fresh();
    w.fake.override('get-key', override);
    assert.equal(await verify(value), 'unreachable', what);
  }
});

test('KBOX-59 verifier property: over every combination of status and body the fake can give the lookup and the read, the verdict is ok or unreachable, never rejected, and ok only for a found, undeleted key', async () => {
  const seed = seedFor(process.env);
  const rng = seededRandom(seed);
  const statuses = [200, 200, 200, 204, 301, 400, 401, 403, 404, 429, 500, 503];
  const lookupBodies = ['{}', '{"name":""}', `{"name":"projects/${P1}/locations/global/keys/live-1"}`, `{"name":"projects/${P2}/locations/global/keys/live-1"}`, '[]', 'x', '{"name":"projects/1/locations/global/keys/live-1"}'];
  const getBodies = ['{}', '{"deleteTime":"2026-01-01T00:00:00Z"}', '{"deleteTime":""}', '[]', 'x', '{"deleteTime":null}', `{"name":"projects/${P1}/locations/global/keys/live-1"}`];
  const pick = <T,>(xs: readonly T[]): T => xs[rng.int(xs.length)] as T;
  const value = LIVE;
  for (let run = 0; run < 120; run += 1) {
    fresh();
    const [lookupStatus, lookupBody, getStatus, getBody] = [pick(statuses), pick(lookupBodies), pick(statuses), pick(getBodies)];
    w.fake.override('lookup-key', answer(lookupStatus, lookupBody));
    w.fake.override('get-key', answer(getStatus, getBody));
    const verdict = await verify(value);
    const found = lookupStatus === 200 && lookupBody.includes(`projects/${P1}/locations/global/keys/live-1`);
    const live = getStatus === 200 && (getBody === '{}' || getBody === '{"deleteTime":""}' || getBody.startsWith('{"name"'));
    assert.equal(verdict, found && live ? 'ok' : 'unreachable', `seed ${seed}: lookup ${lookupStatus} ${lookupBody}, read ${getStatus} ${getBody}`);
  }
});

// --- a canary value is absent from errors and results on every path (L3) ---------------------------------------------------------

const shaped = (c: ReturnType<typeof canary>): string => `AIza${Buffer.from(c.bytes).toString('base64url').slice(0, 35)}`;
const surfacesOf = (error: Error): Record<string, string> => ({
  message: error.message,
  stack: error.stack ?? '',
  inspected: inspect(error, { depth: 6, showHidden: true }),
  json: JSON.stringify(error, Object.getOwnPropertyNames(error)),
});

test('KBOX-59 KBOX-14 canary: a key value never appears in an error, a returned object or a listing, on any issuer or verifier path; a value not of the shape is never sent', async () => {
  const c = canary(26);
  const value = shaped(c);
  assert.ok(matchesShape(API_KEY_SHAPE, value));
  w.reset();
  w.fake.apis.knobs.nextKeyString = value;
  const issued = await issueOf(P1);
  c.assertAbsent({ issued: inspect(issued, { depth: 6 }), json: JSON.stringify(issued) });
  assert.equal(await textOf(issued.value), value);
  c.assertAbsent({ listing: JSON.stringify(await listerOf().listAt(at(P1), w.master)) });
  // Every failure path with the canary as the key string Google gave back (not of the shape here: one character too many), or nearby.
  const wrong = `${value}x`;
  const setups: readonly (readonly [string, () => void])[] = [
    [
      'key string of the wrong shape',
      () => {
        w.fake.apis.knobs.nextKeyString = wrong;
      },
    ],
    [
      'key string of the wrong shape, delete failing',
      () => {
        w.fake.apis.knobs.nextKeyString = wrong;
        w.fake.override('delete-key', answer(500));
      },
    ],
    [
      'answer naming another place',
      () => {
        w.fake.apis.knobs.nameAs = (_p, id) => `projects/${P2}/locations/global/keys/${id}`;
        w.fake.apis.knobs.nextKeyString = value;
      },
    ],
    [
      'operation error',
      () => {
        w.fake.apis.knobs.operationError = true;
        w.fake.apis.knobs.nextKeyString = value;
      },
    ],
  ];
  for (const [what, setup] of setups) {
    w.reset();
    setup();
    const error = await issueOf(P1).then(
      () => undefined,
      (e: unknown) => e,
    );
    assert.ok(error instanceof GoogleError, what);
    c.assertAbsent(surfacesOf(error));
  }
  // The verifier: a shaped value is sent only in the lookup; a refused answer, a cut one and an echo of it leave it nowhere else.
  for (const [what, override] of [['echo', answer(403, { error: { message: `key ${value} is not allowed` } })], ['cut', CUT], ['404', answer(404)]] as const) {
    w.reset();
    w.fake.apis.plant(P1, { id: 'live-1', displayName: 'kbox_c', keyString: value });
    w.fake.override('lookup-key', override);
    const verdict = await verify(value);
    assert.equal(verdict, 'unreachable', what);
    c.assertAbsent({ verdict });
    const holding = w.sent().filter((s) => Buffer.from(s.body).toString('utf8').includes(value) || s.target.includes(value) || JSON.stringify(s.headers).includes(value));
    assert.deepEqual(holding.map((s) => s.target), [lookupTarget(value)], `${what}: only the lookup carries it`);
  }
  // A value that is not of the shape is never sent, in any form.
  w.reset();
  const odd = `ya29.${Buffer.from(c.bytes).toString('base64url')}`;
  assert.equal(await verify(odd), 'unreachable');
  assert.equal(w.sent().length, 0);
});

// --- G1's hand-off: every call mints kbox-keys@<that call's stored project> and no other ------------------------------------

test('KBOX-41 KBOX-59 with keys stored in two projects, issue, list, verify, revoke and addVersion each mint the admin account of their call\'s project and no other', async () => {
  const calls: readonly (readonly [string, (project: string) => Promise<unknown>])[] = [
    ['issue', (p) => issueOf(p)],
    ['listAt', (p) => listerOf().listAt(at(p), w.master)],
    ['verify', async (p) => verify(planted(p), at(p))],
    ['revoke', (p) => issuerOf().revoke(stored('k-1', p), w.master)],
    ['addVersion', async (p) => (w.fake.apis.makeSecret(p, 's1'), destinationOf().push({ kind: 'google-secret-manager', id: `projects/${p}/secrets/s1` }, 'GEMINI', lent(Buffer.from('v'), 'v'), 'ordinary', w.master))],
  ];
  for (const project of [P1, P2]) {
    for (const [what, call] of calls) {
      w.reset();
      await call(project);
      assert.deepEqual(w.minted(), [adminOf(project)], `${what} at ${project}`);
      assert.deepEqual(projectsNamed(), [project], `${what} at ${project}`);
    }
  }
});

test('KBOX-41 KBOX-59 negative control: Google refuses one project\'s admin token at another project, so the pin above has teeth', async () => {
  w.reset();
  const token = await w.minter.mint({ use: 'admin', at: at(P1) }, w.master);
  const status = await token.token.use(async (bytes) => (await w.http.request({ method: 'GET', url: `https://${APIKEYS}/v2/projects/${P2}/locations/global/keys`, headers: { authorization: `Bearer ${Buffer.from(bytes).toString('utf8')}` } })).status);
  assert.equal(status, 403);
});

// --- the contract suites ------------------------------------------------------------------------------------------------------------

const subject = () => {
  w.reset();
  return { issuer: issuerOf(), lister: listerOf(), master: w.master, wrongMaster: w.wrongMaster, scope: SCOPE, unknownId: stored('never-issued'), listedAt: at(P1) };
};
issuerContract('google', subject, at(P1));
listerContract('google', subject, at(P1));

// --- the Secret Manager destination -------------------------------------------------------------------------------------------------

const TARGET: DestinationTarget = { kind: 'google-secret-manager', id: `projects/${P1}/secrets/s1` };
const push = (value: string, klass: 'ordinary' | 'admin' | 'master' = 'ordinary', target: DestinationTarget = TARGET, master: Lent = w.master) =>
  destinationOf().push(target, 'GEMINI_KEY', lent(Buffer.from(value), 'v'), klass, master);

test('KBOX-16 KBOX-59 the destination is readable by the API (an ordinary key only), needs no redeploy; it adds a version of the target secret, made by the project\'s admin account', async () => {
  assert.deepEqual(destinationOf().properties(), { readableBy: 'api', needsRedeploy: false });
  assert.equal(destinationOf().kind, 'google-secret-manager');
  assert.equal(entry.destinations?.[0]?.redeployer, undefined);
  w.reset();
  w.fake.apis.makeSecret(P1, 's1');
  const first = await push('value-one');
  assert.equal(first.outcome, 'applied');
  assert.deepEqual(w.fake.apis.versionsOf(P1, 's1'), ['value-one']);
  assert.deepEqual(w.calls(SECRETS).map((c) => `${c.method} ${c.target}`), [`POST /v1/projects/${P1}/secrets/s1:addVersion`]);
  assert.deepEqual(w.minted(), [adminOf(P1)]);
  const again = await push('value-two');
  assert.equal(again.outcome, 'applied');
  assert.equal(JSON.stringify([first, again]).includes('value-'), false, 'a receipt holds nothing of the value');
  assert.equal(JSON.stringify([first, again]).includes(Buffer.from('value-one').toString('base64')), false);
});

test('KBOX-16 KBOX-59 the destination refuses an admin or a master key before any call, and a target that is not projects/<project id>/secrets/<secret id>', async () => {
  w.reset();
  w.fake.apis.makeSecret(P1, 's1');
  for (const klass of ['admin', 'master'] as const) assert.deepEqual(await push('v', klass), { outcome: 'refused' }, klass);
  assert.equal(w.sent().length, 0);
  const targets: DestinationTarget[] = [{ kind: 'vercel-env', id: TARGET.id }, { kind: TARGET.kind, id: '' }, { kind: TARGET.kind, id: `projects/P1/secrets/s1` }, { kind: TARGET.kind, id: `projects/${P1}/secrets/` }, { kind: TARGET.kind, id: `projects/${P1}/secrets/s1/versions/1` }, { kind: TARGET.kind, id: `projects/${P1}/secrets/s:1` }, { kind: TARGET.kind, id: `projects/${P1}/secrets/${'s'.repeat(256)}` }, { kind: TARGET.kind, id: `projects/${P1}/locations/us/secrets/s1` }, { kind: TARGET.kind, id: `${P1}/s1` }];
  for (const target of targets) assert.equal(await codeOf(push('v', 'ordinary', target)), 'bad_secret_target', JSON.stringify(target));
  assert.equal(w.sent().length, 0);
});

test('KBOX-59 the destination\'s outcomes: Google refusing the request is refused, anything else that may have applied is unknown, a master that cannot be minted throws before any write', async () => {
  w.reset();
  w.fake.apis.makeSecret(P1, 's1');
  for (const code of [400, 401, 403, 404]) {
    w.fake.override('add-version', answer(code));
    assert.deepEqual(await push('v'), { outcome: 'refused' }, String(code));
  }
  for (const code of [429, 500, 503, 302]) {
    w.fake.override('add-version', answer(code));
    assert.deepEqual(await push('v'), { outcome: 'unknown' }, String(code));
  }
  w.fake.override('add-version', CUT);
  assert.deepEqual(await push('v'), { outcome: 'unknown' });
  w.fake.override('add-version', answer(200, 'text'));
  assert.deepEqual(await push('v'), { outcome: 'unknown' }, 'it answered 200 and told nothing: it may hold the value');
  w.fake.override('add-version', undefined);
  assert.equal(await codeOf(push('v', 'ordinary', TARGET, w.wrongMaster)), 'sts_refused');
  assert.equal(w.calls(SECRETS).length, 10, 'no write was tried with the refused master');
});

test('KBOX-59 the destination cannot remove a value it never learned the version of: remove fails closed (the rollback waits) and never deletes a secret', async () => {
  w.reset();
  w.fake.apis.makeSecret(P1, 's1');
  assert.equal(await codeOf(destinationOf().remove(TARGET, 'GEMINI_KEY', w.master)), 'remove_unsupported');
  assert.equal(w.sent().length, 0);
});

// --- the relay profile --------------------------------------------------------------------------------------------------------------

const HOSTS = ['iam', 'iamcredentials', 'sts', 'oauth2', 'securetoken', 'apikeys', 'cloudresourcemanager', 'secretmanager', 'identitytoolkit', 'firebase', 'run', 'cloudfunctions', 'cloudbuild', 'compute', 'appengine', 'cloudscheduler', 'cloudtasks', 'workflows', 'eventarc', 'pubsub'].map((h) => `${h}.googleapis.com`);
/** The spec's mustDeny samples (KBOX-59), as the caller would send them. */
const SPEC_DENY: readonly (readonly [string, string, string])[] = [
  ['POST', 'iamcredentials.googleapis.com', '/v1/projects/-/serviceAccounts/x@p.iam.gserviceaccount.com:generateAccessToken'],
  ['POST', 'sts.googleapis.com', '/v1/token'],
  ['POST', 'oauth2.googleapis.com', '/token'],
  ['GET', 'accounts.google.com', '/o/oauth2/v2/auth'],
  ['POST', 'securetoken.googleapis.com', '/v1/token'],
  ['GET', 'apikeys.googleapis.com', '/v2/projects/p/locations/global/keys'],
  ['POST', 'cloudresourcemanager.googleapis.com', '/v1/projects/p:getIamPolicy'],
  ['GET', 'secretmanager.googleapis.com', '/v1/projects/p/secrets/s/versions/1:access'],
  ['POST', 'identitytoolkit.googleapis.com', '/v1/accounts:signInWithCustomToken'],
  ['GET', 'firebase.googleapis.com', '/v1beta1/projects/p/webApps/a/config'],
  ...['run', 'cloudfunctions', 'cloudbuild', 'compute', 'appengine', 'cloudscheduler', 'cloudtasks', 'workflows', 'eventarc'].map((h): readonly [string, string, string] => ['GET', `${h}.googleapis.com`, '/v1/projects/p']),
  ['PUT', 'pubsub.googleapis.com', '/v1/projects/p/subscriptions/s'],
  ['PATCH', 'pubsub.googleapis.com', '/v1/projects/p/subscriptions/s'],
  ['POST', 'storage.googleapis.com', '/storage/v1/projects/p/hmacKeys?serviceAccountEmail=x'],
  ['GET', 'storage.googleapis.com', '/storage/v1/b/b/iam'],
  ['PUT', 'storage.googleapis.com', '/storage/v1/b/b/iam'],
  ['POST', 'firestore.googleapis.com', '/v1/projects/p/databases/d:setIamPolicy'],
];

const profile: RelayProfile = googleRelayProfile;

test('KBOX-59 the relay profile: host in the first path segment, the spec\'s deny samples each with the KBOX-13 variants, the pass in no query; it passes the registry check', () => {
  assert.equal(profile.platform, 'google');
  assert.equal(profile.origin.kind, 'host-in-path');
  const urls = profile.mustDeny.flatMap((d) => d.samples.map((s) => `${s.method} ${s.url}`));
  for (const [method, host, path] of SPEC_DENY) assert.ok(urls.includes(`${method} https://${host}${path}`), `${method} ${host}${path}`);
  for (const host of HOSTS) assert.ok(profile.origin.kind === 'host-in-path' && profile.origin.hosts.includes(host), host);
  assert.ok(profile.mustDeny.every((d) => d.samples.length >= 10), 'each rule carries the canonicalisation variants');
  assert.deepEqual(checkRegistry([{ id: 'google', relay: profile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), { ok: true });
  assert.deepEqual(profile.allow.map((r) => r.id).filter((id) => id.startsWith('gcs')).sort(), ['gcs-list', 'gcs-object-delete', 'gcs-object-get', 'gcs-upload']);
  assert.ok(profile.allow.some((r) => r.id.startsWith('fs-doc')) && profile.allow.some((r) => r.id.startsWith('fs-query')));
  assert.deepEqual(profile.envForClients('https://relay.example/r/k'), { KBOX_GOOGLE_RELAY_URL: 'https://relay.example/r/k' });
});

test('KBOX-59 the relay injects the key only as header x-goog-api-key: never a key= query, never the authorization header', async () => {
  const headers = new Headers({ authorization: 'Bearer pass', 'x-goog-api-key': 'caller-sent' });
  await profile.inject(headers, lent(Buffer.from('AIza-value'), 'v'));
  assert.equal(headers.get('x-goog-api-key'), 'AIza-value');
  assert.equal(headers.get('authorization'), null, 'the caller\'s pass does not go upstream');
  assert.ok(profile.allow.every((r) => !Object.hasOwn(r.query, 'key')), 'no rule lets a caller name the key in a query');
});

const KEYREF = 'hostkey001';

/** Every sample of the profile through a running relay: each that got anything but 400 or 403, or reached upstream. */
async function leaks(t: TestContext): Promise<{ readonly through: string[]; readonly sent: number }> {
  const registry = TEST_REGISTRY.map((e) => (e.id === 'hostplat' ? { id: 'hostplat', relay: { ...profile, platform: 'hostplat' }, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] } : e));
  const relay = await relayWorld(t, { registry });
  const through: string[] = [];
  let sent = 0;
  for (const rule of profile.mustDeny) {
    for (const sample of rule.samples) {
      sent += 1;
      const before = relay.upstream.requests.length;
      const rest = sample.url.slice('https://'.length);
      const reply = await relay.call(`/r/${KEYREF}/${rest}`, { method: sample.method });
      if ((reply.status !== 400 && reply.status !== 403) || relay.upstream.requests.length !== before) through.push(`${rule.id} ${sample.method} ${sample.url} -> ${reply.status}`);
    }
  }
  return { through, sent };
}

test('KBOX-25 KBOX-59 every mustDeny sample of the Google profile, with its canonicalisation variants, is 400 or 403 through a running relay, with no upstream call', async (t) => {
  const { through, sent } = await leaks(t);
  assert.deepEqual(through, []);
  assert.ok(sent >= 200, `${sent} samples`);
});

// --- one rotation through core with the Google adapters over the fake Google ---------------------------------------------------

/** Core's platform source over the Google adapters of this file and the box's signing key as the one master. */
const googleSource = (real: PlatformSource): PlatformSource => ({
  ...real,
  platform: () => ({ issuer: issuerOf(), lister: listerOf(), verifier: verifierOf(), ...(entry.location === undefined ? {} : { location: entry.location }) }),
  master: () => ({ ok: true, value: w.master }),
  masters: () => [{ at: {}, value: w.master }],
});

test('KBOX-51 KBOX-58 KBOX-59 a Google key rotates through core: the verifier is handed the master at steps 5 and 8, the new key is verified, and with no probed death answer the old one stays in grace with one notice and one audit row; no key value reaches an event, an audit row or a push', async (t) => {
  w.reset();
  const c = canary(26);
  const keyref = `google/${P1}/GEMINI_KEY`;
  const world = await rotationWorld(t, { source: googleSource });
  await world.seedKey({ keyref, platform: 'google', name: 'GEMINI_KEY', projects: [P1], scopeItems: [FIRESTORE], class: 'ordinary', destinations: [], location: at(P1) });
  assert.equal(world.store.gens(keyref).length, 1, 'the first generation was made, verified and stored');
  w.fake.apis.knobs.nextKeyString = shaped(c);
  world.orch.start({ keyref, origin: 'owner' });
  await world.orch.idle();
  assert.equal(world.store.activeRunOf(keyref)?.state, 'grace');
  assert.equal(world.store.gen(keyref, 2)?.status, 'current');
  assert.equal(world.store.gen(keyref, 2)?.location?.project, P1);
  const minted = w.minted();
  assert.ok(minted.length >= 4 && minted.every((account) => account === adminOf(P1)), 'every mint of the run is for the key\'s project');
  world.clock.advance(24 * HOUR);
  await world.orch.idle();
  for (const minutes of [1, 2, 4]) {
    world.clock.advance(minutes * MINUTE);
    await world.orch.idle();
  }
  assert.equal(world.store.gen(keyref, 1)?.status, 'grace', 'no Google answer is a probed death: the old key is not confirmed dead');
  assert.equal(world.events('rotation.old_key_still_on').length, 1, 'one notice');
  const unconfirmed = world.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.revoke_unconfirmed');
  assert.equal(unconfirmed.length, 1, 'one audit row for the stall, not one per retry');
  assert.equal(w.fake.apis.keysOf(P1).filter((k) => k.deleteTime === undefined).length, 1, 'the box did send the DELETE of the old key');
  const everySurface = JSON.stringify([world.parts.events.after(0), world.parts.audit.read(0).entries, world.push.sent]);
  c.assertAbsent({ everySurface });
  assert.equal(await world.valueOf(keyref, 2), shaped(c));
});

test('KBOX-59 KBOX-41 a key whose scope holds an sa: item is refused by the issuer, not made: the run fails at issuing with one notice, and Google is not called at all', async (t) => {
  w.reset();
  const world = await rotationWorld(t, { source: googleSource });
  const key = world.newKey({ keyref: `google/${P1}/ACTING_KEY`, platform: 'google', name: 'ACTING_KEY', projects: [P1], scopeItems: ['sa:p-proj1/acct1x'], class: 'ordinary', destinations: [], location: at(P1) });
  world.orch.create(key);
  await world.orch.idle();
  const failed = world.events('rotation.failed');
  assert.deepEqual(failed.map((e) => [e.data['step'], e.data['reason_code']]), [['issuing', 'issue_failed']]);
  assert.equal(w.calls().length, 0, 'no mint and no call: the issuer refused the scope first');
});
