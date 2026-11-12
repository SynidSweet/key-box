// KBOX-36: the Vercel adapter's issuer, lister, verifier and shape over a stateful fake of api.vercel.com (test/fakes/vercel.ts), and the
// contract suites of the ports they implement. Destination and redeployer are in vercel-env.test.ts, the deny list in vercel-deny.test.ts,
// the canary in vercel-canary.test.ts.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import type { AdapterHttp, HttpRequest, HttpResponse } from '../src/ports/http.ts';
import { HttpTransportError } from '../src/ports/http.ts';
import type { KeyListing } from '../src/ports/issuer.ts';
import { matchesShape } from '../src/pure/class.ts';
import { confirmDead } from '../src/pure/rotation-machine.ts';
import { shapeOf } from '../src/pure/platform-shape.ts';
import { createRegistry } from '../src/platforms/registry.ts';
import { assertRegistry } from '../src/pure/profile.ts';
import { checkLocation } from '../src/pure/location.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { verifierContract } from './contracts/verifier.contract.ts';
import { bytesOf, listAll } from './kit/index.ts';
import { routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';
import { unverifiedDisagreement } from './support/probe-status.ts';
import { MASTER_TEXT, OTHER_PROJECT, PROJECT, WRONG_TEXT, lentText, master, vercelWorld } from './support/vercel-world.ts';

const world = await vercelWorld();
const { fake, http, issuer, lister, verifier } = world;
const fresh = (): typeof world => {
  fake.reset();
  return world;
};
const textOf = async (l: Parameters<typeof bytesOf>[0]): Promise<string> => Buffer.from(await bytesOf(l)).toString('utf8');
const sentSince = (n: number): string[] => http.sent.slice(n).map((s) => `${s.method} ${s.target}`);

issuerContract('vercel', () => {
  fresh();
  return { issuer, master: master(), wrongMaster: lentText(WRONG_TEXT), lister };
});
listerContract('vercel', () => {
  fresh();
  return { issuer, lister, master: master(), wrongMaster: lentText(WRONG_TEXT) };
});
verifierContract('vercel', () => {
  fresh();
  return { issuer, verifier, master: master(), stranger: lentText(WRONG_TEXT), setUnreachable: (down) => void fake.setDown(down) };
});

// ---------------------------------------------------------------- the entry

test('KBOX-36 KBOX-23 the entry is the registry\'s vercel line: deny-only with no relay, the one management host, a key page, and it passes the registry checks', () => {
  const registry = createRegistry({ http, clock: world.clock });
  const entry = registry.find((e) => e.id === 'vercel');
  assert.ok(entry !== undefined, 'createRegistry has a vercel entry');
  assert.equal(entry.relay, undefined);
  assert.ok((entry.denyOnly?.length ?? 0) > 0);
  assert.deepEqual(entry.hosts, ['api.vercel.com']);
  assert.match(entry.keyPageUrl ?? '', /^https:\/\/vercel\.com\//);
  assert.equal(entry.shape, undefined, 'an entry with an issuer takes its shape from the issuer');
  assert.equal(entry.classify, undefined);
  assertRegistry(registry);
});

test('KBOX-42 the entry lists exactly the ids its probe report marks STILL UNVERIFIED', async () => {
  const report = await readFile(new URL('../docs/probes/vercel.md', import.meta.url), 'utf8');
  assert.equal(unverifiedDisagreement(world.entry, report), undefined);
});

test('KBOX-36 every call goes to api.vercel.com over https', async () => {
  fresh();
  const before = http.sent.length;
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_a', master());
  await listAll(lister, master());
  await verifier.verify(made.value, { platform: 'vercel', at: {} });
  await issuer.revoke(made.platformKeyId, master());
  const hosts = new Set(http.sent.slice(before).map((s) => s.originalHost));
  assert.deepEqual([...hosts], ['api.vercel.com']);
});

// ---------------------------------------------------------------- shape

const SHAPE = shapeOf(world.entry);
const core = (n: number, ch = 'a'): string => ch.repeat(n);

test('KBOX-18 KBOX-36 shape accepts a vcp_ token of 24 to 256 base62 characters', () => {
  assert.ok(SHAPE !== undefined);
  for (const n of [24, 32, 40, 64, 256]) assert.equal(matchesShape(SHAPE, `vcp_${core(n)}`), true, `${n}`);
  assert.equal(matchesShape(SHAPE, `vcp_${'aB3'.repeat(10)}`), true);
  assert.equal(SHAPE.prefix, 'vcp_');
  assert.equal(SHAPE.alphabet, 'base62');
  assert.equal(SHAPE.random, true);
});

test('KBOX-18 KBOX-36 shape refuses near misses: wrong prefix, short or long core, characters outside base62', () => {
  assert.ok(SHAPE !== undefined);
  const refused = [`vcx_${core(32)}`, `VCP_${core(32)}`, `vcp${core(32)}`, core(32), `vcp_${core(23)}`, `vcp_${core(257)}`, `vcp_${core(31)}-`, `vcp_${core(16)}_${core(16)}`, `vcp_${core(31)} `, `vcp_${core(31)}\n`, `sk-${core(32)}`, ''];
  for (const value of refused) assert.equal(matchesShape(SHAPE, value), false, JSON.stringify(value));
});

// ---------------------------------------------------------------- issuer

test('KBOX-36 capabilities: api create and revoke, self-rotating master, overlap, no set, the value only in the create response', () => {
  const caps = issuer.capabilities();
  assert.deepEqual(
    { create: caps.create, revoke: caps.revoke, selfRotate: caps.selfRotate, overlap: caps.overlap, set: caps.set, revealOnce: caps.revealOnce },
    { create: 'api', revoke: 'api', selfRotate: true, overlap: true, set: 'none', revealOnce: true },
  );
  assert.equal(issuer.set, undefined);
  // As of the KBOX-57 ruling the project is the key's location and the team a `team:` scope item: the scope has one field.
  assert.deepEqual(caps.scopeSchema.fields, ['items']);
});

// As of the KBOX-57 ruling the project is the key's location (at), never a scope field; the adapter's own view is kept, and the shell's
// KBOX-15 floor makes every Vercel token master (below).
test('KBOX-36 KBOX-57 the adapter\'s classify: a token whose location names a plain project id is ordinary and any other is master', () => {
  const { classify } = issuer.capabilities();
  assert.equal(classify({}, { project: PROJECT }), 'ordinary');
  assert.equal(classify({}, {}), 'master');
  assert.equal(classify({ access: 'read' }, {}), 'master');
  assert.equal(classify({ items: ['team:team_x'] }, {}), 'master');
  assert.equal(classify({}, { project: 'a/b' }), 'master');
});

test('KBOX-36 issue posts name and projectId to /v3/user/tokens with the master as bearer, and nothing else in the body', async () => {
  fresh();
  const before = http.sent.length;
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_name_one', master());
  const sent = http.sent[before];
  assert.equal(sent?.method, 'POST');
  assert.equal(sent?.target, '/v3/user/tokens');
  assert.equal(sent?.headers['authorization'], `Bearer ${MASTER_TEXT}`);
  assert.deepEqual(JSON.parse(Buffer.from(sent?.body ?? []).toString('utf8')), { name: 'kbox_name_one', projectId: PROJECT });
  assert.equal(fake.tokenProject(made.platformKeyId), PROJECT);
  assert.equal(await textOf(made.value), fake.tokenValue(made.platformKeyId));
});

// As of the KBOX-57 ruling the team is a `team:` scope item, never a scope field.
test('KBOX-36 KBOX-57 a master-class issue sends no projectId, and a team: item in the scope goes in the query', async () => {
  fresh();
  const before = http.sent.length;
  const made = await issuer.issue({ scope: { items: ['team:team_abc'] }, at: {} }, 'kbox_master', master());
  const sent = http.sent[before];
  assert.equal(sent?.target, '/v3/user/tokens?teamId=team_abc');
  assert.deepEqual(JSON.parse(Buffer.from(sent?.body ?? []).toString('utf8')), { name: 'kbox_master' });
  assert.equal(fake.tokenProject(made.platformKeyId), undefined);
});

// As of the KBOX-57 ruling the project comes from the location and the team from a `team:` item; the list case is now a project: scope item.
test('KBOX-36 KBOX-57 a location project that is empty or not a plain id, a project: scope item or a team: item that is not a plain id is refused before any call, never turned into a master token', async () => {
  fresh();
  const before = http.sent.length;
  for (const project of ['', ' ', 'a/b', 'a?b', '../x', 'x'.repeat(200)]) {
    await assert.rejects(() => issuer.issue({ scope: {}, at: { project } }, 'kbox_bad', master()), /vercel: bad_scope/);
  }
  await assert.rejects(() => issuer.issue({ scope: { items: [`project:${PROJECT}`] }, at: {} }, 'kbox_bad', master()), /vercel: bad_scope/);
  await assert.rejects(() => issuer.issue({ scope: { items: ['team:a b'] }, at: {} }, 'kbox_bad', master()), /vercel: bad_scope/);
  await assert.rejects(() => issuer.issue({ scope: { items: ['team:t1', 'team:t2'] }, at: {} }, 'kbox_bad', master()), /vercel: bad_scope/, 'two teams');
  await assert.rejects(() => issuer.issue({ scope: { items: ['read'] }, at: {} }, 'kbox_bad', master()), /vercel: bad_scope/, 'an item Vercel does not know');
  await assert.rejects(() => issuer.issue({ scope: { items: ['teams_abc'] }, at: {} }, 'kbox_bad', master()), /vercel: bad_scope/, 'an item without the team: prefix whose tail is a plain id');
  assert.deepEqual(sentSince(before), []);
  assert.deepEqual(fake.tokenIds(), []);
});

test('KBOX-36 the revoke of a project token\'s old id: the token is gone from the platform and a second revoke says absent', async () => {
  fresh();
  const old = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_old', master());
  const next = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_new', master());
  assert.equal(await issuer.revoke(old.platformKeyId, master()), 'revoked');
  assert.deepEqual(fake.tokenIds(), [next.platformKeyId]);
  assert.equal(await issuer.revoke(old.platformKeyId, master()), 'absent');
});

test('KBOX-36 revoke sends DELETE /v3/user/tokens/{id} with the id as one encoded path segment', async () => {
  fresh();
  const before = http.sent.length;
  await issuer.revoke('a/b c', master());
  assert.deepEqual(sentSince(before), ['DELETE /v3/user/tokens/a%2Fb%20c']);
});

test('KBOX-36 a platform failure is a fixed named error: 403 rejected, other 4xx and 5xx by class, transport unreachable, a cut answer malformed', async () => {
  fresh();
  const issue = (): Promise<unknown> => issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_x', master());
  const cases: [number, RegExp][] = [[401, /vercel: rejected/], [403, /vercel: rejected/], [400, /vercel: client_error/], [429, /vercel: client_error/], [500, /vercel: server_error/], [503, /vercel: server_error/]];
  for (const [status, message] of cases) {
    fake.forceStatus(status);
    await assert.rejects(issue, message, String(status));
    await assert.rejects(() => issuer.revoke('t', master()), message, `revoke ${status}`);
  }
  fake.forceStatus(undefined);
  fake.cutAnswers(true);
  await assert.rejects(issue, /vercel: malformed/);
  fake.cutAnswers(false);
  await fake.setDown(true);
  await assert.rejects(issue, /vercel: unreachable/);
  await assert.rejects(() => issuer.revoke('t', master()), /vercel: unreachable/);
  await fake.setDown(false);
  assert.ok(await issue(), 'the platform is back');
});

test('KBOX-36 a create answer without a bearerToken or a token id is a malformed failure and returns no key', async () => {
  const answering = (body: unknown): AdapterHttp => ({ request: (): Promise<HttpResponse> => Promise.resolve({ status: 200, headers: {}, body: Buffer.from(JSON.stringify(body)) }) });
  const bodies: unknown[] = [{}, { bearerToken: 'vcp_x' }, { token: { id: 't' } }, { bearerToken: 7, token: { id: 't' } }, { bearerToken: 'vcp_x', token: { id: '' } }, 'text', null, []];
  for (const body of bodies) {
    const entry = world.entryOver(asHttp(answering(body)));
    await assert.rejects(() => entry.issuer?.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_x', master()) ?? Promise.reject(new Error('no issuer')), /vercel: malformed/, JSON.stringify(body));
  }
});

// ---------------------------------------------------------------- lister

test('KBOX-36 list reads every page of /v6/user/tokens and shows names and project, never a value', async () => {
  fresh();
  const made = [];
  for (const [i, project] of [PROJECT, OTHER_PROJECT, PROJECT, undefined, PROJECT].entries()) {
    made.push(await issuer.issue({ scope: {}, at: project === undefined ? {} : { project } }, `kbox_n${i}`, master()));
  }
  const listed = await listAll(lister, master());
  assert.deepEqual(listed.map((k) => k.name).sort(), ['kbox_n0', 'kbox_n1', 'kbox_n2', 'kbox_n3', 'kbox_n4']);
  assert.deepEqual(listed.find((k) => k.name === 'kbox_n1')?.location, { project: OTHER_PROJECT });
  assert.equal(listed.find((k) => k.name === 'kbox_n3')?.location, undefined);
  for (const key of made) assert.equal(JSON.stringify(listed).includes(await textOf(key.value)), false);
});

test('KBOX-51 KBOX-36 listAt a project is complete and leaves out tokens known to belong to another project, never one of unknown project', async () => {
  fresh();
  const mine = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_mine', master());
  const theirs = await issuer.issue({ scope: {}, at: { project: OTHER_PROJECT } }, 'kbox_theirs', master());
  const wide = await issuer.issue({ scope: {}, at: {} }, 'kbox_wide', master());
  const listing = await lister.listAt({ project: PROJECT }, master());
  assert.equal(listing.complete, true);
  assert.deepEqual(listing.at, { project: PROJECT });
  const ids = listing.keys.map((k) => k.platformKeyId);
  assert.deepEqual(ids.sort(), [mine.platformKeyId, wide.platformKeyId].sort());
  assert.equal(ids.includes(theirs.platformKeyId), false);
});

/** An http that passes the first `n` calls to the fake and answers every later one with `later`. */
const afterCalls = (n: number, later: () => Promise<HttpResponse>): AdapterHttp => {
  let calls = 0;
  return { request: (req: HttpRequest): Promise<HttpResponse> => (++calls <= n ? http.request(req) : later()) };
};
const asHttp = (inner: AdapterHttp): typeof http => ({ ...inner, sent: [] });

test('KBOX-51 KBOX-36 a listing whose later page cannot be read is incomplete, and list refuses to answer from half a listing', async () => {
  fresh();
  for (let i = 0; i < 5; i++) await issuer.issue({ scope: {}, at: { project: PROJECT } }, `kbox_p${i}`, master());
  for (const later of [(): Promise<HttpResponse> => Promise.reject(new HttpTransportError('timeout')), (): Promise<HttpResponse> => Promise.resolve({ status: 500, headers: {}, body: Buffer.from('{}') })]) {
    const entry = world.entryOver(asHttp(afterCalls(1, later)));
    const listing: KeyListing | undefined = await entry.lister?.listAt({ project: PROJECT }, master());
    assert.equal(listing?.complete, false);
    assert.equal(listing?.keys.length, 2, 'the first page is still shown');
    const again = world.entryOver(asHttp(afterCalls(1, later)));
    await assert.rejects(() => again.lister === undefined ? Promise.reject(new Error('no lister')) : listAll(again.lister, master()), /vercel: (unreachable|server_error)/);
  }
});

test('KBOX-51 KBOX-36 a page cursor that repeats ends the listing as incomplete instead of looping', async () => {
  const page = { tokens: [{ id: 't1', name: 'kbox_a' }], pagination: { count: 1, next: 5, prev: null } };
  const looping = world.entryOver(asHttp({ request: (): Promise<HttpResponse> => Promise.resolve({ status: 200, headers: {}, body: Buffer.from(JSON.stringify(page)) }) }));
  const listing = await looping.lister?.listAt({}, master());
  assert.equal(listing?.complete, false);
  assert.deepEqual(listing?.keys.map((k) => k.platformKeyId), ['t1']);
});

test('KBOX-36 the next page is asked with until=<cursor> and a refused master lists nothing', async () => {
  fresh();
  for (let i = 0; i < 3; i++) await issuer.issue({ scope: {}, at: {} }, `kbox_c${i}`, master());
  const before = http.sent.length;
  await listAll(lister, master());
  assert.deepEqual(sentSince(before)[0], 'GET /v6/user/tokens');
  assert.match(sentSince(before)[1] ?? '', /^GET \/v6\/user\/tokens\?until=\d+$/);
  await assert.rejects(() => listAll(lister, lentText(WRONG_TEXT)), /vercel: rejected/);
});

// ---------------------------------------------------------------- verifier

test('KBOX-36 verifier: a master token is ok after GET /v2/user alone', async () => {
  fresh();
  const made = await issuer.issue({ scope: {}, at: {} }, 'kbox_team', master());
  const before = http.sent.length;
  assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'ok');
  assert.deepEqual(sentSince(before), ['GET /v2/user']);
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: {} }), 'ok');
});

test('KBOX-36 verifier: a project token cannot read its user, so it reads itself and then its own project', async () => {
  fresh();
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_proj', master());
  const before = http.sent.length;
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: {} }), 'ok');
  assert.deepEqual(sentSince(before), ['GET /v2/user', 'GET /v5/user/tokens/current', `GET /v9/projects/${PROJECT}`]);
  await issuer.revoke(made.platformKeyId, master());
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: {} }), 'rejected');
});

test('KBOX-36 verifier: a stranger is rejected on 403 with invalidToken, and on 401', async () => {
  fresh();
  assert.equal(await verifier.verify(lentText(WRONG_TEXT), { platform: 'vercel', at: {} }), 'rejected');
  fake.forceStatus(401);
  assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'rejected');
  fake.forceStatus(403);
  assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'unreachable');
});

test('KBOX-36 verifier: no answer, a cut answer, a 5xx or a 429 is unreachable, never rejected', async () => {
  fresh();
  for (const status of [500, 502, 503, 429, 404]) {
    fake.forceStatus(status);
    assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'unreachable', String(status));
  }
  fake.forceStatus(undefined);
  fake.cutAnswers(true);
  assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'unreachable');
  fake.cutAnswers(false);
  await fake.setDown(true);
  assert.equal(await verifier.verify(master(), { platform: 'vercel', at: {} }), 'unreachable');
  await fake.setDown(false);
});

test('KBOX-36 verifier: an outage after the user call, on the token or project call, is unreachable and not a rejection of a live project token', async () => {
  fresh();
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_proj', master());
  for (const calls of [1, 2]) {
    const entry = world.entryOver(asHttp(afterCalls(calls, () => Promise.reject(new HttpTransportError('unreachable')))));
    assert.equal(await entry.verifier?.verify(made.value, { platform: 'vercel', at: {} }), 'unreachable', `outage after ${calls} calls`);
    const erroring = world.entryOver(asHttp(afterCalls(calls, () => Promise.resolve({ status: 500, headers: {}, body: Buffer.from('{}') }))));
    assert.equal(await erroring.verifier?.verify(made.value, { platform: 'vercel', at: {} }), 'unreachable', `5xx after ${calls} calls`);
  }
});

test('KBOX-36 verifier: a token that reads itself but names no project is ok, and one whose project is gone is rejected', async () => {
  const answers = (token: unknown, project: number): AdapterHttp => ({
    request: (req: HttpRequest): Promise<HttpResponse> => {
      const url = new URL(req.url);
      const reply = (status: number, body: unknown): Promise<HttpResponse> => Promise.resolve({ status, headers: {}, body: Buffer.from(JSON.stringify(body)) });
      if (url.pathname === '/v2/user') return reply(403, { error: { code: 'forbidden' } });
      if (url.pathname === '/v5/user/tokens/current') return reply(200, token);
      return reply(project, {});
    },
  });
  const verify = (token: unknown, project: number): Promise<string | undefined> => world.entryOver(asHttp(answers(token, project))).verifier?.verify(master(), { platform: 'vercel', at: {} }) ?? Promise.resolve(undefined);
  assert.equal(await verify({ token: { id: 't' } }, 200), 'ok');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 200), 'ok');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 404), 'rejected');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 403), 'unreachable');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 500), 'unreachable');
  assert.equal(await verify({}, 200), 'unreachable', 'an answer that is no token record proves nothing');
  assert.equal(await verify('text', 200), 'unreachable');
});

test('KBOX-36 verifier: a project id from the platform is one encoded path segment', async () => {
  const seen: string[] = [];
  const probing: AdapterHttp = {
    request: (req: HttpRequest): Promise<HttpResponse> => {
      const path = new URL(req.url).pathname;
      seen.push(path);
      const body = path === '/v5/user/tokens/current' ? { token: { projectId: 'a/b ../c' } } : {};
      return Promise.resolve({ status: path === '/v2/user' ? 403 : 200, headers: {}, body: Buffer.from(JSON.stringify(body)) });
    },
  };
  await world.entryOver(asHttp(probing)).verifier?.verify(master(), { platform: 'vercel', at: {} });
  assert.equal(seen[2], '/v9/projects/a%2Fb%20..%2Fc');
});

test('KBOX-36 an id of "." or ".." or one that is empty never reaches a path: revoke and verify refuse before any call', async () => {
  fresh();
  const before = http.sent.length;
  for (const id of ['', '.', '..']) await assert.rejects(() => issuer.revoke(id, master()), /vercel: bad_scope/, JSON.stringify(id));
  assert.deepEqual(sentSince(before), []);
});

// ---------------------------------------------------------------- review fixes (adapters batch 1)

test('KBOX-36 KBOX-51 verifier: a live project token refused on its own record (a plain 403) is no verdict, and never confirms a revoke', async () => {
  fresh();
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_proj', master());
  fake.restrictSelfRead(true);
  const verdict = await verifier.verify(made.value, { platform: 'vercel', at: {} });
  assert.notEqual(verdict, 'rejected');
  assert.equal(confirmDead({ by: 'verifier', verdict }), false);
  fake.restrictSelfRead(false);
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: {} }), 'ok', 'the switch is the only difference');
});

test('KBOX-36 KBOX-51 verifier: its own record answered 401, or 403 saying invalidToken, is the platform saying the token is invalid: rejected', async () => {
  const answers = (self: { status: number; body: unknown }): AdapterHttp => ({
    request: (req: HttpRequest): Promise<HttpResponse> => {
      const path = new URL(req.url).pathname;
      const reply = path === '/v2/user' ? { status: 403, body: { error: { code: 'forbidden' } } } : self;
      return Promise.resolve({ status: reply.status, headers: {}, body: Buffer.from(JSON.stringify(reply.body)) });
    },
  });
  const verify = (self: { status: number; body: unknown }): Promise<string | undefined> => world.entryOver(asHttp(answers(self))).verifier?.verify(master(), { platform: 'vercel', at: {} }) ?? Promise.resolve(undefined);
  assert.equal(await verify({ status: 401, body: {} }), 'rejected');
  assert.equal(await verify({ status: 403, body: { error: { code: 'forbidden', invalidToken: true } } }), 'rejected');
  assert.equal(await verify({ status: 403, body: { error: { code: 'forbidden', message: 'Not authorized' } } }), 'unreachable');
  assert.equal(await verify({ status: 403, body: { error: { code: 'forbidden', invalidToken: 'yes' } } }), 'unreachable', 'only the boolean true says invalid');
});

test('KBOX-14 KBOX-36 a key that cannot be a header value is refused with no call: the verifier says rejected, any other call a fixed bad_key', async () => {
  fresh();
  const before = http.sent.length;
  for (const bad of ['vcp_a\nb', 'vcp_a b', 'vcp_\u0001x', 'vcp_é', '']) {
    assert.equal(await verifier.verify(lentText(bad), { platform: 'vercel', at: {} }), 'rejected', JSON.stringify(bad));
    await assert.rejects(() => listAll(lister, lentText(bad)), /vercel: bad_key/);
    await assert.rejects(() => issuer.revoke('tok_x', lentText(bad)), /vercel: bad_key/);
  }
  assert.deepEqual(sentSince(before), []);
});

test('KBOX-42 the entry and unverified.json list the paging of the variable list that remove relies on', async () => {
  const listed = JSON.parse(await readFile(new URL('../src/platforms/vercel/unverified.json', import.meta.url), 'utf8')) as string[];
  assert.ok(world.entry.unverified.includes('vercel.env-list-pagination'));
  assert.ok(listed.includes('vercel.env-list-pagination'));
});

test('KBOX-36 KBOX-51 verifier: a project token refused on its own project (a plain 403) is no verdict; 401, or 403 saying invalidToken, is rejected', async () => {
  const answers = (project: { status: number; body: unknown }): AdapterHttp => ({
    request: (req: HttpRequest): Promise<HttpResponse> => {
      const path = new URL(req.url).pathname;
      const reply = path === '/v2/user' ? { status: 403, body: { error: { code: 'forbidden' } } } : path === '/v5/user/tokens/current' ? { status: 200, body: { token: { id: 't', projectId: 'prj_x' } } } : project;
      return Promise.resolve({ status: reply.status, headers: {}, body: Buffer.from(JSON.stringify(reply.body)) });
    },
  });
  const verify = (project: { status: number; body: unknown }): Promise<string | undefined> => world.entryOver(asHttp(answers(project))).verifier?.verify(master(), { platform: 'vercel', at: {} }) ?? Promise.resolve(undefined);
  assert.equal(await verify({ status: 403, body: { error: { code: 'forbidden', message: 'Not authorized' } } }), 'unreachable');
  assert.equal(await verify({ status: 401, body: {} }), 'rejected');
  assert.equal(await verify({ status: 403, body: { error: { code: 'forbidden', invalidToken: true } } }), 'rejected');
  assert.equal(await verify({ status: 404, body: {} }), 'rejected');
  assert.equal(await verify({ status: 200, body: {} }), 'ok');
});

// ---------------------------------------------------------------- placement (KBOX-57)

test('KBOX-57 the entry declares the key\'s project as its location: a plain id, required of no class; a region is no Vercel field', () => {
  for (const klass of ['ordinary', 'admin', 'master'] as const) {
    assert.equal(checkLocation(world.entry.location, { project: PROJECT }, klass, []), 'ok');
    assert.equal(checkLocation(world.entry.location, {}, klass, []), 'ok', klass);
  }
  for (const bad of ['a/b', '.x', 'x.', 'x'.repeat(129), ' x']) assert.equal(checkLocation(world.entry.location, { project: bad }, 'master', []), 'location_bad_value', bad);
  assert.equal(checkLocation(world.entry.location, { region: 'us' }, 'master', []), 'location_field_unknown');
  assert.equal(checkLocation(world.entry.location, { project: PROJECT }, 'master', [`project:${PROJECT}`]), 'location_in_scope');
  assert.equal(checkLocation(world.entry.location, {}, 'master', ['team:team_abc']), 'ok', 'team: stays a scope item');
});

test('KBOX-57 the issuer reports the project the create answer names as the issued key\'s location, and makes no claim when it names none', async () => {
  const answering = (token: object): AdapterHttp => ({ request: (): Promise<HttpResponse> => Promise.resolve({ status: 200, headers: {}, body: Buffer.from(JSON.stringify({ bearerToken: 'vcp_x', token })) }) });
  const named = await world.entryOver(asHttp(answering({ id: 't', projectId: OTHER_PROJECT }))).issuer?.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_x', master());
  assert.deepEqual(named?.location, { project: OTHER_PROJECT });
  const silent = await world.entryOver(asHttp(answering({ id: 't' }))).issuer?.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_x', master());
  assert.equal(silent?.location, undefined);
});

test('KBOX-36 KBOX-57 verifier: a token whose location names a project reads that project, never the project the token says it has', async () => {
  fresh();
  const made = await issuer.issue({ scope: {}, at: { project: PROJECT } }, 'kbox_proj', master());
  const before = http.sent.length;
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: { project: PROJECT } }), 'ok');
  assert.deepEqual(sentSince(before), ['GET /v2/user', `GET /v9/projects/${PROJECT}`]);
  assert.notEqual(await verifier.verify(made.value, { platform: 'vercel', at: { project: OTHER_PROJECT } }), 'ok', 'a token for another project does not work here');
  await issuer.revoke(made.platformKeyId, master());
  assert.equal(await verifier.verify(made.value, { platform: 'vercel', at: { project: PROJECT } }), 'rejected');
  const claims: string[] = [];
  const claiming: AdapterHttp = {
    request: (req: HttpRequest): Promise<HttpResponse> => {
      const path = new URL(req.url).pathname;
      claims.push(path);
      const body = path === '/v5/user/tokens/current' ? { token: { id: 't', projectId: OTHER_PROJECT } } : {};
      return Promise.resolve({ status: path === '/v2/user' ? 403 : 200, headers: {}, body: Buffer.from(JSON.stringify(body)) });
    },
  };
  await world.entryOver(asHttp(claiming)).verifier?.verify(master(), { platform: 'vercel', at: { project: PROJECT } });
  assert.deepEqual(claims, ['/v2/user', `/v9/projects/${PROJECT}`]);
});

test('KBOX-15 KBOX-57 at the route every Vercel token classes master, a project token too: nothing is issued and no key row is written', async (t) => {
  const box: { w?: RoutesWorld } = {};
  const w = await routesWorld(t, {
    source: (real) => ({
      ...real,
      platform: (id) => {
        if (id !== 'vercel') return real.platform(id);
        assert.ok(box.w);
        const routes = box.w;
        return createPlatformSource({ registry: [world.entry], meta: routes.parts.meta, vault: routes.parts.vault, keyInfo: (keyref) => routes.rotation.store.keyInfo(keyref) }).platform(id);
      },
    }),
  });
  box.w = w;
  fresh();
  const before = http.sent.length;
  for (const placed of [{ location: { project: PROJECT } }, {}]) {
    const reply = await w.api('/api/keys', { json: { platform: 'vercel', name: 'VERCEL_TOKEN', projects: ['shop'], scope: { items: ['team:team_abc'] }, ...placed } });
    // KBOX-34 (shared-2 U6): the master result is a paste task (it was `master_not_issuable`); the class is what this pins.
    assert.equal(reply.status, 202, reply.body);
    assert.equal((reply.json() as { class: string }).class, 'master', JSON.stringify(placed));
    assert.equal(typeof (reply.json() as { paste_task_id: unknown }).paste_task_id, 'string', JSON.stringify(placed));
  }
  assert.deepEqual(sentSince(before), []);
  assert.equal(w.parts.meta.snapshot().keys.length, 0);
});

test('KBOX-36 KBOX-57 the Vercel master of a key is the team token of the key\'s own team (masterItems team:), never another team\'s, and a project token is no master', async (t) => {
  const w = await routesWorld(t);
  const source = createPlatformSource({ registry: [world.entry], meta: w.parts.meta, vault: w.parts.vault, keyInfo: (keyref) => w.rotation.store.keyInfo(keyref) });
  const put = (keyref: string, items: readonly string[], at: { readonly project?: string }, text: string): void => {
    w.parts.vault.put(keyref, 1, Buffer.from(text));
    w.parts.meta.putKey({ keyref, platform: 'vercel', name: 'VERCEL_TOKEN', projects: [], class: 'master', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
    w.rotation.store.putKeyInfo(keyref, { scopeItems: items, location: at, rotatedAt: 0, markAdmin: false });
  };
  put('vercel/a/VERCEL_TOKEN', ['team:team_a'], {}, 'team-a-master');
  put('vercel/b/VERCEL_TOKEN', ['team:team_b'], {}, 'team-b-master');
  put('vercel/a-project/VERCEL_TOKEN', ['team:team_a'], { project: PROJECT }, 'project-token');
  const pick = async (at: { readonly project?: string }, items: readonly string[]): Promise<string> => {
    const result = source.master('vercel', at, items);
    return result.ok ? textOf(result.value) : result.code;
  };
  assert.equal(await pick({ project: PROJECT }, ['team:team_a']), 'team-a-master', 'the project token of team_a (master only by the floor) is not a candidate');
  assert.equal(await pick({}, ['team:team_b']), 'team-b-master');
  assert.equal(await pick({}, []), 'no_master', 'a key naming no team has no team master');
});
