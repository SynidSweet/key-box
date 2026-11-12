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
import { shapeOf } from '../src/pure/platform-shape.ts';
import { createRegistry } from '../src/platforms/registry.ts';
import { assertRegistry } from '../src/pure/profile.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { verifierContract } from './contracts/verifier.contract.ts';
import { bytesOf } from './kit/index.ts';
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
  const made = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_a', master());
  await lister.list(master());
  await verifier.verify(made.value, { platform: 'vercel' });
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
  assert.deepEqual(caps.scopeSchema.fields, ['projectId', 'teamId']);
});

test('KBOX-36 classify: a token made with a project id is ordinary and any other is master', () => {
  const { classify } = issuer.capabilities();
  assert.equal(classify({ projectId: PROJECT }), 'ordinary');
  assert.equal(classify({}), 'master');
  assert.equal(classify({ access: 'read' }), 'master');
  assert.equal(classify({ teamId: 'team_x' }), 'master');
  assert.equal(classify({ projectId: ['a', 'b'] }), 'master');
});

test('KBOX-36 issue posts name and projectId to /v3/user/tokens with the master as bearer, and nothing else in the body', async () => {
  fresh();
  const before = http.sent.length;
  const made = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_name_one', master());
  const sent = http.sent[before];
  assert.equal(sent?.method, 'POST');
  assert.equal(sent?.target, '/v3/user/tokens');
  assert.equal(sent?.headers['authorization'], `Bearer ${MASTER_TEXT}`);
  assert.deepEqual(JSON.parse(Buffer.from(sent?.body ?? []).toString('utf8')), { name: 'kbox_name_one', projectId: PROJECT });
  assert.equal(fake.tokenProject(made.platformKeyId), PROJECT);
  assert.equal(await textOf(made.value), fake.tokenValue(made.platformKeyId));
});

test('KBOX-36 a master-class issue sends no projectId, and a teamId in the scope goes in the query', async () => {
  fresh();
  const before = http.sent.length;
  const made = await issuer.issue({ scope: { teamId: 'team_abc' } }, 'kbox_master', master());
  const sent = http.sent[before];
  assert.equal(sent?.target, '/v3/user/tokens?teamId=team_abc');
  assert.deepEqual(JSON.parse(Buffer.from(sent?.body ?? []).toString('utf8')), { name: 'kbox_master' });
  assert.equal(fake.tokenProject(made.platformKeyId), undefined);
});

test('KBOX-36 a projectId that is empty, not text or not a plain id is refused before any call, never turned into a master token', async () => {
  fresh();
  const before = http.sent.length;
  for (const projectId of ['', ' ', 'a/b', 'a?b', '../x', ['a', 'b'], 'x'.repeat(200)]) {
    await assert.rejects(() => issuer.issue({ scope: { projectId } }, 'kbox_bad', master()), /vercel: bad_scope/);
  }
  await assert.rejects(() => issuer.issue({ scope: { teamId: 'a b' } }, 'kbox_bad', master()), /vercel: bad_scope/);
  assert.deepEqual(sentSince(before), []);
  assert.deepEqual(fake.tokenIds(), []);
});

test('KBOX-36 the revoke of a project token\'s old id: the token is gone from the platform and a second revoke says absent', async () => {
  fresh();
  const old = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_old', master());
  const next = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_new', master());
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
  const issue = (): Promise<unknown> => issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_x', master());
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
    await assert.rejects(() => entry.issuer?.issue({ scope: { projectId: PROJECT } }, 'kbox_x', master()) ?? Promise.reject(new Error('no issuer')), /vercel: malformed/, JSON.stringify(body));
  }
});

// ---------------------------------------------------------------- lister

test('KBOX-36 list reads every page of /v6/user/tokens and shows names and project, never a value', async () => {
  fresh();
  const made = [];
  for (const [i, project] of [PROJECT, OTHER_PROJECT, PROJECT, undefined, PROJECT].entries()) {
    made.push(await issuer.issue({ scope: project === undefined ? {} : { projectId: project } }, `kbox_n${i}`, master()));
  }
  const listed = await lister.list(master());
  assert.deepEqual(listed.map((k) => k.name).sort(), ['kbox_n0', 'kbox_n1', 'kbox_n2', 'kbox_n3', 'kbox_n4']);
  assert.deepEqual(listed.find((k) => k.name === 'kbox_n1')?.location, { project: OTHER_PROJECT });
  assert.equal(listed.find((k) => k.name === 'kbox_n3')?.location, undefined);
  for (const key of made) assert.equal(JSON.stringify(listed).includes(await textOf(key.value)), false);
});

test('KBOX-51 KBOX-36 listAt a project is complete and leaves out tokens known to belong to another project, never one of unknown project', async () => {
  fresh();
  const mine = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_mine', master());
  const theirs = await issuer.issue({ scope: { projectId: OTHER_PROJECT } }, 'kbox_theirs', master());
  const wide = await issuer.issue({ scope: {} }, 'kbox_wide', master());
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
  for (let i = 0; i < 5; i++) await issuer.issue({ scope: { projectId: PROJECT } }, `kbox_p${i}`, master());
  for (const later of [(): Promise<HttpResponse> => Promise.reject(new HttpTransportError('timeout')), (): Promise<HttpResponse> => Promise.resolve({ status: 500, headers: {}, body: Buffer.from('{}') })]) {
    const entry = world.entryOver(asHttp(afterCalls(1, later)));
    const listing: KeyListing | undefined = await entry.lister?.listAt({ project: PROJECT }, master());
    assert.equal(listing?.complete, false);
    assert.equal(listing?.keys.length, 2, 'the first page is still shown');
    const again = world.entryOver(asHttp(afterCalls(1, later)));
    await assert.rejects(() => again.lister?.list(master()) ?? Promise.reject(new Error('no lister')), /vercel: (unreachable|server_error)/);
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
  for (let i = 0; i < 3; i++) await issuer.issue({ scope: {} }, `kbox_c${i}`, master());
  const before = http.sent.length;
  await lister.list(master());
  assert.deepEqual(sentSince(before)[0], 'GET /v6/user/tokens');
  assert.match(sentSince(before)[1] ?? '', /^GET \/v6\/user\/tokens\?until=\d+$/);
  await assert.rejects(() => lister.list(lentText(WRONG_TEXT)), /vercel: rejected/);
});

// ---------------------------------------------------------------- verifier

test('KBOX-36 verifier: a master token is ok after GET /v2/user alone', async () => {
  fresh();
  const made = await issuer.issue({ scope: {} }, 'kbox_team', master());
  const before = http.sent.length;
  assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'ok');
  assert.deepEqual(sentSince(before), ['GET /v2/user']);
  assert.equal(await verifier.verify(made.value, { platform: 'vercel' }), 'ok');
});

test('KBOX-36 verifier: a project token cannot read its user, so it reads itself and then its own project', async () => {
  fresh();
  const made = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_proj', master());
  const before = http.sent.length;
  assert.equal(await verifier.verify(made.value, { platform: 'vercel' }), 'ok');
  assert.deepEqual(sentSince(before), ['GET /v2/user', 'GET /v5/user/tokens/current', `GET /v9/projects/${PROJECT}`]);
  await issuer.revoke(made.platformKeyId, master());
  assert.equal(await verifier.verify(made.value, { platform: 'vercel' }), 'rejected');
});

test('KBOX-36 verifier: a stranger is rejected on 403 with invalidToken, and on 401', async () => {
  fresh();
  assert.equal(await verifier.verify(lentText(WRONG_TEXT), { platform: 'vercel' }), 'rejected');
  fake.forceStatus(401);
  assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'rejected');
  fake.forceStatus(403);
  assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'rejected');
});

test('KBOX-36 verifier: no answer, a cut answer, a 5xx or a 429 is unreachable, never rejected', async () => {
  fresh();
  for (const status of [500, 502, 503, 429, 404]) {
    fake.forceStatus(status);
    assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'unreachable', String(status));
  }
  fake.forceStatus(undefined);
  fake.cutAnswers(true);
  assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'unreachable');
  fake.cutAnswers(false);
  await fake.setDown(true);
  assert.equal(await verifier.verify(master(), { platform: 'vercel' }), 'unreachable');
  await fake.setDown(false);
});

test('KBOX-36 verifier: an outage after the user call, on the token or project call, is unreachable and not a rejection of a live project token', async () => {
  fresh();
  const made = await issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_proj', master());
  for (const calls of [1, 2]) {
    const entry = world.entryOver(asHttp(afterCalls(calls, () => Promise.reject(new HttpTransportError('unreachable')))));
    assert.equal(await entry.verifier?.verify(made.value, { platform: 'vercel' }), 'unreachable', `outage after ${calls} calls`);
    const erroring = world.entryOver(asHttp(afterCalls(calls, () => Promise.resolve({ status: 500, headers: {}, body: Buffer.from('{}') }))));
    assert.equal(await erroring.verifier?.verify(made.value, { platform: 'vercel' }), 'unreachable', `5xx after ${calls} calls`);
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
  const verify = (token: unknown, project: number): Promise<string | undefined> => world.entryOver(asHttp(answers(token, project))).verifier?.verify(master(), { platform: 'vercel' }) ?? Promise.resolve(undefined);
  assert.equal(await verify({ token: { id: 't' } }, 200), 'ok');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 200), 'ok');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 404), 'rejected');
  assert.equal(await verify({ token: { id: 't', projectId: 'prj_x' } }, 403), 'rejected');
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
  await world.entryOver(asHttp(probing)).verifier?.verify(master(), { platform: 'vercel' });
  assert.equal(seen[2], '/v9/projects/a%2Fb%20..%2Fc');
});
