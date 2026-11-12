// KBOX-13: forwarding rules. The first half pins the one parse of the request target (pure); the second half runs the relay
// over a real loopback fake platform through the egress gate's test connector.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { AuditRow } from '../src/ports/audit.ts';
import { RegistryRefused } from '../src/pure/profile.ts';
import { METHOD_OVERRIDE_HEADERS } from '../src/pure/relay-errors.ts';
import { canonicalPath, canonicalQuery, parseRelayTarget } from '../src/pure/target-parse.ts';
import { createLendClient } from '../src/shell/lend-socket.ts';
import { createRelayServer } from '../src/shell/relay-http.ts';
import { waitUntil } from './kit/index.ts';
import { pathProfile } from './fixtures/profiles.ts';
import { PROJECT_REGISTRY } from './fixtures/profiles.ts';
import { relayWorld } from './support/relay-world.ts';
import type { CallOptions, RelayWorld } from './support/relay-world.ts';

const KEYREF = 'abc123';
const parsed = (target: string) => {
  const result = parseRelayTarget(target);
  if (!result.ok) throw new Error(`refused with ${result.code}`);
  return result.value;
};
const refusal = (target: string): string => {
  const result = parseRelayTarget(target);
  return result.ok ? 'accepted' : result.code;
};

test('KBOX-13 the canonicalisation table: every ambiguous path is bad_path', () => {
  for (const path of [
    '/v1/a%2Fb',
    '/v1/a%2fb',
    '/v1/%2e%2e/x',
    '/v1/%2E/x',
    '/v1/a%5Cb',
    '/v1/a%5cb',
    '/v1//x',
    '/v1/x/',
    '/v1/./x',
    '/v1/../x',
    '/v1/.',
    '/v1/..',
    '/v1/a;x',
    '/v1/a\\b',
    '/v1/a%00b',
    '/v1/a%0Ab',
    '/v1/a\x01b',
    '/v1/a\x7fb',
    '/v1/café',
    '/v1/caf%C3%A9',
    '/v1/a%zz',
    '/v1/a%4',
    '/v1/a%',
    '/v1/a%25b',
    '/v1/a%3Bb',
  ]) {
    assert.equal(refusal(`/r/${KEYREF}${path}`), 'bad_path', path);
  }
});

test('KBOX-13 a raw # anywhere in the target is refused, in the path as bad_path and in the query as bad_query', () => {
  assert.equal(refusal(`/r/${KEYREF}/v1/a#b`), 'bad_path');
  assert.equal(refusal(`/r/${KEYREF}/v1/a?x=1#b`), 'bad_query');
});

test('KBOX-13 escapes are decoded once per segment, rules see the decoded segments, and the sent path is the canonical re-encoding', () => {
  const target = parsed(`/r/${KEYREF}/v1/%6Frganization/a~b_c.d-e/x%3Ay%40z`);
  assert.equal(target.keyref, KEYREF);
  assert.deepEqual(target.segments, ['v1', 'organization', 'a~b_c.d-e', 'x:y@z']);
  assert.equal(canonicalPath(target.segments), '/v1/organization/a~b_c.d-e/x%3Ay%40z');
});

test('KBOX-13 the canonical encoding is idempotent: parsing a canonical path gives the same segments (round trip)', () => {
  for (const segments of [['v1', 'x'], ['a:b', 'c@d', 'e!f', "g'h", 'i(j)', 'k*l', 'm,n', 'o+p', 'q=r', 's$t', 'u&v', 'w|x', 'y"z', '{}', '[]', '<>', '^`', ' ']]) {
    assert.deepEqual(parsed(`/r/${KEYREF}${canonicalPath(segments)}`).segments, segments);
  }
});

test('KBOX-13 a keyref of 5 or 25 characters, with an upper-case letter or a symbol never routes', () => {
  for (const ref of ['abcde', 'a'.repeat(25), 'abcDef', 'abc-def', '_']) assert.equal(refusal(`/r/${ref}/v1/x`), 'not_found', ref);
  for (const ref of ['abcdef', 'a'.repeat(24)]) assert.equal(parsed(`/r/${ref}/v1/x`).keyref, ref);
  for (const target of ['/x/abcdef/v1', '/r', '/r/', '/rr/abcdef', 'r/abcdef', '/R/abcdef']) assert.equal(refusal(target), 'not_found', target);
});

test('KBOX-13 a target with nothing after the keyref is the root path', () => {
  assert.deepEqual(parsed(`/r/${KEYREF}`).segments, []);
  assert.equal(canonicalPath([]), '/');
});

test('KBOX-13 the query table: each ambiguity is bad_query', () => {
  for (const query of ['a=%zz', 'a=%4', 'a=%00', 'a=%0a', 'a=\x01', 'a=café', 'a=1;b=2', '=1', '&a=1', 'a=1&', 'a=1&&b=2', 'a=1&a=2', 'a=1&%61=2', 'a', 'a%3D1=2', 'a=%26', 'a=%3D', 'a=%25', '%25=1', 'a=%7F']) {
    assert.equal(refusal(`/r/${KEYREF}/v1/x?${query}`), 'bad_query', query);
  }
});

test('KBOX-13 query names and values are decoded once, in order, and re-encoded canonically', () => {
  const target = parsed(`/r/${KEYREF}/v1/x?al%74=media&limit=10&%24method=&o=a+b`);
  assert.deepEqual(target.query, [
    ['alt', 'media'],
    ['limit', '10'],
    ['$method', ''],
    ['o', 'a+b'],
  ]);
  assert.equal(canonicalQuery(target.query), 'alt=media&limit=10&%24method=&o=a%2Bb');
  assert.deepEqual(parsed(`/r/${KEYREF}/v1/x?`).query, []);
  assert.equal(canonicalQuery([]), '');
});

// ---------------------------------------------------------------- through the running relay

const PATH = '/r/adminkey1';
const settleAudit = async (w: RelayWorld): Promise<readonly AuditRow[]> => {
  await waitUntil(() => w.lend.core.audit.read(0).entries.some((r) => r.action === 'relay.request'), 'the relay audit row');
  return w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
};

test('KBOX-13 the canonicalisation table through the relay: every ambiguous target is 400 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  for (const [path, code] of [
    ['/v1/a%2Fb', 'bad_path'],
    ['/v1/%2e%2e/models', 'bad_path'],
    ['/v1//models', 'bad_path'],
    ['/v1/models;x', 'bad_path'],
    ['/v1/a%5Cb', 'bad_path'],
    ['/v1/caf%C3%A9', 'bad_path'],
    ['/v1/a%zz', 'bad_path'],
    ['/v1/models?a=%zz', 'bad_query'],
    ['/v1/items?limit=1&limit=2', 'bad_query'],
  ] as const) {
    const reply = await w.call(`${PATH}${path}`);
    assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [400, code], path);
  }
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 the forwarded path and query are the matched ones, canonically encoded', async (t) => {
  const w = await relayWorld(t);
  assert.equal((await w.call(`${PATH}/v1/%6Dodels`)).status, 200);
  assert.equal((await w.call(`${PATH}/v1/items?order=asc&limit=5`)).status, 200);
  assert.deepEqual(w.upstream.requests.map((r) => [r.method, r.url, r.httpVersion]), [
    ['GET', '/v1/models', '1.1'],
    ['GET', '/v1/items?order=asc&limit=5', '1.1'],
  ]);
});

test('KBOX-13 the three method-override headers give 400 method_override with no upstream call; the method comes from the request line', async (t) => {
  const w = await relayWorld(t);
  for (const header of METHOD_OVERRIDE_HEADERS) {
    const reply = await w.call(`${PATH}/v1/models`, { headers: { [header]: 'POST' } });
    assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [400, 'method_override'], header);
  }
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 query tricks are refused with no upstream call: _method, al%74, %24method, %61ccess_token, $httpMethod, a duplicated key', async (t) => {
  const w = await relayWorld(t);
  for (const query of ['_method=POST', 'al%74=media', '%24method=POST', '%61ccess_token=x', '$httpMethod=POST', 'order=asc&order=desc']) {
    const reply = await w.call(`${PATH}/v1/items?${query}`);
    assert.ok([400, 403].includes(reply.status), `${query}: ${reply.status}`);
  }
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 only the allow-listed request headers go upstream: never the caller pass, apikey, cookie-less extras, Range, If-Range or client-address headers', async (t) => {
  const w = await relayWorld(t);
  const reply = await w.call(`${PATH}/v1/models`, {
    headers: {
      accept: 'application/json',
      'openai-beta': 'assistants=v2',
      'x-unlisted': 'nope',
      range: 'bytes=0-9',
      'if-range': '"etag"',
      'x-forwarded-for': '198.51.100.7',
      'x-real-ip': '198.51.100.8',
      forwarded: 'for=198.51.100.9',
      'x-agent': 'claude',
      'x-project': 'shop',
      'accept-encoding': 'gzip',
      apikey: w.pass,
    },
  });
  assert.equal(reply.status, 200);
  const sent = w.upstream.requests[0]?.headers ?? {};
  assert.deepEqual(Object.keys(sent).sort(), ['accept', 'accept-encoding', 'authorization', 'connection', 'host', 'openai-beta']);
  assert.equal(sent['accept-encoding'], 'identity');
  assert.equal(sent['host'], 'api.pathplat.example');
  assert.equal(sent['authorization'], `Bearer ${Buffer.from(w.value).toString()}`);
  assert.equal(JSON.stringify(sent).includes(w.pass), false);
});

test('KBOX-13 a request trailer is not forwarded: the upstream request carries none, with the body length recomputed', async (t) => {
  const w = await relayWorld(t);
  const body = Buffer.from('{"name":"thing"}');
  const reply = await w.call(`${PATH}/v1/items`, { method: 'POST', headers: { 'content-type': 'application/json' }, body, trailers: { 'x-trailer': 'planted' } });
  assert.equal(reply.status, 200);
  const sent = w.upstream.requests[0];
  assert.deepEqual([sent?.body.toString(), sent?.headers['content-length'], sent?.headers['transfer-encoding'], sent?.trailers], [body.toString(), String(body.length), undefined, {}]);
});

test('KBOX-13 a request body over 32 MiB is 413 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  const reply = await w.call(`${PATH}/v1/items`, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(32 * 1024 * 1024 + 1) } });
  assert.equal(reply.status, 413);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 Accept-Profile passes only with the word public: vault gives 403 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  assert.equal((await w.call(`${PATH}/v1/models`, { headers: { 'accept-profile': 'vault' } })).status, 403);
  assert.equal(w.upstream.requests.length, 0);
  assert.equal((await w.call(`${PATH}/v1/models`, { headers: { 'accept-profile': 'public' } })).status, 200);
  assert.equal(w.upstream.requests[0]?.headers['accept-profile'], 'public');
});

test('KBOX-23 a relay with a profile listing Range refuses to start, naming the platform', () => {
  const registry = [{ id: 'pathplat', relay: { ...pathProfile, requestHeaders: [...pathProfile.requestHeaders, 'range'] }, unverified: [] }];
  assert.throws(() => createRelayServer({ registry, lend: createLendClient('/nonexistent'), egress: { open: () => Promise.reject(new Error('unused')) }, domain: 'box.example', journal: () => undefined }), (e: unknown) => e instanceof RegistryRefused && e.message === 'registry check failed: partial_content_header (pathplat)');
});

test('KBOX-13 a 3xx is not followed: the caller gets it with its Location and upstream sees one request', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(302, { location: 'https://elsewhere.example/next', 'set-cookie': 'a=b' });
    res.end();
  });
  const reply = await w.call(`${PATH}/v1/models`);
  assert.deepEqual([reply.status, reply.headers['location'], reply.headers['set-cookie']], [302, 'https://elsewhere.example/next', undefined]);
  assert.equal(w.upstream.requests.length, 1);
});

test('KBOX-3 a granted master keyref gives 403 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  w.lend.addKey({ keyref: 'masterkey1', value: Buffer.from('a master value'), cls: 'master', grants: ['laptop'] });
  const reply = await w.call('/r/masterkey1/v1/models');
  assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [403, 'forbidden']);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 two different source addresses both pass, and the audit row has the rule id, the source and no query', async (t) => {
  const w = await relayWorld(t);
  assert.equal((await w.call(`${PATH}/v1/items?limit=7`, { ip: '198.51.100.1' })).status, 200);
  assert.equal((await w.call(`${PATH}/v1/items?limit=7`, { ip: '2001:db8::5' })).status, 200);
  const rows = await settleAudit(w);
  await waitUntil(() => w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request').length === 2, 'two rows');
  const both = w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
  assert.deepEqual(both.map((r) => [r.actor, r.ref, r.detail['rule_id'], r.detail['source'], r.detail['status']]), [
    ['laptop', 'adminkey1', 'items-list', '198.51.100.1', 200],
    ['laptop', 'adminkey1', 'items-list', '2001:db8::5', 200],
  ]);
  assert.ok(rows.length >= 1);
  assert.equal(JSON.stringify(both).includes('limit'), false);
});

test('KBOX-13 a hung upstream gives 504 upstream_timeout after 10 s; a refused connection gives 502 upstream_unreachable', async (t) => {
  const w = await relayWorld(t);
  w.hung.add('api.pathplat.example');
  const pending = w.call(`${PATH}/v1/models`);
  await waitUntil(() => w.lend.clock.pendingTimers > 0, 'the connect timer');
  w.lend.clock.advance(10_000);
  const reply = await pending;
  assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [504, 'upstream_timeout']);
  w.hung.clear();
  w.upstream.respond((req) => void req.socket.destroy());
  const reset = await w.call(`${PATH}/v1/models`);
  assert.deepEqual([reset.status, JSON.parse(reset.body.toString()).error.code], [502, 'upstream_unreachable']);
});

test('KBOX-13 the real streaming path end to end: a 5 MiB body and an SSE stream arrive whole', async (t) => {
  const w = await relayWorld(t);
  const line = Buffer.from('{"id":1,"object":"model","owned_by":"system"},\n');
  const big = Buffer.concat(Array.from({ length: Math.ceil((5 * 1024 * 1024) / line.length) }, () => line));
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(big.length) });
    res.end(big);
  });
  const reply = await w.call(`${PATH}/v1/models`);
  assert.deepEqual([reply.status, reply.complete, reply.body.length, reply.headers['content-length']], [200, true, big.length, String(big.length)]);
  assert.ok(reply.body.equals(big));
  const events = ['data: {"delta":"Hel"}\n\n', 'data: {"delta":"lo"}\n\n', 'data: [DONE]\n\n'];
  w.upstream.respond(async (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const event of events) {
      res.write(event);
      await new Promise((resolve) => setImmediate(resolve));
    }
    res.end();
  });
  const sse = await w.call(`${PATH}/v1/events`);
  assert.deepEqual([sse.status, sse.complete, sse.body.toString(), sse.headers['content-type']], [200, true, events.join(''), 'text/event-stream']);
});

test('KBOX-10 a /r/* request carrying Origin or Cookie is refused 403 browser_call', async (t) => {
  const w = await relayWorld(t);
  for (const headers of [{ origin: 'https://evil.example' }, { cookie: 'a=b' }]) {
    const reply = await w.call(`${PATH}/v1/models`, { headers });
    assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [403, 'browser_call']);
  }
  assert.equal((await w.call('/r/_/grants', { headers: { origin: 'https://evil.example' } })).status, 403);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-43 the relay reads the client address only from X-KB-Client-Ip: missing or malformed is 400, spoofed headers change nothing', async (t) => {
  const w = await relayWorld(t);
  for (const ip of [null, 'not-an-ip', '203.0.113.300']) assert.equal((await w.call(`${PATH}/v1/models`, { ip })).status, 400, String(ip));
  assert.equal(w.upstream.requests.length, 0);
  await w.call(`${PATH}/v1/models`, { ip: '203.0.113.20', headers: { 'x-forwarded-for': '198.51.100.1', 'x-real-ip': '198.51.100.2', forwarded: 'for=198.51.100.3' } });
  await waitUntil(() => w.lend.core.audit.read(0).entries.some((r) => r.action === 'relay.request' && r.detail['status'] === 200), 'the row');
  const row = w.lend.core.audit.read(0).entries.find((r) => r.action === 'relay.request' && r.detail['status'] === 200);
  assert.equal(row?.detail['source'], '203.0.113.20');
});

test('KBOX-43 the first relay use of a pass from a new network writes one token.new_network event; the same /24 writes none', async (t) => {
  const w = await relayWorld(t);
  await w.call(`${PATH}/v1/models`, { ip: '198.51.100.10' });
  await w.call(`${PATH}/v1/models`, { ip: '198.51.100.200' });
  await w.call(`${PATH}/v1/models`, { ip: '198.51.101.1' });
  const networks = w.lend.core.events.after(0).filter((e) => e.kind === 'token.new_network').map((e) => e.data['network']);
  assert.deepEqual(networks, ['198.51.100.0/24', '198.51.101.0/24']);
});

test('KBOX-13 the pass: absent or malformed is 401 bad_token, two headers that disagree are 400, an unknown pass is 401', async (t) => {
  const w = await relayWorld(t);
  const code = async (options: CallOptions): Promise<[number, string]> => {
    const reply = await w.call(`${PATH}/v1/models`, options);
    return [reply.status, JSON.parse(reply.body.toString()).error.code];
  };
  assert.deepEqual(await code({ pass: null }), [401, 'bad_token']);
  assert.deepEqual(await code({ pass: 'kbt_short' }), [401, 'bad_token']);
  assert.deepEqual(await code({ pass: `kbt_${'B'.repeat(43)}` }), [401, 'bad_token']);
  assert.deepEqual(await code({ headers: { apikey: `kbt_${'C'.repeat(43)}` } }), [400, 'bad_request']);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 a pass for a key without a grant is 403 forbidden, and an unlisted operation is 403 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  w.lend.enrol('desktop');
  w.lend.addKey({ keyref: 'otherkey01', value: Buffer.from('other value'), grants: ['desktop'] });
  assert.equal((await w.call('/r/otherkey01/v1/models')).status, 403);
  assert.equal((await w.call(`${PATH}/v1/organization/admin_api_keys`, { method: 'POST' })).status, 403);
  assert.equal((await w.call(`${PATH}/v1/models`, { method: 'DELETE' })).status, 403);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-50 a request whose pass core did not confirm writes no audit row, whatever it carries: the journal gets a fixed code per refusal and nothing the caller chose', async (t) => {
  const w = await relayWorld(t);
  const attacker = { 'x-agent': 'evil-agent', 'x-project': 'evil-project' };
  const unknown = `kbt_${'B'.repeat(43)}`;
  const calls: [string, CallOptions][] = [
    [`${PATH}/v1/models`, { pass: null, headers: attacker }],
    [`${PATH}/v1/models`, { pass: unknown, headers: attacker }],
    [`${PATH}/v1/models`, { headers: { ...attacker, apikey: `kbt_${'C'.repeat(43)}` } }],
    [`/r/evilkeyref0/v1/models`, { pass: unknown, headers: attacker }],
    ['/not/a/relay/path', { headers: attacker }],
    [`${PATH}/v1/a%2Fb`, { pass: unknown, headers: attacker }],
    [`${PATH}/v1/models`, { ip: null, headers: attacker }],
    [`${PATH}/v1/models`, { headers: { ...attacker, origin: 'https://evil.example' } }],
  ];
  for (const [path, options] of calls) assert.ok((await w.call(path, options)).status >= 400, path);
  assert.equal((await w.call(`${PATH}/v1/organization/admin_api_keys`, { method: 'POST', headers: attacker })).status, 403, 'control: a confirmed pass is refused and audited');
  await w.stop();
  const rows = w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
  assert.deepEqual(rows.map((r) => [r.actor, r.detail['agent'], r.detail['project'], r.detail['code']]), [['laptop', 'evil-agent', 'evil-project', 'forbidden']], 'only the confirmed pass is audited');
  assert.deepEqual([...w.journal].sort(), ['pre_auth_bad_path', 'pre_auth_bad_request', 'pre_auth_bad_request', 'pre_auth_bad_token', 'pre_auth_bad_token', 'pre_auth_bad_token', 'pre_auth_browser_call', 'pre_auth_not_found']);
  w.canary.assertAbsent({ journal: w.journal.join('\n') });
  assert.ok(!w.journal.join('\n').includes('evil'));
});

// ---------------------------------------------------------------- KBOX-57: a project-host key goes to its stored project's host only

const STORED_HOST = 'abcdefgh.projplat.example';
const PROJECT_PATH = '/r/projkey01/rest/v1/things';

/** The relay over the project-host fixture, with key `projkey01` stored at project `abcdefgh` and naming `zyxwvuts` in its projects (`at` null stores no rotation record). */
async function projectRelay(t: TestContext, at: { readonly project?: string } | null = { project: 'abcdefgh' }): Promise<RelayWorld> {
  const w = await relayWorld(t, { registry: PROJECT_REGISTRY });
  w.lend.addKey({ keyref: 'projkey01', value: w.value, platform: 'projplat', grants: ['laptop'], projects: ['zyxwvuts'], ...(at === null ? {} : { at }) });
  return w;
}

const lendRefusals = (w: RelayWorld) => w.lend.core.audit.read(0).entries.filter((r) => r.action === 'lend.refused').map((r) => [r.ref, r.detail['op'], r.detail['code']]);

test('KBOX-57 negative control: a project-host key whose projects name another valid ref is relayed to its stored project host only', async (t) => {
  const w = await projectRelay(t);
  assert.equal((await w.call(PROJECT_PATH)).status, 200);
  assert.deepEqual(w.connects, [STORED_HOST]);
  assert.deepEqual(w.upstream.requests.map((r) => [r.method, r.url, r.headers['host']]), [['GET', '/rest/v1/things', STORED_HOST]]);
});

test('KBOX-13 a request path or headers naming another ref change nothing: the call still goes to the stored project host, or is 403 with no upstream call', async (t) => {
  const w = await projectRelay(t);
  const other = 'zyxwvuts.projplat.example';
  const headers = { host: other, 'x-project': 'zyxwvuts', 'x-forwarded-host': other, forwarded: `host=${other}` };
  assert.equal((await w.call(PROJECT_PATH, { headers })).status, 200);
  assert.equal((await w.call(`/r/projkey01/${other}/rest/v1/things`)).status, 403);
  assert.deepEqual(w.connects, [STORED_HOST]);
  assert.deepEqual(w.upstream.requests.map((r) => r.headers['host']), [STORED_HOST]);
});

test('KBOX-57 a project-host key with no stored project is 403 forbidden with no lend and no upstream call, audited location_mismatch', async (t) => {
  const w = await projectRelay(t, null);
  const reply = await w.call(PROJECT_PATH);
  assert.deepEqual([reply.status, JSON.parse(reply.body.toString()).error.code], [403, 'forbidden']);
  const rows = await settleAudit(w);
  assert.deepEqual(rows.map((r) => [r.ref, r.detail['status'], r.detail['code']]), [['projkey01', 403, 'forbidden']]);
  assert.deepEqual(lendRefusals(w), [['projkey01', 'resolve', 'location_mismatch']]);
  assert.deepEqual([w.connects, w.upstream.requests.length], [[], 0]);
});

test('KBOX-13 a stored project that is not a ref of the profile (the relay re-checks its shape) is 403 with no upstream call', async (t) => {
  for (const project of ['abc', 'ABCDEFGH', 'abcdefgh.evil', 'abcdefghi']) {
    const w = await projectRelay(t, { project });
    const reply = await w.call(PROJECT_PATH);
    assert.equal(reply.status, 403, project);
    assert.deepEqual([w.connects, w.upstream.requests.length], [[], 0], project);
  }
});
