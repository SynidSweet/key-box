// KBOX-29: wire conventions of every machine-API route. KBOX-10 and KBOX-43 are tested here at route level too.
import assert from 'node:assert/strict';
import { statSync } from 'node:fs';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { TokenStore } from '../src/ports/meta.ts';
import { ApiError } from '../src/pure/errors.ts';
import type { ErrorCode } from '../src/pure/errors.ts';
import { NAME, int, oneOf, text } from '../src/pure/schemas.ts';
import { route } from '../src/shell/http.ts';
import type { Route } from '../src/shell/http.ts';
import { canary, startCore } from './kit/index.ts';
import type { RunningCore } from './kit/index.ts';

/** The fixed texts, written out here so a change of wording is a change of this test. */
const TEXT: Record<ErrorCode, string> = {
  bad_request: 'The request could not be understood.',
  browser_call: 'Browser calls are not accepted.',
  unauthorized: 'A valid token is required.',
  forbidden: 'This token may not do that.',
  not_found: 'There is nothing here.',
  slot_taken: 'That slot is already taken.',
  conflict: 'That conflicts with the current state.',
  too_large: 'The request body is too large.',
  unsupported_media: 'The request body must be application/json.',
  rejected: 'The value did not pass its checks.',
  unavailable: 'A part of the box is not available.',
  internal: 'Something went wrong inside the box.',
};
const STATUS: Record<ErrorCode, number> = {
  bad_request: 400,
  browser_call: 403,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  slot_taken: 409,
  conflict: 409,
  too_large: 413,
  unsupported_media: 415,
  rejected: 422,
  unavailable: 503,
  internal: 500,
};

const KINDS = ['slot_taken', 'conflict', 'rejected', 'unavailable', 'internal', 'plain_crash'] as const;
const probe = { changes: 0, crashText: 'crash text' };

const testRoutes = (): Route[] => [
  route({
    method: 'POST',
    path: '/api/test/echo',
    surface: 'api',
    scope: 'control',
    body: { name: text(NAME), count: int(0, 10) },
    handle: ({ body }) => {
      probe.changes += 1;
      return { json: { name: body.name, count: body.count } };
    },
  }),
  route({
    method: 'GET',
    path: '/api/test/throw',
    surface: 'api',
    scope: 'control',
    query: { kind: oneOf(...KINDS) },
    handle: ({ query }) => {
      switch (query.kind) {
        case 'slot_taken':
          throw new ApiError('slot_taken');
        case 'conflict':
          throw new ApiError('conflict', 'epoch_changed');
        case 'rejected':
          throw new ApiError('rejected', 'too_short');
        case 'unavailable':
          throw new ApiError('unavailable');
        case 'internal':
          throw new ApiError('internal');
        case 'plain_crash':
          throw new Error(probe.crashText);
      }
    },
  }),
  route({ method: 'GET', path: '/api/test/relay-only', surface: 'api', scope: 'relay', handle: () => ({ json: { ok: true } }) }),
  route({ method: 'GET', path: '/phone/ping', surface: 'phone', handle: () => ({ json: { pong: true } }) }),
];

async function boxWithTokens(t: TestContext, options: { tokenStore?: (real: TokenStore) => TokenStore } = {}): Promise<{ box: RunningCore; control: string; relay: string }> {
  probe.changes = 0;
  const box = await startCore(t, { extraRoutes: testRoutes(), ...options });
  return { box, control: box.enrol('ctl-1', 'control'), relay: box.enrol('rly-1', 'relay') };
}

const expectError = (reply: { status: number; json(): unknown }, code: ErrorCode, detail?: string): void => {
  const base = { code, message: TEXT[code] };
  assert.equal(reply.status, STATUS[code]);
  assert.deepEqual(reply.json(), { error: detail === undefined ? base : { ...base, detail: { code: detail } } });
};

const json = (value: unknown): string => JSON.stringify(value);

test('KBOX-29 each error code is produced by a request that should get it, with its fixed text and status', async (t) => {
  const { box, control, relay } = await boxWithTokens(t);
  const revoked = box.enrol('old-1', 'control');
  box.meta.revokeMachine('old-1');
  const ok = { token: control };

  expectError(await box.call('/api/test/echo', { ...ok, method: 'POST', json: true, body: json({ name: 'a', count: 1, extra: 1 }) }), 'bad_request');
  expectError(await box.call('/api/meta', { ...ok, headers: { origin: 'https://evil.example' } }), 'browser_call');
  expectError(await box.call('/api/meta', { ...ok, headers: { cookie: 'a=b' } }), 'browser_call');
  expectError(await box.call('/api/meta'), 'unauthorized');
  expectError(await box.call('/api/meta', { token: revoked }), 'unauthorized');
  expectError(await box.call('/api/meta', { headers: { authorization: 'Bearer nope' } }), 'unauthorized');
  expectError(await box.call('/api/meta', { token: relay }), 'forbidden');
  expectError(await box.call('/api/test/relay-only', ok), 'forbidden');
  expectError(await box.call('/phone/ping', { ...ok }), 'forbidden');
  expectError(await box.call('/api/nothing-here', ok), 'not_found');
  expectError(await box.call('/nothing-here'), 'not_found');
  expectError(await box.call('/api/meta', { ...ok, method: 'DELETE' }), 'not_found');
  expectError(await box.call('/api/test/throw?kind=slot_taken', ok), 'slot_taken');
  expectError(await box.call('/api/test/throw?kind=conflict', ok), 'conflict', 'epoch_changed');
  expectError(await box.call('/api/test/echo', { ...ok, method: 'POST', json: true, body: ' '.repeat(65_537) }), 'too_large');
  expectError(await box.call('/api/test/echo', { ...ok, method: 'POST', body: json({ name: 'a', count: 1 }), headers: { 'content-type': 'text/plain' } }), 'unsupported_media');
  expectError(await box.call('/api/test/throw?kind=rejected', ok), 'rejected', 'too_short');
  expectError(await box.call('/api/test/throw?kind=unavailable', ok), 'unavailable');
  expectError(await box.call('/api/test/throw?kind=internal', ok), 'internal');
  expectError(await box.call('/api/test/throw?kind=plain_crash', ok), 'internal');
  assert.equal(probe.changes, 0);
  assert.equal((await box.call('/phone/ping')).json() !== undefined, true);
});

test('KBOX-29 every response carries no-store, the API version and a request id, and the id is in the audit log', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const replies = [await box.call('/api/meta', { token: control }), await box.call('/api/meta'), await box.call('/api/nothing', { token: control }), await box.call('/phone/ping')];
  const ids = replies.map((r) => r.headers['kb-request-id']);
  for (const reply of replies) {
    assert.equal(reply.headers['cache-control'], 'no-store');
    assert.equal(reply.headers['kb-api-version'], '1');
    assert.match(reply.headers['content-type'] ?? '', /^application\/json(; charset=utf-8)?$/);
    assert.match(reply.headers['kb-request-id'] ?? '', /^req_[A-Za-z0-9_-]{12}$/);
  }
  assert.equal(new Set(ids).size, ids.length);
  const rows = box.audit.read(0).entries;
  assert.deepEqual(rows.map((r) => r.detail['request_id']), ids);
  assert.deepEqual(rows.map((r) => [r.actor, r.action, r.ref, r.detail['status'], r.detail['code']]), [
    ['ctl-1', 'api.request', '/api/meta', 200, undefined],
    ['box', 'api.request', 'unmatched', 401, 'unauthorized'],
    ['ctl-1', 'api.request', 'unmatched', 404, 'not_found'],
    ['box', 'api.request', '/phone/ping', 200, undefined],
  ]);
  assert.deepEqual(box.audit.verifyChain(), { ok: true, rows: 4 });
});

test('KBOX-29 an unknown member, a wrong type, a missing member, a non-object, a BOM, bad UTF-8 and an empty body are refused with no state change', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const post = (body: string | Uint8Array, headers: Record<string, string> = {}) => box.call('/api/test/echo', { token: control, method: 'POST', json: true, body, headers });
  const good = json({ name: 'a', count: 1 });
  const bad: (string | Uint8Array)[] = [
    json({ name: 'a', count: 1, extra: true }),
    json({ name: 'a', count: '1' }),
    json({ name: 'a', count: 1.5 }),
    json({ name: 'a', count: 11 }),
    json({ name: 'a' }),
    json({ name: 5, count: 1 }),
    json({ name: 'has space', count: 1 }),
    json({ name: 'a', count: null }),
    json(['a']),
    json(null),
    json('a'),
    '',
    '{"name":"a","count":1} trailing',
    '{"name":"a","count":1',
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(good)]),
    Buffer.concat([Buffer.from('{"name":"a\xff","count":1}', 'latin1')]),
    Buffer.from([0xc3, 0x28]),
    Buffer.from([0xff, 0xfe]),
    '{"__proto__":{"x":1},"name":"a","count":1}',
  ];
  for (const body of bad) {
    const reply = await post(body);
    assert.equal(reply.status, 400, `${body.toString().slice(0, 40)}`);
    assert.deepEqual(reply.json(), { error: { code: 'bad_request', message: TEXT.bad_request } });
  }
  assert.equal(probe.changes, 0);
  const accepted = await post(good);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.json(), { name: 'a', count: 1 });
  assert.equal(probe.changes, 1);
});

test('KBOX-29 a body of 64 KiB is read and one byte more is refused, with a length header or chunked', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const padded = (size: number): string => `${json({ name: 'a', count: 1 })}${' '.repeat(size - json({ name: 'a', count: 1 }).length)}`;
  const send = (body: string, headers: Record<string, string> = {}) => box.call('/api/test/echo', { token: control, method: 'POST', json: true, body, headers });
  assert.equal((await send(padded(65_536))).status, 200);
  expectError(await send(padded(65_537)), 'too_large');
  expectError(await send(padded(65_537), { 'transfer-encoding': 'chunked' }), 'too_large');
  expectError(await send(padded(200_000)), 'too_large');
  assert.equal(probe.changes, 1);
  assert.equal((await send(padded(65_536))).status, 200, 'the server still answers after refusing a big body');
});

test('KBOX-29 a query string with an unknown member, a repeated member or a wrong shape is a bad_request', async (t) => {
  const { box, control } = await boxWithTokens(t);
  for (const query of ['kind=internal&extra=1', 'kind=internal&kind=conflict', 'kind=other', 'kind=', '', 'kind=%ff']) {
    expectError(await box.call(`/api/test/throw?${query}`, { token: control }), 'bad_request');
  }
});

test('KBOX-29 an error body never contains text placed in the request: body, query, headers, path, content type or token', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const c = canary(32);
  const raw = Buffer.from(c.bytes).toString('base64url');
  const replies = [
    await box.call('/api/test/echo', { token: control, method: 'POST', json: true, body: json({ name: 'a', count: 1, [raw]: raw }) }),
    await box.call('/api/test/echo', { token: control, method: 'POST', json: true, body: json({ name: `${raw} with space`, count: 1 }) }),
    await box.call('/api/test/echo', { token: control, method: 'POST', body: '{}', headers: { 'content-type': `text/${raw}` } }),
    await box.call(`/api/test/throw?kind=${raw}`, { token: control }),
    await box.call(`/api/${raw}`, { token: control }),
    await box.call(`/${raw}`),
    await box.call('/api/meta', { headers: { authorization: `Bearer ${raw}` } }),
    await box.call('/api/meta', { headers: { authorization: `Bearer kbt_${raw}`.slice(0, 47) } }),
    await box.call('/api/meta', { token: control, ip: raw.slice(0, 40) }),
    await box.call('/api/meta', { token: control, headers: { origin: raw } }),
    await box.call('/api/meta', { token: control, headers: { cookie: raw } }),
    await box.call('/phone/ping', { headers: { authorization: `Bearer ${raw}` } }),
  ];
  c.assertAbsent({ bodies: replies.map((r) => r.body).join('\n'), headers: replies.map((r) => JSON.stringify(r.headers)).join('\n') });
  assert.ok(replies.every((r) => r.status >= 400));
});

test('KBOX-10 a request with an Origin or Cookie header is refused 403 browser_call on every /api route, unknown ones and unauthenticated ones too', async (t) => {
  const { box, control, relay } = await boxWithTokens(t);
  const paths = ['/api/meta', '/api/audit', '/api/events', '/api/test/echo', '/api/test/throw', '/api/test/relay-only', '/api/unknown', '/api'];
  for (const path of paths) {
    for (const headers of [{ origin: 'https://app.example' }, { cookie: 'session=1' }, { origin: 'null' }, { origin: '' }]) {
      for (const token of [control, relay, undefined]) {
        for (const method of ['GET', 'POST']) {
          const reply = await box.call(path, { method, headers, ...(token === undefined ? {} : { token }) });
          expectError(reply, 'browser_call');
        }
      }
    }
  }
  assert.equal(probe.changes, 0);
  assert.equal(box.meta.snapshot().machines.every((m) => m.last_network === null), true, 'a refused browser call is not a use of the token');
});

test('KBOX-10 a bearer token on a phone route is refused, and a phone route without one works', async (t) => {
  const { box, control } = await boxWithTokens(t);
  expectError(await box.call('/phone/ping', { token: control }), 'forbidden');
  expectError(await box.call('/phone/ping', { headers: { authorization: 'Basic abc' } }), 'forbidden');
  assert.equal((await box.call('/phone/ping')).status, 200);
});

test('KBOX-10 a malformed token (length, alphabet, prefix) gets 401 with no database lookup, and a well-formed unknown one gets 401 after exactly one', async (t) => {
  let lookups = 0;
  const { box, control } = await boxWithTokens(t, {
    tokenStore: (real) => ({
      tokens: () => {
        lookups += 1;
        return real.tokens();
      },
      recordUse: (label, network) => real.recordUse(label, network),
    }),
  });
  const A = 'A'.repeat(43);
  for (const header of [undefined, 'Bearer', `Bearer kbt_${'A'.repeat(42)}`, `Bearer kbt_${A}A`, `Bearer kbt_${'A'.repeat(42)}+`, `Bearer kbx_${A}`, `Bearer ${A}`, `Basic kbt_${A}`, `Bearer kbt_${A} extra`]) {
    const reply = await box.call('/api/meta', header === undefined ? {} : { headers: { authorization: header } });
    expectError(reply, 'unauthorized');
  }
  assert.equal(lookups, 0);
  expectError(await box.call('/api/meta', { token: `kbt_${A}` }), 'unauthorized');
  assert.equal(lookups, 1);
  assert.equal((await box.call('/api/meta', { token: control })).status, 200);
  assert.equal(lookups, 2);
});

test('KBOX-43 the audit row\'s source address is the X-KB-Client-Ip header, whatever X-Forwarded-For, X-Real-IP and Forwarded say', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const spoof = { 'x-forwarded-for': '198.51.100.1', 'x-real-ip': '198.51.100.2', forwarded: 'for=198.51.100.3' };
  const first = await box.call('/api/meta', { token: control, ip: '203.0.113.50', headers: spoof });
  const second = await box.call('/api/meta', { token: control, ip: '2001:db8:7::9', headers: spoof });
  assert.deepEqual([first.status, second.status], [200, 200]);
  assert.deepEqual(box.audit.read(0).entries.map((r) => r.detail['source']), ['203.0.113.50', '2001:db8:7::9']);
  assert.equal(box.meta.snapshot().machines.find((m) => m.label === 'ctl-1')?.last_network, '2001:db8:7::/48');
  assert.deepEqual(box.events.after(0).filter((e) => e.kind === 'token.new_network').map((e) => e.data['network']), ['203.0.113.0/24', '2001:db8:7::/48']);
});

test('KBOX-43 a missing or malformed X-KB-Client-Ip is bad_request, with a good token and without one, and nothing is used', async (t) => {
  const { box, control } = await boxWithTokens(t);
  for (const ip of [null, '', 'not-an-ip', '203.0.113.256', '203.0.113.9, 198.51.100.1', '[::1]', '203.0.113.9:80']) {
    expectError(await box.call('/api/meta', { token: control, ip }), 'bad_request');
    expectError(await box.call('/api/meta', { ip }), 'bad_request');
    expectError(await box.call('/phone/ping', { ip }), 'bad_request');
  }
  expectError(await box.call('/api/meta', { token: control, headers: { 'x-forwarded-for': '203.0.113.9' }, ip: null }), 'bad_request');
  assert.equal(box.events.after(0).some((e) => e.kind === 'token.new_network'), false);
});

test('KBOX-43 the first use of a token from a new network writes one token.new_network event, a second from the same /24 none, and the next /24 one', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const networks = (): unknown[] => box.events.after(0).filter((e) => e.kind === 'token.new_network').map((e) => e.data['network']);
  await box.call('/api/meta', { token: control, ip: '203.0.113.1' });
  await box.call('/api/meta', { token: control, ip: '203.0.113.1' });
  await box.call('/api/meta', { token: control, ip: '203.0.113.255' });
  assert.deepEqual(networks(), ['203.0.113.0/24']);
  await box.call('/api/meta', { token: control, ip: '203.0.114.0' });
  assert.deepEqual(networks(), ['203.0.113.0/24', '203.0.114.0/24']);
  await box.call('/api/meta', { token: control, ip: '2001:db8:1:ffff::1' });
  await box.call('/api/meta', { token: control, ip: '2001:db8:1::5' });
  await box.call('/api/meta', { token: control, ip: '2001:db8:2::5' });
  assert.deepEqual(networks(), ['203.0.113.0/24', '203.0.114.0/24', '2001:db8:1::/48', '2001:db8:2::/48']);
});

test('KBOX-29 an internal failure answers the fixed text and puts only a cause code in the audit log', async (t) => {
  const { box, control } = await boxWithTokens(t);
  const c = canary();
  probe.crashText = `crash with ${Buffer.from(c.bytes).toString('latin1')} and ${Buffer.from(c.bytes).toString('base64')}`;
  const reply = await box.call('/api/test/throw?kind=plain_crash', { token: control });
  expectError(reply, 'internal');
  const row = box.audit.read(0).entries[0];
  assert.deepEqual([row?.detail['status'], row?.detail['code'], row?.detail['cause']], [500, 'internal', 'unhandled']);
  c.assertAbsent({ body: reply.body, audit: JSON.stringify(box.audit.read(0).entries), journal: box.journal.join('\n') });
  probe.crashText = 'crash text';
});

test('KBOX-45 the socket the frame listens on is 0660 whatever the umask of the process, so only its owner and group can connect', async (t) => {
  const { box } = await boxWithTokens(t);
  assert.equal(statSync(box.socket).mode & 0o777, 0o660);
});
