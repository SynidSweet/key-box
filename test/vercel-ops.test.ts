// KBOX-26: the three Vercel operations (createProject, setDomain, setTeamSetting): the exact request each makes with the master, the typed
// parameters that may reach a path or a body, the four outcome names, the phone approval of the two that need it, and a crash after `approved`.
// The adapter runs for real over a scripted `AdapterHttp` (api.vercel.com is not ours: no real request is made).
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { AdapterHttp, HttpRequest, HttpResponse } from '../src/ports/http.ts';
import { HttpTransportError } from '../src/ports/http.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { Action } from '../src/pure/actions.ts';
import { createVercelEntry } from '../src/platforms/vercel/index.ts';
import { startCore } from '../src/main-core.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { openApproveCore } from '../src/shell/approve-core.ts';
import { openCore } from '../src/shell/core.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import type { StoredApproval } from '../src/shell/approvals.ts';
import type { Route } from '../src/shell/http.ts';
import type { MasterRow, PlatformSource } from '../src/shell/rotation-ports.ts';
import { createVercelOps, vercelRoutes } from '../src/shell/vercel-routes.ts';
import { FakeClock, TimedClock, drive, lent, seededRandom, tempDir } from './kit/index.ts';
import { DOMAIN, WORDLIST, approveWorld } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';

const MASTER_TEXT = `vcp_KboxTestFakeMaster${'M'.repeat(20)}`;
const TEAM = 'team_abc123';
const masterRow = (items: readonly string[] = [`team:${TEAM}`], text = MASTER_TEXT): MasterRow => ({ at: {}, items, value: lent(Buffer.from(text), 'master:1') });

interface Answer {
  readonly status: number;
  readonly json?: unknown;
  /** Instead of an answer: the transport fails with this code. */
  readonly transport?: 'unreachable' | 'timeout';
  /** An answer whose body is not JSON. */
  readonly text?: string;
}
interface Sent {
  readonly method: string;
  readonly target: string;
  readonly bearer: string | undefined;
  readonly body: unknown;
}

/** An `AdapterHttp` that records each request and answers from `answer`. */
function scripted(answer: (sent: Sent) => Answer): AdapterHttp & { readonly sent: Sent[] } {
  const sent: Sent[] = [];
  return {
    sent,
    request(req: HttpRequest): Promise<HttpResponse> {
      const url = new URL(req.url);
      const text = req.body === undefined ? '' : Buffer.from(req.body).toString('utf8');
      const record: Sent = { method: req.method, target: `${url.pathname}${url.search}`, bearer: req.headers?.['authorization'], body: text === '' ? undefined : (JSON.parse(text) as unknown) };
      sent.push(record);
      const reply = answer(record);
      if (reply.transport !== undefined) return Promise.reject(new HttpTransportError(reply.transport));
      const body = Buffer.from(reply.text ?? JSON.stringify(reply.json ?? {}));
      return Promise.resolve({ status: reply.status, headers: {}, body: Uint8Array.from(body) });
    },
  };
}

const bearer = `Bearer ${MASTER_TEXT}`;

interface Ops {
  readonly http: ReturnType<typeof scripted>;
  readonly entry: PlatformEntry;
  readonly rows: MasterRow[];
  readonly source: Pick<PlatformSource, 'masters'>;
  readonly ops: ReturnType<typeof createVercelOps>;
}

function opsWith(answer: (sent: Sent) => Answer = () => ({ status: 200 }), rows: MasterRow[] = [masterRow()]): Ops {
  const http = scripted(answer);
  const entry = createVercelEntry({ http, clock: new FakeClock(0), pause: () => Promise.resolve() });
  const source = { masters: () => rows };
  return { http, entry, rows, source, ops: createVercelOps({ registry: [entry], source, audit: { append: () => undefined }, clock: new FakeClock(0) }) };
}

const operations = (entry: PlatformEntry) => {
  assert.ok(entry.operations, 'the vercel entry has operations');
  return entry.operations;
};
const master = (items: readonly string[] = [`team:${TEAM}`]) => ({ value: masterRow(items).value, items });

// -------------------------------------------------------------------------------------------------- the exact request of each operation

test('KBOX-26 setDomain add, remove and move each send exactly one request: the method, the path with the project and domain, teamId, the master as bearer, and a body with only its member', async () => {
  const x = opsWith();
  const o = operations(x.entry);
  assert.deepEqual(await o.setDomain(master(), { project: 'shop', op: 'add', domain: 'shop.example.com' }), { ok: true });
  assert.deepEqual(await o.setDomain(master(), { project: 'shop', op: 'remove', domain: 'shop.example.com' }), { ok: true });
  assert.deepEqual(await o.setDomain(master(), { project: 'shop', op: 'move', domain: 'shop.example.com', toProject: 'shop-2' }), { ok: true });
  assert.deepEqual(x.http.sent, [
    { method: 'POST', target: `/v10/projects/shop/domains?teamId=${TEAM}`, bearer, body: { name: 'shop.example.com' } },
    { method: 'DELETE', target: `/v9/projects/shop/domains/shop.example.com?teamId=${TEAM}`, bearer, body: undefined },
    { method: 'POST', target: `/v1/projects/shop/domains/shop.example.com/move?teamId=${TEAM}`, bearer, body: { projectId: 'shop-2' } },
  ]);
});

const SETTING_BODIES: readonly (readonly [string, string, unknown])[] = [
  ['enablePreviewFeedback', 'true', { enablePreviewFeedback: 'on' }],
  ['enablePreviewFeedback', 'false', { enablePreviewFeedback: 'off' }],
  ['enableProductionFeedback', 'true', { enableProductionFeedback: 'on' }],
  ['hideIpAddresses', 'true', { hideIpAddresses: true }],
  ['hideIpAddressesInLogDrains', 'false', { hideIpAddressesInLogDrains: false }],
  ['remoteCaching.enabled', 'true', { remoteCaching: { enabled: true } }],
  ['previewDeploymentSuffix', 'preview.example.com', { previewDeploymentSuffix: 'preview.example.com' }],
  ['description', 'Our shop team', { description: 'Our shop team' }],
];

for (const [setting, value, body] of SETTING_BODIES) {
  test(`KBOX-26 setTeamSetting ${setting}=${value} sends PATCH /v2/teams/{teamId} with the master and exactly one member`, async () => {
    const x = opsWith();
    assert.deepEqual(await operations(x.entry).setTeamSetting(master(), setting, value), { ok: true });
    assert.deepEqual(x.http.sent, [{ method: 'PATCH', target: `/v2/teams/${TEAM}`, bearer, body }]);
  });
}

test('KBOX-26 createProject sends POST /v11/projects with only the name and answers the project id and name and nothing else, however much Vercel says', async () => {
  const x = opsWith(() => ({ status: 200, json: { id: 'prj_1', name: 'shop', accountId: 'acct', link: { token: 'x' }, env: [{ value: 'secret' }] } }));
  const created = await operations(x.entry).createProject(master(), 'shop');
  assert.deepEqual(created, { ok: true, projectId: 'prj_1', name: 'shop' });
  assert.deepEqual(x.http.sent, [{ method: 'POST', target: `/v11/projects?teamId=${TEAM}`, bearer, body: { name: 'shop' } }]);
});

test('KBOX-26 a master with no team item (a personal account) sends no teamId; a team setting then has no team to change and sends nothing', async () => {
  const x = opsWith();
  const o = operations(x.entry);
  await o.setDomain(master([]), { project: 'shop', op: 'add', domain: 'shop.example.com' });
  assert.equal(x.http.sent[0]?.target, '/v10/projects/shop/domains');
  assert.deepEqual(await o.setTeamSetting(master([]), 'hideIpAddresses', 'true'), { ok: false, code: 'vercel_not_found' });
  assert.equal(x.http.sent.length, 1);
});

// -------------------------------------------------------------------------------------------------- typed parameters

test('KBOX-26 a setting outside the list, and a bad value of a listed one, is refused by the adapter before any request', async () => {
  const x = opsWith();
  const o = operations(x.entry);
  const outside = ['sensitiveEnvironmentVariablePolicy', 'requireVerifiedCommits', 'disableRepositoryDispatchEvents', 'defaultDeploymentProtection', 'deploymentPolicy', 'members', 'billing', 'name', 'slug', '__proto__', 'constructor', 'description ', 'Description', 'remoteCaching', 'remoteCaching.enabled.x', ''];
  for (const setting of outside) {
    assert.deepEqual(await o.setTeamSetting(master(), setting, 'true'), { ok: false, code: 'setting_not_listed' }, JSON.stringify(setting));
    assert.equal(x.entry.vetSetting?.(setting, 'true'), 'setting_not_listed', JSON.stringify(setting));
  }
  const bad: readonly (readonly [string, string])[] = [
    ['hideIpAddresses', 'yes'], ['hideIpAddresses', 'TRUE'], ['hideIpAddresses', ''], ['enablePreviewFeedback', 'on'], ['remoteCaching.enabled', '1'],
    ['previewDeploymentSuffix', 'not a domain'], ['previewDeploymentSuffix', 'UPPER.example.com'], ['previewDeploymentSuffix', ''],
    ['description', ''], ['description', 'x'.repeat(141)], ['description', 'tab\there'], ['description', 'café'],
  ];
  for (const [setting, value] of bad) {
    assert.deepEqual(await o.setTeamSetting(master(), setting, value), { ok: false, code: 'bad_value' }, `${setting}=${JSON.stringify(value)}`);
    assert.equal(x.entry.vetSetting?.(setting, value), 'bad_value');
  }
  assert.equal(x.entry.vetSetting?.('description', 'x'.repeat(140)), 'ok', 'the longest description (at the bound)');
  assert.deepEqual(x.http.sent, [], 'no request for any of them');
});

test('KBOX-26 a project or domain that is not a plain name never reaches a path: every piece is encoded or refused, and no request carries a slash from it', async () => {
  const x = opsWith();
  const o = operations(x.entry);
  const result = await o.setDomain(master(), { project: '..', op: 'add', domain: 'shop.example.com' });
  assert.equal(result.ok, false);
  assert.equal(x.http.sent.length, 0, '".." sends nothing');
  await o.setDomain(master(), { project: 'a/b', op: 'add', domain: 'shop.example.com' });
  await o.setDomain(master(), { project: 'a:b', op: 'remove', domain: 'x/../y' });
  for (const sent of x.http.sent) assert.doesNotMatch(sent.target.split('?')[0] ?? '', /\/b\/|\/\.\.(\/|$)|a:b/, sent.target);
  assert.equal(x.http.sent[0]?.target, `/v10/projects/a%2Fb/domains?teamId=${TEAM}`);
});

// -------------------------------------------------------------------------------------------------- outcomes

const FAILURES: readonly (readonly [string, Answer, string])[] = [
  ['404', { status: 404, json: { error: { code: 'not_found', message: 'secret' } } }, 'vercel_not_found'],
  ['409', { status: 409, json: { error: { code: 'domain_already_in_use' } } }, 'vercel_conflict'],
  ['403', { status: 403, json: { error: { code: 'forbidden', message: `quotes ${MASTER_TEXT}` } } }, 'vercel_forbidden'],
  ['401', { status: 401, json: { error: { code: 'forbidden' } } }, 'vercel_forbidden'],
  ['400', { status: 400, json: { error: { code: 'bad_request' } } }, 'vercel_conflict'],
  ['429', { status: 429, json: { error: { code: 'rate_limited' } } }, 'unreachable'],
  ['500', { status: 500, json: {} }, 'unreachable'],
  ['a transport that is down', { status: 0, transport: 'unreachable' }, 'unreachable'],
  ['a timeout', { status: 0, transport: 'timeout' }, 'unreachable'],
  ['a 200 that is not JSON', { status: 200, text: '<html>' }, 'unreachable'],
];

for (const [name, answer, code] of FAILURES) {
  test(`KBOX-26 ${name} from Vercel is the name ${code} for setDomain and for setTeamSetting, with nothing of Vercel's body`, async () => {
    const x = opsWith(() => answer);
    const o = operations(x.entry);
    const domain = await o.setDomain(master(), { project: 'shop', op: 'add', domain: 'shop.example.com' });
    const setting = await o.setTeamSetting(master(), 'hideIpAddresses', 'true');
    assert.deepEqual(domain, { ok: false, code });
    assert.deepEqual(setting, { ok: false, code });
  });
}

test('KBOX-26 createProject: an existing name (409) is conflict; any other failure, and an answer with no id, is unavailable', async () => {
  const cases: readonly (readonly [Answer, string])[] = [
    [{ status: 409, json: { error: { code: 'conflict' } } }, 'conflict'],
    [{ status: 403, json: {} }, 'unavailable'],
    [{ status: 500, json: {} }, 'unavailable'],
    [{ status: 0, transport: 'unreachable' }, 'unavailable'],
    [{ status: 200, json: { name: 'shop' } }, 'unavailable'],
    [{ status: 200, json: { id: '', name: 'shop' } }, 'unavailable'],
    [{ status: 200, text: 'nope' }, 'unavailable'],
  ];
  for (const [answer, code] of cases) {
    const x = opsWith(() => answer);
    assert.deepEqual(await operations(x.entry).createProject(master(), 'shop'), { ok: false, code }, JSON.stringify(answer));
  }
});

test('KBOX-26 the entry offers exactly three operations, by name', () => {
  const x = opsWith();
  assert.deepEqual(Object.keys(operations(x.entry)).sort(), ['createProject', 'setDomain', 'setTeamSetting']);
});

// -------------------------------------------------------------------------------------------------- core: routes, proposals, execution

const CONTROL = 'mission-control';

interface Core {
  readonly w: World;
  readonly x: Ops;
  readonly audit: () => readonly { readonly ref: string; readonly actor: string; readonly action: string; readonly detail: Readonly<Record<string, unknown>> }[];
  api(path: string, json: unknown): ReturnType<World['call']>;
}

async function core(t: Parameters<typeof approveWorld>[0], answer?: (sent: Sent) => Answer, rows?: MasterRow[]): Promise<Core> {
  const x = opsWith(answer, rows);
  let world: World | undefined;
  const live = (): World => {
    if (world === undefined) throw new RangeError('the world is not started');
    return world;
  };
  const ops = createVercelOps({ registry: [x.entry], source: x.source, audit: { append: (e) => live().parts.audit.append(e) }, clock: { now: () => live().clock.now() } });
  const routes: readonly Route[] = vercelRoutes({ ops, approvals: { propose: (input) => live().core.approvals.propose(input) }, precheck: (action) => Promise.resolve(ops.precheck(action)) });
  const w = await approveWorld(t, { vet: () => 'ok', executors: ops.executors, routes });
  world = w;
  const token = w.token(CONTROL, 'control');
  return { w, x, audit: () => w.parts.audit.read(0).entries, api: (path, json) => w.call(path, { json, token }) };
}

const errorOf = (reply: { readonly body: string }): { readonly code?: string; readonly detail?: { readonly code?: string } } => (JSON.parse(reply.body) as { error: { code?: string; detail?: { code?: string } } }).error;

test('KBOX-26 POST /api/vercel/domains and /settings open KBOX-53 proposals with the action minus kind: 201, the answer\'s members, the slot by project and operation or by setting name, a replace for the same asker', async (t) => {
  const c = await core(t);
  const first = await c.api('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' });
  assert.equal(first.status, 201, first.body);
  const body = first.json() as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), ['approval_id', 'replaced', 'revision', 'slot', 'status']);
  assert.deepEqual([body['status'], body['slot'], body['revision'], body['replaced']], ['pending', 'vercel_set_domain:shop:add', 1, false]);
  const again = (await c.api('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'other.example.com' })).json() as Record<string, unknown>;
  assert.deepEqual([again['approval_id'], again['revision'], again['replaced']], [body['approval_id'], 2, true], 'the same asker replaces in the same slot');
  const other = (await c.api('/api/vercel/domains', { project: 'shop', op: 'remove', domain: 'shop.example.com' })).json() as Record<string, unknown>;
  assert.equal(other['slot'], 'vercel_set_domain:shop:remove');
  const setting = await c.api('/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true' });
  assert.equal(setting.status, 201, setting.body);
  assert.equal((setting.json() as Record<string, unknown>)['slot'], 'vercel_set_team_setting:hideIpAddresses');
  assert.deepEqual(c.x.http.sent, [], 'a proposal sends nothing to Vercel');
});

test('KBOX-26 the proposal routes are closed: an unknown member, a kind member, a missing member and a move without to_project are 400; a to_project on add is 400', async (t) => {
  const c = await core(t);
  const bad: readonly [string, unknown][] = [
    ['/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com', extra: 1 }],
    ['/api/vercel/domains', { kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'shop.example.com' }],
    ['/api/vercel/domains', { project: 'shop', op: 'add' }],
    ['/api/vercel/domains', { project: 'shop', op: 'move', domain: 'shop.example.com' }],
    ['/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com', to_project: 'shop-2' }],
    ['/api/vercel/domains', { project: 'shop', op: 'copy', domain: 'shop.example.com' }],
    ['/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true', teamId: 'other' }],
    ['/api/vercel/settings', { kind: 'vercel_set_team_setting', setting: 'hideIpAddresses', value: 'true' }],
    ['/api/vercel/settings', { setting: 'hideIpAddresses' }],
    ['/api/vercel/projects', { name: 'shop', teamId: 'other' }],
    ['/api/vercel/projects', {}],
  ];
  for (const [path, json] of bad) assert.equal((await c.api(path, json)).status, 400, `${path} ${JSON.stringify(json)}`);
  assert.deepEqual(c.x.http.sent, []);
});

test('KBOX-26 a setting outside the list is 422 setting_not_listed and a bad value 422 bad_value at proposal, and no approval opens', async (t) => {
  const c = await core(t);
  const outside = await c.api('/api/vercel/settings', { setting: 'sensitiveEnvironmentVariablePolicy', value: 'off' });
  assert.deepEqual([outside.status, errorOf(outside).code, errorOf(outside).detail?.code], [422, 'rejected', 'setting_not_listed']);
  const bad = await c.api('/api/vercel/settings', { setting: 'hideIpAddresses', value: 'maybe' });
  assert.deepEqual([bad.status, errorOf(bad).detail?.code], [422, 'bad_value']);
  assert.deepEqual(await c.w.queue(), []);
});

test('KBOX-26 a project name with a slash, a colon or dots, and an uppercase or overlong one, is refused at proposal (project, to_project and createProject), never in a path, and opens nothing', async (t) => {
  const c = await core(t);
  const names = ['a/b', '/a', 'a:b', '..', '.', 'a/../b', 'Shop', '-shop', 'x'.repeat(101), 'sh op', 'shop\n', 'café'];
  for (const name of names) {
    for (const [path, json] of [
      ['/api/vercel/domains', { project: name, op: 'add', domain: 'shop.example.com' }],
      ['/api/vercel/domains', { project: 'shop', op: 'move', domain: 'shop.example.com', to_project: name }],
      ['/api/vercel/projects', { name }],
    ] as const) {
      const reply = await c.api(path, json);
      assert.ok(reply.status === 400 || reply.status === 422, `${path} ${JSON.stringify(name)}: ${reply.status}`);
    }
  }
  assert.deepEqual(c.x.http.sent, []);
  assert.deepEqual(await c.w.queue(), []);
  for (const name of ['shop', 'prj_fake1', 'a'.repeat(100), 'my.shop-2_x']) assert.equal((await c.api('/api/vercel/domains', { project: name, op: 'add', domain: 'shop.example.com' })).status, 201, name);
});

test('KBOX-26 with no Vercel master, createProject, /domains and /settings are 422 no_master at proposal', async (t) => {
  const c = await core(t, undefined, []);
  for (const [path, json] of [
    ['/api/vercel/projects', { name: 'shop' }],
    ['/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' }],
    ['/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true' }],
  ] as const) {
    const reply = await c.api(path, json);
    assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', 'no_master'], path);
  }
  assert.deepEqual(await c.w.queue(), []);
});

const approveFirst = async (c: Core, kind?: string): Promise<string> => {
  const item = (await c.w.queue()).find((q) => kind === undefined || q.kind === kind);
  assert.ok(item, 'one approval is waiting');
  const reply = await c.w.decide(item.approval_id, 'approve', c.w.proofFor(item));
  assert.equal(reply.status, 200, reply.body);
  return item.approval_id;
};
const executedOf = (c: Core) => c.w.parts.events.after(0).filter((e) => e.kind === 'approval.executed').map((e) => e.data);

test('KBOX-26 an approved add runs exactly once with the master and teamId, the approval is done, and the audit row names the project, operation and domain only', async (t) => {
  const c = await core(t);
  await c.api('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' });
  const id = await approveFirst(c);
  assert.deepEqual(c.x.http.sent, [{ method: 'POST', target: `/v10/projects/shop/domains?teamId=${TEAM}`, bearer, body: { name: 'shop.example.com' } }]);
  assert.deepEqual(executedOf(c), [{ approval_id: id, result: 'done', reason_code: 'ok' }]);
  assert.deepEqual(c.audit().filter((r) => r.action === 'vercel.domain_changed').map((r) => [r.ref, r.detail]), [[id, { project: 'shop', op: 'add', domain: 'shop.example.com' }]]);
});

test('KBOX-26 an approved move sends projectId from to_project; an approved team setting sends the one member, and its audit row has the value except for description', async (t) => {
  const c = await core(t);
  await c.api('/api/vercel/domains', { project: 'shop', op: 'move', domain: 'shop.example.com', to_project: 'shop-2' });
  await approveFirst(c);
  assert.deepEqual(c.x.http.sent.at(-1), { method: 'POST', target: `/v1/projects/shop/domains/shop.example.com/move?teamId=${TEAM}`, bearer, body: { projectId: 'shop-2' } });
  assert.deepEqual(c.audit().filter((r) => r.action === 'vercel.domain_changed').map((r) => r.detail), [{ project: 'shop', op: 'move', domain: 'shop.example.com' }]);

  await c.api('/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true' });
  await approveFirst(c);
  await c.api('/api/vercel/settings', { setting: 'description', value: 'Secret-ish words' });
  await approveFirst(c);
  assert.deepEqual(c.x.http.sent.slice(1).map((s) => [s.method, s.target, s.body]), [
    ['PATCH', `/v2/teams/${TEAM}`, { hideIpAddresses: true }],
    ['PATCH', `/v2/teams/${TEAM}`, { description: 'Secret-ish words' }],
  ]);
  assert.deepEqual(c.audit().filter((r) => r.action === 'vercel.team_setting_changed').map((r) => r.detail), [{ setting: 'hideIpAddresses', value: 'true' }, { setting: 'description' }]);
});

test('KBOX-26 Vercel\'s 404, 409, 403 and an unreachable Vercel make the approval failed with the four names, and no audit row for a change that did not happen', async (t) => {
  for (const [answer, name] of [
    [{ status: 404 }, 'vercel_not_found'],
    [{ status: 409 }, 'vercel_conflict'],
    [{ status: 403 }, 'vercel_forbidden'],
    [{ status: 0, transport: 'unreachable' as const }, 'unreachable'],
  ] as const) {
    const c = await core(t, () => answer);
    await c.api('/api/vercel/domains', { project: 'shop', op: 'remove', domain: 'shop.example.com' });
    const id = await approveFirst(c);
    assert.deepEqual(executedOf(c), [{ approval_id: id, result: 'failed', reason_code: name }], name);
    assert.deepEqual(c.audit().filter((r) => r.action.startsWith('vercel.')), [], name);
  }
});

test('KBOX-26 at execution two masters are failed master_ambiguous and none is failed no_master, each with no request to Vercel', async (t) => {
  const rows = [masterRow()];
  const c = await core(t, undefined, rows);
  await c.api('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' });
  await c.api('/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true' });
  rows.push(masterRow([`team:${TEAM}`], `vcp_KboxTestFakeSecond${'S'.repeat(20)}`));
  const first = await approveFirst(c, 'vercel_set_domain');
  rows.length = 0;
  const second = await approveFirst(c, 'vercel_set_team_setting');
  assert.deepEqual(executedOf(c), [{ approval_id: first, result: 'failed', reason_code: 'master_ambiguous' }, { approval_id: second, result: 'failed', reason_code: 'no_master' }]);
  assert.deepEqual(c.x.http.sent, []);
});

test('KBOX-26 F1: an approval for a setting outside the list (the list changed, or the row was forced in) is failed with the proposal\'s code at execution and sends nothing', async (t) => {
  const c = await core(t);
  const ops = createVercelOps({ registry: [c.x.entry], source: c.x.source, audit: { append: () => undefined }, clock: new FakeClock(0) });
  const run = (action: Action) => {
    const approval: StoredApproval = { approvalId: 'apr_AAAAAAAAAAAAAAAA', revision: 1, action, requester: { kind: 'box' }, proof: undefined };
    return ops.executors.vercel_set_team_setting(approval);
  };
  assert.deepEqual(await run({ kind: 'vercel_set_team_setting', setting: 'members', value: 'x' }), { result: 'failed', reason: 'setting_not_listed' });
  assert.deepEqual(await run({ kind: 'vercel_set_team_setting', setting: 'description', value: '' }), { result: 'failed', reason: 'bad_value' });
  assert.deepEqual(await run({ kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'shop.example.com' }), { result: 'failed', reason: 'wrong_kind' });
  assert.deepEqual(c.x.http.sent, []);
});

test('KBOX-26 F3: a crash after approved is failed interrupted at the next start and Vercel is not called again', async (t) => {
  let died = true;
  const c = await core(t, () => {
    if (died) throw new Error('the process died here');
    return { status: 200 };
  });
  await c.api('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' });
  const [item] = await c.w.queue();
  assert.ok(item);
  await c.w.decide(item.approval_id, 'approve', c.w.proofFor(item));
  assert.equal(c.x.http.sent.length, 1, 'the request was made once, then the process died');
  died = false;
  const ops = createVercelOps({ registry: [c.x.entry], source: c.x.source, audit: { append: () => undefined }, clock: new FakeClock(0) });
  openApproveCore({ parts: c.w.parts, approverStore: c.w.priv, trust: c.w.trust, push: c.w.push, clock: c.w.clock, random: seededRandom(77), domain: DOMAIN, wordlist: WORDLIST, vet: () => 'ok', executors: ops.executors });
  assert.equal(c.x.http.sent.length, 1, 'no second call');
  assert.deepEqual(executedOf(c), [{ approval_id: item.approval_id, result: 'failed', reason_code: 'interrupted' }]);
});

test('KBOX-26 POST /api/vercel/projects opens no approval, calls Vercel once, answers 201 with project_id and name and no other member, and audits vercel.project_created with the token label', async (t) => {
  const c = await core(t, () => ({ status: 200, json: { id: 'prj_77', name: 'shop', accountId: 'acct', token: 'leak' } }));
  const reply = await c.api('/api/vercel/projects', { name: 'shop' });
  assert.equal(reply.status, 201, reply.body);
  assert.deepEqual(reply.json(), { project_id: 'prj_77', name: 'shop' });
  assert.deepEqual(c.x.http.sent, [{ method: 'POST', target: `/v11/projects?teamId=${TEAM}`, bearer, body: { name: 'shop' } }]);
  assert.deepEqual(await c.w.queue(), [], 'no approval');
  assert.deepEqual(c.audit().filter((r) => r.action === 'vercel.project_created').map((r) => [r.ref, r.actor, r.detail]), [['shop', CONTROL, { name: 'shop' }]]);
});

test('KBOX-26 createProject: an existing name is 409 conflict and a failing Vercel is 503 unavailable, with no audit row for either', async (t) => {
  const conflict = await core(t, () => ({ status: 409 }));
  const exists = await conflict.api('/api/vercel/projects', { name: 'shop' });
  assert.deepEqual([exists.status, errorOf(exists).code], [409, 'conflict']);
  const down = await core(t, () => ({ status: 0, transport: 'unreachable' }));
  const failed = await down.api('/api/vercel/projects', { name: 'shop' });
  assert.deepEqual([failed.status, errorOf(failed).code], [503, 'unavailable']);
  for (const c of [conflict, down]) assert.deepEqual(c.audit().filter((r) => r.action === 'vercel.project_created'), []);
});

test('KBOX-26 the routes need the control token: no token is 401 and a relay token is refused, and nothing is sent', async (t) => {
  const c = await core(t);
  const none = await c.w.call('/api/vercel/projects', { json: { name: 'shop' } });
  assert.equal(none.status, 401);
  const relay = await c.w.call('/api/vercel/projects', { json: { name: 'shop' }, token: c.w.token('machine', 'relay') });
  assert.ok(relay.status === 401 || relay.status === 403, String(relay.status));
  assert.deepEqual(c.x.http.sent, []);
});

// -------------------------------------------------------------------------------------------------- the running core

test('KBOX-26 through the running core (the registry\'s Vercel entry, the stored master): createProject answers 201, the three routes and both executors are wired, and POST /api/proposals runs the same typed checks', async (t) => {
  const dir = await tempDir(t);
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(9);
  const token = newToken(random);
  const keyref = 'vercel/team/MASTER';
  const prepared = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random });
  prepared.meta.addMachine({ label: CONTROL, scope: 'control', tokenSha256: hashToken(token), enrolledAt: clock.now() });
  prepared.vault.put(keyref, 1, Buffer.from(MASTER_TEXT));
  prepared.meta.putKey({
    keyref,
    platform: 'vercel',
    name: 'MASTER',
    projects: ['team'],
    class: 'master',
    status: 'works',
    gen_current: 1,
    schedule: { rotate_every_days: 90, grace_hours: 24, next_due_at: null, expires_at: null },
    coverage: null,
    last_use_at: null,
  });
  createRotationStore(prepared.db, clock, prepared.hub).putKeyInfo(keyref, { scopeItems: [`team:${TEAM}`], location: {}, rotatedAt: clock.now(), markAdmin: false });
  prepared.close();
  const http = scripted(() => ({ status: 200, json: { id: 'prj_9', name: 'shop' } }));
  const socket = join(dir, 'http.sock');
  const env = { KB_STATE_DIR: join(dir, 'state'), KB_SOCKET: socket, KB_INSTALL_RESULTS: join(dir, 'results'), KB_CURRENT: join(dir, 'current'), KB_DOMAIN: 'box.example' };
  const started = await startCore(env, { clock, scheduler: clock, random, journal: () => undefined, registry: [createVercelEntry({ http, clock, pause: () => Promise.resolve() })] });
  t.after(() => started.stop());
  const driver = drive(socket);
  const call = (path: string, body: unknown) =>
    driver.request({ path, method: 'POST', headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  assert.ok(started.executorKinds.has('vercel_set_domain') && started.executorKinds.has('vercel_set_team_setting'), 'both executors are wired');
  const created = await call('/api/vercel/projects', { name: 'shop' });
  assert.deepEqual([created.status, created.json()], [201, { project_id: 'prj_9', name: 'shop' }]);
  const writes = (): readonly (readonly string[])[] => http.sent.filter((s) => s.method !== 'GET').map((s) => [s.method, s.target]); // start-up reconcile only reads
  assert.deepEqual(writes(), [['POST', `/v11/projects?teamId=${TEAM}`]]);
  const outside = await call('/api/proposals', { action: { kind: 'vercel_set_team_setting', setting: 'members', value: 'x' } });
  assert.deepEqual([outside.status, errorOf(outside).detail?.code], [422, 'setting_not_listed']);
  const opened = await call('/api/vercel/settings', { setting: 'hideIpAddresses', value: 'true' });
  assert.equal(opened.status, 201, opened.body);
  const domain = await call('/api/vercel/domains', { project: 'shop', op: 'add', domain: 'shop.example.com' });
  assert.equal(domain.status, 201, domain.body);
  assert.equal(writes().length, 1, 'a proposal sends nothing to Vercel');
});
