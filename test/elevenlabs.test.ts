// KBOX-39: the ElevenLabs adapter, over a loopback fake that plays the platform as docs/probes/elevenlabs.md describes it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { Issuer, KeyLister, Verifier } from '../src/ports/issuer.ts';
import type { AllowRule, RelayProfile } from '../src/ports/relay-profile.ts';
import type { Lent } from '../src/ports/types.ts';
import { createElevenLabsEntry } from '../src/platforms/elevenlabs/index.ts';
import { matchesShape } from '../src/pure/class.ts';
import { checkRegistry, compileProfile, refuseWidening } from '../src/pure/profile.ts';
import { parseRelayTarget } from '../src/pure/target-parse.ts';
import { issuerContract } from './contracts/issuer.contract.ts';
import { listerContract } from './contracts/lister.contract.ts';
import { verifierContract } from './contracts/verifier.contract.ts';
import { HOST_OF, startElevenLabsWorld } from './fakes/elevenlabs.ts';
import type { ElevenLabsWorld, Region } from './fakes/elevenlabs.ts';
import { variants } from './fixtures/profiles.ts';
import { bytesOf, canary, lent } from './kit/index.ts';

const PERMISSIONS = JSON.parse(readFileSync(new URL('../src/platforms/elevenlabs/permissions.json', import.meta.url), 'utf8')) as { master: string[]; ordinary: string[] };
const MASTER_NAMES = [
  'workspace_read', 'workspace_write', 'workspace_analytics_full_read', 'workspace_members_read', 'workspace_members_invite', 'workspace_members_remove',
  'group_members_manage', 'audit_log_read', 'copy_resources_cross_workspace', 'service_account_write', 'create_user_api_key', 'webhooks_write',
  'conversation_privacy_manage', 'terms_of_service_accept', 'share_voice_externally', 'publish_voice_to_voice_library',
];

let world: ElevenLabsWorld;
let entry: PlatformEntry;
before(async () => {
  world = await startElevenLabsWorld();
  entry = createElevenLabsEntry({ http: world.http });
});
after(() => world.close());

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
const classify = (items: readonly string[]): string => issuerOf().capabilities().classify({ items });
const textOf = (l: Lent): Promise<string> => bytesOf(l).then((b) => Buffer.from(b).toString('utf8'));

test('KBOX-39 permissions.json holds the 54 permission names of the probe: the 16 master ones and 38 ordinary ones, no name twice', () => {
  assert.deepEqual([...PERMISSIONS.master].sort(), [...MASTER_NAMES].sort());
  assert.equal(PERMISSIONS.ordinary.length, 38);
  assert.equal(new Set([...PERMISSIONS.master, ...PERMISSIONS.ordinary]).size, 54);
});

test('KBOX-39 classify: every workspace, service-account, key-management and doubtful permission is master, every other known one is ordinary', () => {
  for (const name of PERMISSIONS.master) assert.equal(classify([name]), 'master', name);
  for (const name of PERMISSIONS.ordinary) assert.equal(classify([name]), 'ordinary', name);
});

test('KBOX-39 classify: "all", an unknown name (fail closed) or one master name among ordinary ones is master; none at all, or only placement items, is ordinary', () => {
  assert.equal(classify(['all']), 'master');
  assert.equal(classify(['text_to_speech', 'a_name_the_enum_never_had']), 'master');
  assert.equal(classify(['text_to_speech', 'speech_to_text', 'create_user_api_key']), 'master');
  assert.equal(classify([]), 'ordinary');
  assert.equal(classify(['region:us', 'service-account:sa-test-1']), 'ordinary');
  assert.equal(issuerOf().capabilities().classify({ access: 'read' }), 'ordinary');
});

test('KBOX-39 the entry states the two management hosts, the three still-unverified probe items, a key page, and no relay profile', () => {
  assert.equal(entry.id, 'elevenlabs');
  assert.deepEqual([...(entry.hosts ?? [])].sort(), ['api.elevenlabs.io', 'api.us.elevenlabs.io']);
  assert.deepEqual([...entry.unverified].sort(), ['elevenlabs.key-format', 'elevenlabs.permission-enum', 'elevenlabs.verifier-call']);
  assert.equal(entry.relay, undefined);
  assert.equal(entry.shape, undefined);
  assert.equal(entry.classify, undefined);
  assert.equal(entry.issuer?.capabilities().revealOnce, true);
  assert.ok(entry.keyPageUrl?.startsWith('https://elevenlabs.io/'));
});

const subject = () => {
  world.reset();
  return { issuer: issuerOf(), lister: listerOf(), verifier: verifierOf(), master: world.master(), wrongMaster: world.stranger(), stranger: world.stranger(), setUnreachable: (down: boolean) => { for (const r of Object.values(world.regions)) r.down = down; } };
};
issuerContract('elevenlabs', subject);
listerContract('elevenlabs', subject);
verifierContract('elevenlabs', subject);

test('KBOX-39 issue posts the name and the permissions to the service account of the scope, with the master in xi-api-key and never in Authorization', async () => {
  world.reset();
  world.regions.global.accounts.set('sa-test-2', { name: 'two', keys: new Map() });
  const issued = await issuerOf().issue({ scope: { items: ['text_to_speech', 'models_read', 'service-account:sa-test-2'] } }, 'kbox_intent', world.master());
  const call = world.sent.find((s) => s.method === 'POST');
  assert.equal(call?.target, '/v1/service-accounts/sa-test-2/api-keys');
  assert.equal(call?.originalHost, HOST_OF.global);
  assert.equal(call?.headers['xi-api-key'], await textOf(world.master()));
  assert.equal(call?.headers['authorization'], undefined);
  assert.deepEqual(JSON.parse(Buffer.from(call?.body ?? []).toString('utf8')), { name: 'kbox_intent', permissions: ['text_to_speech', 'models_read'] });
  assert.equal(world.regions.global.accounts.get('sa-test-2')?.keys.size, 1);
  assert.ok((await textOf(issued.value)).startsWith('sk_'));
});

test('KBOX-39 issue sends the string "all" when the scope asks for all permissions, and an empty list when it asks for none', async () => {
  world.reset();
  await issuerOf().issue({ scope: { items: ['all'] } }, 'a', world.master());
  await issuerOf().issue({ scope: { items: [] } }, 'b', world.master());
  const bodies = world.sent.filter((s) => s.method === 'POST').map((s) => (JSON.parse(Buffer.from(s.body).toString('utf8')) as { permissions: unknown }).permissions);
  assert.deepEqual(bodies, ['all', []]);
});

test('KBOX-39 issue without a service-account item uses the workspace\'s one service account, and refuses when there are two or none, naming a fixed code', async () => {
  world.reset();
  await issuerOf().issue({ scope: { items: [] } }, 'a', world.master());
  assert.equal(world.regions.global.accounts.get('sa-test-1')?.keys.size, 1);
  world.regions.global.accounts.set('sa-test-2', { name: 'two', keys: new Map() });
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'b', world.master()), /elevenlabs: service_account_unclear/);
  world.regions.global.accounts.clear();
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'c', world.master()), /elevenlabs: service_account_unclear/);
});

test('KBOX-39 a scope naming a region that does not exist or a service account that is not a plain id is refused before any call', async () => {
  world.reset();
  await assert.rejects(() => issuerOf().issue({ scope: { items: ['region:mars'] } }, 'a', world.master()), /elevenlabs: bad_scope/);
  await assert.rejects(() => issuerOf().issue({ scope: { items: ['service-account:../x'] } }, 'a', world.master()), /elevenlabs: bad_scope/);
  assert.equal(world.sent.length, 0);
});

test('KBOX-39 the region switch: scope "region:us" reaches the us host and only it, no item reaches the global host', async () => {
  world.reset();
  const mine = await issuerOf().issue({ scope: { items: ['region:us'] } }, 'us-key', world.master('us'));
  assert.deepEqual(world.sent.map((s) => s.originalHost), [HOST_OF.us, HOST_OF.us]);
  assert.equal(world.regions.us.accounts.get('sa-test-1')?.keys.size, 1);
  assert.equal(world.regions.global.accounts.get('sa-test-1')?.keys.size, 0);
  world.clearSent();
  await issuerOf().issue({ scope: { items: [] } }, 'global-key', world.master());
  assert.ok(world.sent.every((s) => s.originalHost === HOST_OF.global));
  assert.ok(mine.platformKeyId.length > 0);
});

test('KBOX-39 revoke finds a key in whichever region holds it, and answers absent only after reading both', async () => {
  world.reset();
  const issued = await issuerOf().issue({ scope: { items: ['region:us'] } }, 'us-key', world.master('us'));
  world.clearSent();
  assert.equal(await issuerOf().revoke(issued.platformKeyId, world.master('us')), 'revoked');
  assert.equal(world.regions.us.accounts.get('sa-test-1')?.keys.size, 0);
  assert.equal(await issuerOf().revoke(issued.platformKeyId, world.master('us')), 'absent');
});

test('KBOX-39 a master only one region knows still lists and revokes: the other region\'s refusal is skipped, a refusal from both throws', async () => {
  world.reset();
  const issued = await issuerOf().issue({ scope: { items: [] } }, 'k', world.master());
  assert.equal((await listerOf().list(world.master())).length, 1);
  assert.equal(await issuerOf().revoke(issued.platformKeyId, world.master()), 'revoked');
  await assert.rejects(() => listerOf().list(world.stranger()), /elevenlabs: rejected/);
});

test('KBOX-39 / KBOX-51 list reads both regions and records each key\'s region; listAt of one region reads that host only; listAt with no region reads both', async () => {
  world.reset();
  world.regions.us.masters.add('sk_kbox-test-master-global-fake');
  await issuerOf().issue({ scope: { items: ['region:us'] } }, 'in-us', world.master());
  await issuerOf().issue({ scope: { items: [] } }, 'in-global', world.master());
  world.clearSent();
  const all = await listerOf().list(world.master());
  assert.deepEqual(all.map((k) => [k.name, k.location?.region]).sort(), [['in-global', 'global'], ['in-us', 'us']]);
  world.clearSent();
  const us = await listerOf().listAt({ region: 'us' }, world.master());
  assert.deepEqual(world.sent.map((s) => s.originalHost), [HOST_OF.us]);
  assert.deepEqual(us.at, { region: 'us' });
  assert.deepEqual(us.keys.map((k) => k.name), ['in-us']);
  assert.equal(us.complete, true);
  world.clearSent();
  const none = await listerOf().listAt({}, world.master());
  assert.deepEqual(world.sent.map((s) => s.originalHost).sort(), [HOST_OF.global, HOST_OF.us].sort());
  assert.equal(none.keys.length, 2);
});

test('KBOX-39 a key the platform holds switched off is listed with disabled: true, and one switched on is not', async () => {
  world.reset();
  await issuerOf().issue({ scope: { items: [] } }, 'on', world.master());
  await issuerOf().issue({ scope: { items: [] } }, 'off', world.master());
  for (const k of world.regions.global.accounts.get('sa-test-1')?.keys.values() ?? []) if (k.name === 'off') k.disabled = true;
  const listed = await listerOf().list(world.master());
  assert.deepEqual(listed.map((k) => [k.name, k.disabled]).sort(), [['off', true], ['on', undefined]]);
});

test('KBOX-39 verifier: GET /v1/user with xi-api-key; a key one region knows is ok, one no region knows is rejected', async () => {
  world.reset();
  const issued = await issuerOf().issue({ scope: { items: ['region:us'] } }, 'k', world.master('us'));
  world.clearSent();
  assert.equal(await verifierOf().verify(issued.value, { platform: 'elevenlabs' }), 'ok');
  const call = world.sent.find((s) => s.target === '/v1/user');
  assert.equal(call?.method, 'GET');
  assert.equal(call?.headers['xi-api-key'], await textOf(issued.value));
  assert.equal(await verifierOf().verify(world.stranger(), { platform: 'elevenlabs' }), 'rejected');
});

test('KBOX-39 verifier: a 403 is rejected; a 500, or a refusal in one region with the other down, is unreachable, never rejected', async () => {
  world.reset();
  const key = world.master();
  world.regions.global.failWith = 403;
  world.regions.us.failWith = 403;
  assert.equal(await verifierOf().verify(key, { platform: 'elevenlabs' }), 'rejected');
  world.regions.global.failWith = 500;
  world.regions.us.failWith = 500;
  assert.equal(await verifierOf().verify(key, { platform: 'elevenlabs' }), 'unreachable');
  world.regions.global.failWith = undefined;
  world.regions.us.failWith = undefined;
  world.regions.us.down = true;
  assert.equal(await verifierOf().verify(world.stranger(), { platform: 'elevenlabs' }), 'unreachable');
  assert.equal(await verifierOf().verify(key, { platform: 'elevenlabs' }), 'ok');
});

test('KBOX-39 failures are fixed codes: 401 and 403 are "rejected", 5xx is "platform_error", a cut connection is "unreachable", an answer of the wrong shape is "malformed"', async () => {
  world.reset();
  world.regions.global.failWith = 503;
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'a', world.master()), /elevenlabs: platform_error \(503\)$/);
  world.regions.global.failWith = 403;
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'a', world.master()), /elevenlabs: rejected \(403\)$/);
  world.regions.global.failWith = undefined;
  world.regions.global.down = true;
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'a', world.master()), /elevenlabs: unreachable$/);
  world.regions.global.down = false;
  world.regions.global.createAnswer = 'no-key-id';
  await assert.rejects(() => issuerOf().issue({ scope: { items: [] } }, 'a', world.master()), /elevenlabs: malformed$/);
});

test('KBOX-14 KBOX-39 canary: a create response carrying a canary key and a platform error quoting the canary master never show in any error, its cause or its fields', async () => {
  world.reset();
  const surfaces = (e: unknown): Record<string, string> => {
    assert.ok(e instanceof Error);
    return { message: e.message, stack: e.stack ?? '', name: e.name, cause: String(e.cause ?? ''), fields: JSON.stringify(e, Object.getOwnPropertyNames(e)) };
  };
  const c = canary(24);
  const value = `sk_${Buffer.from(c.bytes).toString('hex')}`;
  world.regions.global.createValue = value;
  world.regions.global.createAnswer = 'no-key-id';
  const failures: unknown[] = [];
  await issuerOf().issue({ scope: { items: [] } }, 'a', world.master()).catch((e: unknown) => failures.push(e));
  world.regions.global.createAnswer = 'ok';
  const created = await issuerOf().issue({ scope: { items: [] } }, 'b', world.master());
  assert.equal(await textOf(created.value), value);
  assert.equal(JSON.stringify(created).includes(value), false);
  assert.equal(String(created.value).includes(value), false);
  const m = canary(24);
  const master = lent(Buffer.from(`sk_${Buffer.from(m.bytes).toString('hex')}`), 'master:canary');
  await issuerOf().issue({ scope: { items: [] } }, 'c', master).catch((e: unknown) => failures.push(e));
  await listerOf().list(master).catch((e: unknown) => failures.push(e));
  await listerOf().listAt({ region: 'us' }, master).catch((e: unknown) => failures.push(e));
  await issuerOf().revoke('key-x', master).catch((e: unknown) => failures.push(e));
  world.regions.global.failWith = 500;
  world.regions.us.failWith = 500;
  await issuerOf().issue({ scope: { items: [] } }, 'd', master).catch((e: unknown) => failures.push(e));
  await listerOf().list(master).catch((e: unknown) => failures.push(e));
  assert.equal(failures.length, 7);
  for (const e of failures) {
    c.assertAbsent(surfaces(e));
    m.assertAbsent(surfaces(e));
  }
  assert.equal(await verifierOf().verify(master, { platform: 'elevenlabs' }), 'unreachable');
});

test('KBOX-39 shape: sk_ plus hex of the stated length is accepted; a wrong prefix, a short core, a long core and a wrong alphabet are refused', () => {
  const shape = issuerOf().capabilities().shape;
  assert.equal(shape.prefix, 'sk_');
  assert.equal(shape.alphabet, 'hex');
  const hex48 = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718';
  assert.equal(matchesShape(shape, `sk_${hex48}`), true);
  assert.equal(matchesShape(shape, `sk_${hex48.slice(0, 32)}`), true);
  assert.equal(matchesShape(shape, `sk-${hex48}`), false);
  assert.equal(matchesShape(shape, `xi_${hex48}`), false);
  assert.equal(matchesShape(shape, `sk_${hex48.slice(0, 31)}`), false);
  assert.equal(matchesShape(shape, `sk_${hex48}${hex48}`), false);
  assert.equal(matchesShape(shape, `sk_${hex48.slice(0, 47)}g`), false);
  assert.equal(matchesShape(shape, `sk_${hex48.slice(0, 47)}G`), false);
});

const MUST_DENY_IDS = [
  'service-accounts', 'workspace-api-keys', 'workspace', 'single-use-token', 'signed-url-dash', 'signed-url-underscore', 'conversation-token', 'realtime-client-secret', 'convai-secrets',
];

test('KBOX-39 denyOnly carries the pinned rules of design 5.5, each with samples on both regional hosts, and passes the registry check', () => {
  assert.deepEqual(entry.denyOnly?.map((r) => r.id), MUST_DENY_IDS);
  const urls = (entry.denyOnly ?? []).flatMap((r) => r.samples.map((s) => `${s.method} ${s.url}`));
  for (const expected of [
    'POST https://api.elevenlabs.io/v1/service-accounts',
    'POST https://api.us.elevenlabs.io/v1/service-accounts/sa-test-1/api-keys',
    'POST https://api.elevenlabs.io/v1/workspaces/api-keys/key01',
    'GET https://api.elevenlabs.io/v1/workspace/members',
    'POST https://api.elevenlabs.io/v1/single-use-token/realtime_scribe',
    'GET https://api.elevenlabs.io/v1/convai/conversation/get-signed-url',
    'GET https://api.us.elevenlabs.io/v1/convai/conversation/get_signed_url',
    'GET https://api.elevenlabs.io/v1/convai/conversation/token',
    'POST https://api.elevenlabs.io/v1/convai/realtime/client_secrets',
    'GET https://api.elevenlabs.io/v1/convai/secrets',
  ]) assert.ok(urls.includes(expected), expected);
  assert.deepEqual(checkRegistry([entry]), { ok: true });
});

/** The widest relay profile on the global host that the registry's widening check still takes while it holds `mustDeny`. */
function widest(mustDeny: RelayProfile['mustDeny']): RelayProfile {
  const base: RelayProfile = {
    platform: 'elevenlabs',
    origin: { kind: 'fixed', host: HOST_OF.global },
    callerTokenHeaders: ['apikey'],
    inject: () => Promise.resolve(),
    allow: [{ id: 'models-list', method: 'GET', host: HOST_OF.global, pathTemplate: '/v1/models', query: {} }],
    tailRules: [],
    mustDeny,
    requestHeaders: [],
    headerWords: {},
    responseHeaders: [],
    envForClients: () => ({}),
  };
  const compiled = compileProfile(base);
  assert.ok(compiled.ok);
  const templates = ['/{rest:**}', '/v1/{rest:**}', '/v1/service-accounts/{rest:**}', '/v1/convai/{rest:**}', '/v1/workspace/{rest:**}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}/{b:[A-Za-z0-9_.-]{1,128}}'];
  const added: AllowRule[] = [];
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const [i, pathTemplate] of templates.entries()) {
      const rule: AllowRule = { id: `wide-${method.toLowerCase()}-${i}`, method, host: HOST_OF.global, pathTemplate, query: {} };
      if (refuseWidening(compiled.engine, [rule], [rule.id]).ok) added.push(rule);
    }
  }
  assert.ok(added.length > 0);
  return { ...base, allow: [...base.allow, ...added], tailRules: added.map((r) => r.id) };
}

function decided(profile: RelayProfile, method: string, url: string): 'allowed' | 'denied' {
  const compiled = compileProfile(profile);
  assert.ok(compiled.ok);
  const u = new URL(url);
  const target = parseRelayTarget(`/r/abc123${u.pathname}${u.search}`);
  if (!target.ok) return 'denied';
  return compiled.engine.decide(method, target.value).ok ? 'allowed' : 'denied';
}

test('KBOX-39 KBOX-13 every deny sample and every canonicalisation variant of it is refused by a profile as wide as the registry lets one be; a request off the list still passes it', () => {
  const deny = entry.denyOnly ?? [];
  const wide = widest(deny);
  const refused: string[] = [];
  for (const rule of deny) {
    for (const sample of rule.samples) {
      const u = new URL(sample.url);
      for (const v of variants(sample.method, HOST_OF.global, u.pathname)) if (decided(wide, v.method, v.url) !== 'denied') refused.push(`${rule.id} ${v.method} ${v.url}`);
      if (decided(wide, sample.method, `https://${HOST_OF.global}${u.pathname}`) !== 'denied') refused.push(`${rule.id} ${sample.method} ${sample.url}`);
    }
  }
  assert.deepEqual(refused, []);
  assert.equal(decided(wide, 'GET', `https://${HOST_OF.global}/v1/models`), 'allowed');
});

test('KBOX-39 positive control: with the deny list emptied the same wide profile lets every base sample through', () => {
  const wide = widest([{ id: 'unrelated', samples: [{ method: 'GET', url: `https://${HOST_OF.global}/v1/unrelated` }] }]);
  const through = (entry.denyOnly ?? []).flatMap((r) => r.samples).filter((s) => decided(wide, s.method, `https://${HOST_OF.global}${new URL(s.url).pathname}`) === 'allowed');
  assert.ok(through.length > 0);
});

test('KBOX-39 the regions of the world are the two the entry knows', () => {
  const regions: Region[] = ['global', 'us'];
  assert.deepEqual(regions.map((r) => HOST_OF[r]).sort(), [...(entry.hosts ?? [])].sort());
});
