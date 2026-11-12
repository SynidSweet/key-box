// KBOX-36, KBOX-23, KBOX-13: Vercel is deny-only in v1. Its pinned mustDeny list holds every sample the spec names, each with the KBOX-13
// canonicalisation variants, and a relay running a profile with that list (and, widened, every broad allow rule the registry still accepts)
// answers each sample 400 or 403 with no upstream call.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { AllowRule, DenyRule, RelayProfile } from '../src/ports/relay-profile.ts';
import { checkRegistry, compileProfile, refuseWidening } from '../src/pure/profile.ts';
import { createVercelEntry } from '../src/platforms/vercel/index.ts';
import { refusingAdapterHttp } from '../src/ports/http.ts';
import { TEST_REGISTRY } from './fixtures/profiles.ts';
import { relayWorld } from './support/relay-world.ts';

const entry: PlatformEntry = createVercelEntry({ http: refusingAdapterHttp, clock: { now: () => 0 } });
const denyOnly = entry.denyOnly ?? [];
const HOST = 'api.vercel.com';

/** The spec's samples (KBOX-36, revised de4ab70 and the probe), as the caller would send them. */
const SPEC_SAMPLES: readonly (readonly [string, string])[] = [
  ['GET', '/v6/user/tokens'],
  ['POST', '/v3/user/tokens'],
  ['DELETE', '/v3/user/tokens/t'],
  ['GET', '/v10/projects/p/env'],
  ['GET', '/v1/env/x'],
  ['GET', '/v1/integrations/configurations?view=account'],
  ['GET', '/v1/teams/t/members'],
  ['GET', '/v1/teams/t/invites'],
  ['POST', '/v2/teams/t/members'],
  ['POST', '/v13/deployments'],
  ['PATCH', '/v1/projects/p/protection-bypass'],
  ['GET', '/v1/drains'],
  ['GET', '/v1/log-drains'],
  ['GET', '/v1/webhooks'],
];

const allSamples = denyOnly.flatMap((rule) => rule.samples.map((s) => `${s.method} ${s.url}`));

test('KBOX-36 the deny list names a rule per operation and holds every sample the spec lists, unchanged', () => {
  for (const [method, path] of SPEC_SAMPLES) assert.ok(allSamples.includes(`${method} https://${HOST}${path}`), `${method} ${path}`);
  assert.ok(denyOnly.length >= 10);
  assert.equal(new Set(denyOnly.map((r) => r.id)).size, denyOnly.length, 'rule ids are unique');
  for (const rule of denyOnly) assert.ok(rule.samples.length >= 10, `${rule.id} has its canonicalisation variants`);
});

test('KBOX-36 the three token-management paths and the invite carry the corrected routes (probe 2026-11-12): invite is POST /v2/teams/t/members, protection bypass is PATCH', () => {
  assert.equal(allSamples.includes(`POST https://${HOST}/v1/teams/t/invites`), false, 'no such route exists');
  assert.equal(allSamples.includes(`POST https://${HOST}/v1/projects/p/protection-bypass`), false, 'the route is PATCH');
});

test('KBOX-13 each rule\'s samples include the canonicalisation variants: encoded first letter, trailing slash, double slash, dot segments, encoded slash, parameter, method override', () => {
  const tokens = denyOnly.find((r) => r.samples.some((s) => s.url === `https://${HOST}/v3/user/tokens`));
  const urls = (tokens?.samples ?? []).filter((s) => s.method === 'POST').map((s) => s.url);
  for (const wanted of [
    `https://${HOST}/v3/%75ser/tokens`,
    `https://${HOST}/v3/user/tokens/`,
    `https://${HOST}//v3/user/tokens`,
    `https://${HOST}/v3/user/x/../tokens`,
    `https://${HOST}/v3/user/%2e%2e/tokens`,
    `https://${HOST}/v3/user%2Ftokens`,
    `https://${HOST}/v3/user/tokens;x`,
    `https://${HOST}/v3/user/tokens?_method=POST`,
  ]) assert.ok(urls.includes(wanted), wanted);
  assert.ok((tokens?.samples ?? []).some((s) => s.method === 'GET' && s.url === `https://${HOST}/v3/user/tokens?%24method=POST`));
});

test('KBOX-13 a sample that needs a query to pass the platform\'s validation keeps it on every variant', () => {
  const integrations = denyOnly.flatMap((r) => r.samples).filter((s) => s.url.includes('configurations'));
  assert.ok(integrations.length >= 10);
  for (const s of integrations) assert.match(s.url, /view=account/, s.url);
});

test('KBOX-23 the real list passes the registry check as deny-only, and a relay profile next to it does not', () => {
  assert.equal(checkRegistry([entry]).ok, true);
  const withRelay: PlatformEntry = { ...entry, relay: relayProfileWith(denyOnly) };
  assert.deepEqual(checkRegistry([withRelay]), { ok: false, code: 'deny_only_with_relay', platform: 'vercel' });
});

// ---------------------------------------------------------------- the deny harness, through the running relay

/** A profile that would relay Vercel with nothing allowed: the harness's stand-in for what a relay profile of this list does. */
function relayProfileWith(mustDeny: readonly DenyRule[], allow: readonly AllowRule[] = [], tailRules: readonly string[] = []): RelayProfile {
  return {
    platform: 'pathplat',
    origin: { kind: 'fixed', host: HOST },
    callerTokenHeaders: ['authorization'],
    inject: (h: Headers): Promise<void> => {
      h.set('authorization', 'Bearer kbox-test-fake');
      return Promise.resolve();
    },
    allow,
    tailRules,
    mustDeny,
    requestHeaders: [],
    headerWords: {},
    responseHeaders: [],
    envForClients: (): Record<string, string> => ({}),
  };
}

const engineOf = (profile: RelayProfile): ReturnType<typeof compiledEngine> => compiledEngine(profile);
function compiledEngine(profile: RelayProfile) {
  const compiled = compileProfile(profile);
  if (!compiled.ok) throw new Error(`profile refused: ${compiled.code}`);
  return compiled.engine;
}

const BROAD = ['/{rest:**}', '/v1/{rest:**}', '/v2/{rest:**}', '/v3/{rest:**}', '/v6/{rest:**}', '/v9/{rest:**}', '/v10/{rest:**}', '/v13/{rest:**}', '/v1/projects/{rest:**}', '/v10/projects/{rest:**}', '/v1/teams/{rest:**}', '/v2/teams/{rest:**}', '/v3/user/{rest:**}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}/{b:[A-Za-z0-9_.-]{1,128}}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

/** The profile with every broad rule added that the widening check still accepts: as wide as the registry permits. */
function widened(profile: RelayProfile): RelayProfile {
  const engine = engineOf(profile);
  const added: AllowRule[] = [];
  for (const method of METHODS) {
    for (const [i, pathTemplate] of BROAD.entries()) {
      const rule: AllowRule = { id: `wide-${method}-${i}`.toLowerCase(), method, host: HOST, pathTemplate, query: {} };
      if (refuseWidening(engine, [rule], [rule.id]).ok) added.push(rule);
    }
  }
  const wide = relayProfileWith(profile.mustDeny, [...profile.allow, ...added], [...profile.tailRules, ...added.map((r) => r.id)]);
  assert.ok(added.length > 0, 'the widening added rules');
  return wide;
}

/** Sends every sample through a relay running `profile`; returns each that got anything but 400 or 403, or reached upstream. */
async function leaks(t: TestContext, profile: RelayProfile, rules: readonly DenyRule[] = profile.mustDeny): Promise<string[]> {
  const registry = TEST_REGISTRY.map((e) => (e.id === 'pathplat' ? { ...e, relay: profile } : e));
  const w = await relayWorld(t, { registry });
  const through: string[] = [];
  for (const rule of rules) {
    for (const sample of rule.samples) {
      const before = w.upstream.requests.length;
      const rest = sample.url.slice('https://'.length);
      const reply = await w.call(`/r/adminkey1${rest.slice(rest.indexOf('/'))}`, { method: sample.method });
      if ((reply.status !== 400 && reply.status !== 403) || w.upstream.requests.length !== before) through.push(`${rule.id} ${sample.method} ${sample.url} -> ${reply.status}`);
    }
  }
  return through;
}

test('KBOX-36 KBOX-13 every sample of the list, variants included, is 400 or 403 with no upstream call through the relay, default and widened', async (t) => {
  const profile = relayProfileWith(denyOnly);
  assert.deepEqual(await leaks(t, profile), []);
  assert.deepEqual(await leaks(t, widened(profile)), []);
});

test('KBOX-36 positive control: a profile that allows one of the listed routes is reported by the harness', async (t) => {
  // The relay refuses to start on a profile whose allow set matches its own mustDeny, so the leaky profile forgets that rule and the harness
  // is handed the full list.
  const leaky = relayProfileWith(denyOnly.filter((r) => r.id !== 'project-env'), [{ id: 'env-read', method: 'GET', host: HOST, pathTemplate: '/v10/projects/{p:[A-Za-z0-9_.-]{1,128}}/env', query: {} }]);
  const through = await leaks(t, leaky, denyOnly);
  assert.ok(through.some((s) => s.includes('GET https://api.vercel.com/v10/projects/p/env ->') && s.endsWith('-> 200')), through.join('\n'));
});
