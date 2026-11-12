// KBOX-25: relay profiles are default-deny with named operations. Template and query matching are pure and tested here
// with many cases; the deny harness that sends every mustDeny sample through the running relay is in the second half.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { AllowRule, DenyRule, RelayProfile } from '../src/ports/relay-profile.ts';
import { checkRegistry, compileProfile, refuseWidening } from '../src/pure/profile.ts';
import type { ProfileEngine } from '../src/pure/profile.ts';
import { parseRelayTarget } from '../src/pure/target-parse.ts';
import { IAM_HOST, PATH_HOST, STORAGE_HOST, hostProfile, leakyProfile, pathProfile } from './fixtures/profiles.ts';
import { NO_ISSUER_CLASSIFY, NO_ISSUER_SHAPE, TEST_REGISTRY } from './fixtures/profiles.ts';
import { relayWorld } from './support/relay-world.ts';

const engineOf = (profile: RelayProfile): ProfileEngine => {
  const compiled = compileProfile(profile);
  if (!compiled.ok) throw new Error(`profile refused: ${compiled.code}`);
  return compiled.engine;
};

/** The rule id the engine matches for `method target`, or the refusal. */
function ruleFor(profile: RelayProfile, method: string, path: string): string {
  const target = parseRelayTarget(`/r/abc123${path}`);
  if (!target.ok) return target.code;
  const decided = engineOf(profile).decide(method, target.value);
  return decided.ok ? decided.rule.id : decided.code;
}

const one = (rule: Partial<AllowRule> & Pick<AllowRule, 'pathTemplate'>, tailRules: readonly string[] = []): RelayProfile => ({
  ...pathProfile,
  allow: [{ id: 'r', method: 'GET', host: PATH_HOST, query: {}, ...rule }],
  tailRules,
});

test('KBOX-25 a literal template matches exactly its decoded segments, case and method included', () => {
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models'), 'models-list');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/%6Dodels'), 'models-list');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/Models'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models/a/b'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'POST', '/v1/models'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'get', '/v1/models'), 'forbidden');
});

test('KBOX-25 a typed parameter takes 1 to 128 characters of its class: 128 pass, 129 and an outside character do not', () => {
  assert.equal(ruleFor(pathProfile, 'GET', `/v1/models/${'a'.repeat(128)}`), 'model-get');
  assert.equal(ruleFor(pathProfile, 'GET', `/v1/models/${'a'.repeat(129)}`), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models/gpt-4.1_mini'), 'model-get');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models/a%3Ab'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models/a~b'), 'forbidden');
});

test('KBOX-25 a trailing slash never matches the template without one', () => {
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models/'), 'bad_path');
  const target = { keyref: 'abc123', segments: ['v1', 'models', ''], rawSegments: ['v1', 'models', ''], query: [] };
  const decided = engineOf(pathProfile).decide('GET', target);
  assert.equal(decided.ok, false);
});

test('KBOX-25 {rest:**} takes one or more tail segments, each still validated, and only on a rule the profile names', () => {
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/files/a'), 'files-tail');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/files/a/b.txt/c~d'), 'files-tail');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/files'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/files/a/b%3Ac'), 'forbidden');
  assert.equal(ruleFor(pathProfile, 'GET', `/v1/files/a/${'b'.repeat(129)}`), 'forbidden');
  const unnamed = compileProfile(one({ pathTemplate: '/v1/{rest:**}' }));
  assert.deepEqual(unnamed.ok ? 'compiled' : unnamed.code, 'tail_not_named');
  const notLast = compileProfile(one({ pathTemplate: '/v1/{rest:**}/x' }, ['r']));
  assert.deepEqual(notLast.ok ? 'compiled' : notLast.code, 'bad_template');
});

test('KBOX-25 a malformed template is refused when the profile is compiled', () => {
  for (const pathTemplate of ['v1/x', '/v1//x', '/v1/{id}', '/v1/{id:[a-z]{0,3}}', '/v1/{id:[a-z]{4,3}}', '/v1/{id:[a-z]{1,300}}', '/v1/{id:[a-z/]{1,3}}', '/v1/{id:[a-z]{1,3}', '/v1/{:[a-z]{1,3}}', '/v1/a b', '/v1/a%2Fb', '/v1/..']) {
    const compiled = compileProfile(one({ pathTemplate }));
    assert.equal(compiled.ok ? 'compiled' : compiled.code, 'bad_template', pathTemplate);
  }
});

test('KBOX-13 a query key the matched rule does not list is forbidden, including decoded tricks; listed keys pass only in their shape', () => {
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/items'), 'items-list');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/items?limit=100&order=desc'), 'items-list');
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/items?order=asc&limit=1'), 'items-list');
  for (const query of ['limit=0', 'limit=101', 'limit=01', 'limit=-1', 'limit=1.5', 'limit=', 'limit=1e2', 'order=ASC', 'order=random', '_method=POST', '%24method=POST', '%61ccess_token=x', 'access_token=x', 'key=x', 'apikey=x', '$httpMethod=POST']) {
    assert.equal(ruleFor(pathProfile, 'GET', `/v1/items?${query}`), 'forbidden', query);
  }
  assert.equal(ruleFor(pathProfile, 'GET', '/v1/models?_method=POST'), 'forbidden');
});

test('KBOX-13 on a host-in-path profile the first segment is the host, byte for byte one of the declared hosts', () => {
  assert.equal(ruleFor(hostProfile, 'GET', `/${IAM_HOST}/v1/projects/proj-01/serviceAccounts`), 'accounts-list');
  assert.equal(ruleFor(hostProfile, 'GET', `/${STORAGE_HOST}/storage/v1/b/bkt-1/o?alt=json`), 'objects-list');
  assert.equal(ruleFor(hostProfile, 'GET', `/${STORAGE_HOST}/storage/v1/b/bkt-1/o?al%74=media`), 'forbidden');
  for (const host of [IAM_HOST.toUpperCase(), `${IAM_HOST}.`, `${IAM_HOST}:443`, `x@${IAM_HOST}`, IAM_HOST.replace('i', '%69'), 'evil.example', STORAGE_HOST]) {
    assert.equal(ruleFor(hostProfile, 'GET', `/${host}/v1/projects/proj-01/serviceAccounts`), 'forbidden', host);
  }
  assert.equal(ruleFor(hostProfile, 'GET', ''), 'forbidden');
});

test('KBOX-25 a request equal to a mustDeny sample is refused even when an allow rule would take it', () => {
  const engine = engineOf(pathProfile);
  const target = parseRelayTarget('/r/abc123/v1/organization/admin_api_keys');
  assert.ok(target.ok);
  assert.equal(engine.isDenied('POST', target.value), true);
  const models = parseRelayTarget('/r/abc123/v1/models');
  assert.ok(models.ok);
  assert.equal(engine.isDenied('GET', models.value), false);
});

test('KBOX-25 the engine itself denies a mustDeny sample that an allow rule would take (the runtime backstop behind the registry check), and only that sample', () => {
  const engine = engineOf(leakyProfile);
  const decide = (method: string, path: string): string => {
    const target = parseRelayTarget(`/r/abc123${path}`);
    if (!target.ok) throw new Error(`refused with ${target.code}`);
    const decided = engine.decide(method, target.value);
    return decided.ok ? decided.rule.id : decided.code;
  };
  assert.equal(decide('POST', '/v1/organization/other'), 'org-anything', 'the leaky rule does take a request that is not a sample');
  assert.equal(decide('POST', '/v1/organization/admin_api_keys'), 'forbidden');
  assert.equal(decide('POST', '/v1/organization/projects/proj01/api_keys'), 'forbidden');
});

test('KBOX-25 widening refusal: a proposed rule that matches a mustDeny sample is refused, naming the rule', () => {
  const engine = engineOf(pathProfile);
  const leak: AllowRule = { id: 'org-anything', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/organization/{rest:**}', query: {} };
  assert.deepEqual(refuseWidening(engine, [leak], ['org-anything']), { ok: false, code: 'allow_matches_must_deny', rule: 'org-anything' });
  const fine: AllowRule = { id: 'models-tail', method: 'GET', host: PATH_HOST, pathTemplate: '/v1/models/{id:[a-z]{1,8}}/x', query: {} };
  assert.deepEqual(refuseWidening(engine, [fine], []), { ok: true });
  const sameAsDenied: AllowRule = { id: 'token', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/auth/token', query: {} };
  assert.deepEqual(refuseWidening(engine, [sameAsDenied], []), { ok: false, code: 'allow_matches_must_deny', rule: 'token' });
});

// ---------------------------------------------------------------- the deny harness, through the running relay

const KEYREF_OF: Readonly<Record<string, string>> = { pathplat: 'adminkey1', hostplat: 'hostkey001' };

/** The relay target of a sample: its raw path (never URL-normalised), under the key, with the host first on a host-in-path profile. */
function relayTargetOf(profile: RelayProfile, url: string): string {
  const rest = url.slice('https://'.length);
  const slash = rest.indexOf('/');
  const host = rest.slice(0, slash);
  const path = rest.slice(slash);
  const keyref = KEYREF_OF[profile.platform] ?? '';
  return profile.origin.kind === 'fixed' ? `/r/${keyref}${path}` : `/r/${keyref}/${host}${path}`;
}

/**
 * KBOX-25: sends every sample of `samples` (by default the profile's own mustDeny) through a relay running `profile`, and
 * returns each sample that got anything but 400 or 403, or reached upstream.
 */
async function leaks(t: TestContext, profile: RelayProfile, samples: readonly DenyRule[] = profile.mustDeny): Promise<string[]> {
  const registry = TEST_REGISTRY.map((e) => (e.id === profile.platform ? { id: e.id, relay: profile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] } : e));
  const w = await relayWorld(t, { registry });
  const through: string[] = [];
  for (const rule of samples) {
    for (const sample of rule.samples) {
      const before = w.upstream.requests.length;
      const reply = await w.call(relayTargetOf(profile, sample.url), { method: sample.method });
      if ((reply.status !== 400 && reply.status !== 403) || w.upstream.requests.length !== before) through.push(`${rule.id} ${sample.method} ${sample.url} -> ${reply.status}`);
    }
  }
  return through;
}

const BROAD_TEMPLATES = ['/{rest:**}', '/v1/{rest:**}', '/v1/organization/{rest:**}', '/v1/organization/projects/{rest:**}', '/v1/auth/{rest:**}', '/v1/models/{rest:**}', '/v1/items/{rest:**}', '/v1/projects/{rest:**}', '/storage/v1/{rest:**}', '/storage/v1/b/{rest:**}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}', '/v1/{a:[A-Za-z0-9_.-]{1,128}}/{b:[A-Za-z0-9_.-]{1,128}}'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

/** The profile with every broad rule added that the widening check still accepts: as wide as the registry permits. */
function widened(profile: RelayProfile): RelayProfile {
  const engine = engineOf(profile);
  const hosts = profile.origin.kind === 'fixed' ? [profile.origin.host] : profile.origin.hosts;
  const added: AllowRule[] = [];
  for (const host of hosts) {
    for (const method of METHODS) {
      for (const [i, pathTemplate] of BROAD_TEMPLATES.entries()) {
        const rule: AllowRule = { id: `wide-${host}-${method}-${i}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(), method, host, pathTemplate, query: {} };
        if (refuseWidening(engine, [rule], [rule.id]).ok) added.push(rule);
      }
    }
  }
  const wide = { ...profile, allow: [...profile.allow, ...added], tailRules: [...profile.tailRules, ...added.map((r) => r.id)] };
  assert.equal(checkRegistry([{ id: wide.platform, relay: wide, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]).ok, true, 'the widened profile passes the registry check');
  assert.ok(added.length > 0, 'the widening added rules');
  return wide;
}

test('KBOX-25 pathplat denies by name admin-key-create, project-key-create, service-account-create and login-token: every sample is 400 or 403 with no upstream call, default and widened', async (t) => {
  assert.deepEqual(pathProfile.mustDeny.map((d) => d.id), ['admin-key-create', 'project-key-create', 'service-account-create', 'login-token']);
  assert.deepEqual(await leaks(t, pathProfile), []);
  assert.deepEqual(await leaks(t, widened(pathProfile)), []);
});

test('KBOX-25 hostplat denies by name account-key-create, access-token, id-token and hmac-key-create: every sample is 400 or 403 with no upstream call, default and widened', async (t) => {
  assert.deepEqual(hostProfile.mustDeny.map((d) => d.id), ['account-key-create', 'access-token', 'id-token', 'hmac-key-create']);
  assert.deepEqual(await leaks(t, hostProfile), []);
  assert.deepEqual(await leaks(t, widened(hostProfile)), []);
});

test('KBOX-25 positive control: the harness reports the samples a leaky profile lets through', async (t) => {
  const forgetful: RelayProfile = { ...leakyProfile, platform: 'pathplat', mustDeny: pathProfile.mustDeny.filter((d) => d.id === 'login-token') };
  const through = await leaks(t, forgetful, pathProfile.mustDeny);
  assert.deepEqual([...new Set(through.map((s) => s.split(' ')[0]))], ['admin-key-create', 'project-key-create', 'service-account-create']);
});
