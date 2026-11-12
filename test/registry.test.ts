// KBOX-23: the registry checks the box runs at startup, as tests. A fixture platform that breaks one check fails with a fixed
// code naming the platform; the real registry and the test profiles pass.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { RelayProfile } from '../src/ports/relay-profile.ts';
import type { SampleRequest } from '../src/ports/relay-profile.ts';
import { RegistryRefused, assertRegistry, checkRegistry } from '../src/pure/profile.ts';
import { REGISTRY } from '../src/platforms/registry.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { lent, seededRandom } from './kit/index.ts';
import { checkLocation } from '../src/pure/location.ts';
import { boxKeyrefOf, kitFor, verifyTargetOf } from '../src/shell/rotation-ports.ts';
import { API_KEY_SHAPE } from '../src/platforms/google/scope.ts';
import { SIGNING_KEY_SHAPE } from '../src/platforms/google/signing-key.ts';
import { hostProfile, leakyProfile, pathProfile } from './fixtures/profiles.ts';
import { NO_ISSUER_CLASSIFY, NO_ISSUER_SHAPE, PATH_HOST, variants } from './fixtures/profiles.ts';

const failure = (entries: readonly PlatformEntry[]): string => {
  const result = checkRegistry(entries);
  return result.ok ? 'passed' : `${result.code} ${result.platform}`;
};

const relayWith = (patch: Partial<RelayProfile>): PlatformEntry => ({ id: 'broken', relay: { ...pathProfile, platform: 'broken', ...patch }, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] });

test('KBOX-23 the real registry passes, and so do the two test profiles', () => {
  assert.equal(failure(REGISTRY), 'passed');
  assert.equal(failure([...REGISTRY, { id: 'pathplat', relay: pathProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }, { id: 'hostplat', relay: hostProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), 'passed');
});

test('KBOX-23 a relay profile with an empty mustDeny fails, naming the platform', () => {
  assert.equal(failure([relayWith({ mustDeny: [] })]), 'no_must_deny broken');
  assert.equal(failure([relayWith({ mustDeny: [{ id: 'x', samples: [] }] })]), 'no_must_deny broken');
});

test('KBOX-23 an allow rule that matches a mustDeny sample fails', () => {
  assert.equal(failure([{ id: 'leaky', relay: leakyProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), 'allow_matches_must_deny leaky');
});

const leakyAllow = { id: 'org-anything', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/organization/{rest:**}', query: {} } as const;
/** The leaky profile with its mustDeny list replaced by `samples`: a regression list that has to find the leak. */
const leakWith = (samples: readonly SampleRequest[]): PlatformEntry => ({
  id: 'leaky',
  relay: { ...pathProfile, platform: 'leaky', allow: [...pathProfile.allow, leakyAllow], tailRules: [...pathProfile.tailRules, 'org-anything'], mustDeny: [{ id: 'admin-key-create', samples }] },
  shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY,
  unverified: [],
});

test('KBOX-23 a mustDeny rule whose samples are all unparsed canonicalisation variants tests nothing: it fails, so the leak behind it cannot pass startup', () => {
  const real = variants('POST', PATH_HOST, '/v1/organization/admin_api_keys');
  const variantsOnly = real.filter((s) => s.url.includes(';x') || s.url.includes('%2F'));
  assert.equal(failure([leakWith(variantsOnly)]), 'must_deny_untested leaky');
  assert.equal(failure([leakWith(real)]), 'allow_matches_must_deny leaky', 'positive control: the real samples find the leak');
});

test('KBOX-23 a mustDeny sample with a typo host, an http scheme or a lower-case method fails registration instead of being skipped', () => {
  const real = variants('POST', PATH_HOST, '/v1/organization/admin_api_keys');
  const typoHost = real.map((s) => ({ ...s, url: s.url.replace(PATH_HOST, 'api.pathplat.exampl') }));
  const http = real.map((s) => ({ ...s, url: s.url.replace('https://', 'http://') }));
  const lowerMethod = real.map((s) => ({ ...s, method: s.method.toLowerCase() }));
  for (const [name, samples] of [['typo host', typoHost], ['http scheme', http], ['lower-case method', lowerMethod]] as const) {
    assert.equal(failure([leakWith(samples)]), 'must_deny_sample_unparsed leaky', name);
  }
  assert.equal(failure([leakWith([...real, { method: 'POST', url: 'https://api.pathplat.exampl/v1/x' }])]), 'must_deny_sample_unparsed leaky', 'one bad sample among good ones');
});

test('KBOX-23 a denyOnly list is held to the same rule: a sample with an http scheme, a lower-case method or no host fails', () => {
  const good = variants('POST', 'api.vercel.example', '/v1/tokens');
  const deny = (samples: readonly SampleRequest[]): PlatformEntry => ({ id: 'vercel', denyOnly: [{ id: 't', samples }], shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] });
  assert.equal(failure([deny(good)]), 'passed');
  assert.equal(failure([deny(good.map((s) => ({ ...s, url: s.url.replace('https://', 'http://') })))]), 'must_deny_sample_unparsed vercel');
  assert.equal(failure([deny(good.map((s) => ({ ...s, method: 'post' })))]), 'must_deny_sample_unparsed vercel');
  assert.equal(failure([deny([{ method: 'POST', url: 'https:///v1/tokens' }])]), 'must_deny_sample_unparsed vercel');
  assert.equal(failure([deny(good.filter((s) => s.url.includes(';x')))]), 'must_deny_untested vercel');
});

test('KBOX-23 a profile listing Range or If-Range, in any case, fails', () => {
  for (const header of ['range', 'if-range', 'Range', 'IF-RANGE']) {
    assert.equal(failure([relayWith({ requestHeaders: [...pathProfile.requestHeaders, header] })]), 'partial_content_header broken', header);
  }
});

test('KBOX-23 a profile forwarding a header the relay owns (the pass, cookies, framing, method override, client address) fails', () => {
  for (const header of ['authorization', 'apikey', 'cookie', 'host', 'content-length', 'transfer-encoding', 'te', 'trailer', 'connection', 'upgrade', 'accept-encoding', 'x-http-method-override', 'x-http-method', 'x-method-override', 'x-forwarded-for', 'forwarded', 'x-real-ip', 'x-kb-client-ip', 'proxy-authorization', 'x-agent', 'x-project']) {
    assert.equal(failure([relayWith({ requestHeaders: [header] })]), 'relay_owned_header broken', header);
  }
  assert.equal(failure([relayWith({ responseHeaders: ['set-cookie'] })]), 'relay_owned_header broken');
  assert.equal(failure([relayWith({ responseHeaders: ['content-range'] })]), 'relay_owned_header broken');
  assert.equal(failure([relayWith({ responseHeaders: ['content-encoding'] })]), 'relay_owned_header broken');
});

test('KBOX-23 a host that is not a plain lower-case name, or a rule on a host the profile does not declare, fails', () => {
  for (const host of ['API.example', 'api.example.', 'api.example:443', 'u@api.example', 'api%2Eexample', '']) {
    assert.equal(failure([relayWith({ origin: { kind: 'fixed', host } })]), 'bad_host broken', host);
  }
  assert.equal(failure([relayWith({ origin: { kind: 'fixed', host: 'other.example' } })]), 'bad_host broken');
});

test('KBOX-23 a malformed template or an unnamed tail fails with its compile code', () => {
  assert.equal(failure([relayWith({ allow: [{ id: 'x', method: 'GET', host: 'api.pathplat.example', pathTemplate: '/v1/{id}', query: {} }] })]), 'bad_template broken');
  assert.equal(failure([relayWith({ tailRules: [] })]), 'tail_not_named broken');
});

test('KBOX-23 a platform in relayDenyOnly must export a mustDeny list and no relay profile', () => {
  assert.equal(failure([{ id: 'vercel', denyOnly: pathProfile.mustDeny, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), 'passed');
  assert.equal(failure([{ id: 'vercel', relay: { ...pathProfile, platform: 'vercel' }, denyOnly: pathProfile.mustDeny, unverified: [] }]), 'deny_only_with_relay vercel');
  assert.equal(failure([{ id: 'elevenlabs', unverified: [] }]), 'deny_only_without_must_deny elevenlabs');
  assert.equal(failure([{ id: 'elevenlabs', denyOnly: [], unverified: [] }]), 'deny_only_without_must_deny elevenlabs');
});

test('KBOX-23 an issuer with revealOnce exports a lister', () => {
  const issuer = new FakePlatformWorld(seededRandom(1)).issuer;
  assert.equal(issuer.capabilities().revealOnce, true);
  assert.equal(failure([{ id: 'reveal', issuer, unverified: [] }]), 'reveal_once_without_lister reveal');
  assert.equal(failure([{ id: 'reveal', issuer, lister: { list: () => Promise.resolve([]), listAt: (at) => Promise.resolve({ complete: true, at, keys: [] }) }, unverified: [] }]), 'passed');
});

test('KBOX-23 two entries with the same id, or an entry whose relay profile names another platform, fail', () => {
  assert.equal(failure([{ id: 'pathplat', relay: pathProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }, { id: 'pathplat', relay: pathProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), 'duplicate_platform pathplat');
  assert.equal(failure([{ id: 'other', relay: pathProfile, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), 'platform_mismatch other');
});

test('KBOX-23 startup refuses a failing registry with a fixed message naming the code and the platform', () => {
  assert.throws(() => assertRegistry([{ id: 'leaky', relay: leakyProfile, unverified: [] }]), (e: unknown) => e instanceof RegistryRefused && e.message === 'registry check failed: allow_matches_must_deny (leaky)');
  assert.doesNotThrow(() => assertRegistry(REGISTRY));
});

// --- KBOX-59 and KBOX-58: the Google entry's place in the registry --------------------------------------------------------------------

const googleEntry = (): PlatformEntry => {
  const found = REGISTRY.find((e) => e.id === 'google');
  assert.ok(found !== undefined);
  return found;
};

test('KBOX-58 only the Google verifier needs the master, and through verifyTargetOf no other entry\'s verifier is handed one', () => {
  const master = lent(Buffer.from('a master'), 'master');
  const target = { platform: 'x', at: {} };
  assert.deepEqual(REGISTRY.filter((e) => e.verifier?.needsMaster === true).map((e) => e.id), ['google']);
  for (const entry of REGISTRY) {
    if (entry.verifier === undefined) continue;
    assert.equal(Object.hasOwn(verifyTargetOf(entry.verifier, target, master), 'master'), entry.id === 'google', entry.id);
    assert.equal(Object.hasOwn(verifyTargetOf(entry.verifier, target, undefined), 'master'), false, `${entry.id}: a master that was not chosen is never made up`);
  }
});

test('KBOX-59 KBOX-47 the Google entry\'s own calls reach exactly the three hosts of the identity half and the API Keys and Secret Manager hosts', () => {
  assert.deepEqual([...(googleEntry().hosts ?? [])].sort(), ['apikeys.googleapis.com', 'cloudresourcemanager.googleapis.com', 'iamcredentials.googleapis.com', 'secretmanager.googleapis.com', 'sts.googleapis.com']);
  assert.ok(googleEntry().unverified.includes('google.apikeys-create-answer') && googleEntry().unverified.includes('google.apikey-verify-call'));
});

test('KBOX-57 KBOX-59 the Google entry declares the location `project` only: a project id, required of an ordinary key, naming no host, proven by no prover', () => {
  const { location, locationProver } = googleEntry();
  assert.deepEqual(Object.keys(location ?? {}), ['project']);
  assert.deepEqual(location?.project?.requiredFor, ['ordinary']);
  assert.equal(location?.project?.namesHost, undefined);
  assert.equal(locationProver, undefined);
  const items = ['api:firestore.googleapis.com'];
  assert.equal(checkLocation(location, { project: 'p-proj1' }, 'ordinary', items), 'ok');
  assert.equal(checkLocation(location, {}, 'ordinary', items), 'location_missing');
  for (const project of ['P1', 'p1', 'p-proj1/x', 'projects/p-proj1', '']) assert.equal(checkLocation(location, { project }, 'ordinary', items), 'location_bad_value', project);
  assert.equal(checkLocation(location, { region: 'global' }, 'ordinary', items), 'location_field_unknown');
  assert.equal(checkLocation(location, { project: 'p-proj1' }, 'ordinary', ['project:p-proj1']), 'location_in_scope');
});

test('KBOX-55 KBOX-59 the API-key issuer classifies no scope master and the entry states no class or shape of its own; the box key keeps master and its shape through kitFor, every other Google keyref gets the issuer', () => {
  const entry = googleEntry();
  assert.equal(entry.shape, undefined);
  assert.equal(entry.classify, undefined);
  assert.ok(entry.issuer !== undefined && entry.boxKey !== undefined);
  for (const items of [[], ['master'], ['admin'], ['api:firestore.googleapis.com'], ['sa:p-proj1/acct1x']]) {
    for (const at of [{}, { project: 'p-proj1' }]) assert.equal(entry.issuer.capabilities().classify({ items }, at), 'ordinary', JSON.stringify(items));
  }
  const source = { platform: (id: string) => REGISTRY.find((e) => e.id === id) };
  const box = kitFor(source, { platform: 'google', keyref: boxKeyrefOf('google', entry.boxKey) });
  assert.equal(box?.issuer, undefined);
  assert.deepEqual(box?.shape, SIGNING_KEY_SHAPE);
  assert.equal(box?.classify?.({ items: [] }, { project: 'p-proj1' }), 'master');
  const api = kitFor(source, { platform: 'google', keyref: 'google/p-proj1/GEMINI_KEY' });
  assert.equal(api?.issuer, entry.issuer);
  assert.equal(api?.boxKey, undefined);
  assert.deepEqual(api?.issuer?.capabilities().shape, API_KEY_SHAPE);
});

test('KBOX-16 KBOX-59 the Google entry provides the Secret Manager destination, readable by the API (ordinary keys only), and no redeployer', () => {
  const kits = googleEntry().destinations ?? [];
  assert.deepEqual(kits.map((k) => k.destination.kind), ['google-secret-manager']);
  assert.equal(kits[0]?.redeployer, undefined);
  assert.equal(kits[0]?.destination.properties().readableBy, 'api');
});
