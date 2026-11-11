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
import { seededRandom } from './kit/index.ts';
import { hostProfile, leakyProfile, pathProfile } from './fixtures/profiles.ts';
import { PATH_HOST, variants } from './fixtures/profiles.ts';

const failure = (entries: readonly PlatformEntry[]): string => {
  const result = checkRegistry(entries);
  return result.ok ? 'passed' : `${result.code} ${result.platform}`;
};

const relayWith = (patch: Partial<RelayProfile>): PlatformEntry => ({ id: 'broken', relay: { ...pathProfile, platform: 'broken', ...patch } });

test('KBOX-23 the real registry passes, and so do the two test profiles', () => {
  assert.equal(failure(REGISTRY), 'passed');
  assert.equal(failure([...REGISTRY, { id: 'pathplat', relay: pathProfile }, { id: 'hostplat', relay: hostProfile }]), 'passed');
});

test('KBOX-23 a relay profile with an empty mustDeny fails, naming the platform', () => {
  assert.equal(failure([relayWith({ mustDeny: [] })]), 'no_must_deny broken');
  assert.equal(failure([relayWith({ mustDeny: [{ id: 'x', samples: [] }] })]), 'no_must_deny broken');
});

test('KBOX-23 an allow rule that matches a mustDeny sample fails', () => {
  assert.equal(failure([{ id: 'leaky', relay: leakyProfile }]), 'allow_matches_must_deny leaky');
});

const leakyAllow = { id: 'org-anything', method: 'POST', host: PATH_HOST, pathTemplate: '/v1/organization/{rest:**}', query: {} } as const;
/** The leaky profile with its mustDeny list replaced by `samples`: a regression list that has to find the leak. */
const leakWith = (samples: readonly SampleRequest[]): PlatformEntry => ({
  id: 'leaky',
  relay: { ...pathProfile, platform: 'leaky', allow: [...pathProfile.allow, leakyAllow], tailRules: [...pathProfile.tailRules, 'org-anything'], mustDeny: [{ id: 'admin-key-create', samples }] },
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
  const deny = (samples: readonly SampleRequest[]): PlatformEntry => ({ id: 'vercel', denyOnly: [{ id: 't', samples }] });
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
  assert.equal(failure([{ id: 'vercel', denyOnly: pathProfile.mustDeny }]), 'passed');
  assert.equal(failure([{ id: 'vercel', relay: { ...pathProfile, platform: 'vercel' }, denyOnly: pathProfile.mustDeny }]), 'deny_only_with_relay vercel');
  assert.equal(failure([{ id: 'elevenlabs' }]), 'deny_only_without_must_deny elevenlabs');
  assert.equal(failure([{ id: 'elevenlabs', denyOnly: [] }]), 'deny_only_without_must_deny elevenlabs');
});

test('KBOX-23 an issuer with revealOnce exports a lister', () => {
  const issuer = new FakePlatformWorld(seededRandom(1)).issuer;
  assert.equal(issuer.capabilities().revealOnce, true);
  assert.equal(failure([{ id: 'reveal', issuer }]), 'reveal_once_without_lister reveal');
  assert.equal(failure([{ id: 'reveal', issuer, lister: { list: () => Promise.resolve([]), listAt: (at) => Promise.resolve({ complete: true, at, keys: [] }) } }]), 'passed');
});

test('KBOX-23 two entries with the same id, or an entry whose relay profile names another platform, fail', () => {
  assert.equal(failure([{ id: 'pathplat', relay: pathProfile }, { id: 'pathplat', relay: pathProfile }]), 'duplicate_platform pathplat');
  assert.equal(failure([{ id: 'other', relay: pathProfile }]), 'platform_mismatch other');
});

test('KBOX-23 startup refuses a failing registry with a fixed message naming the code and the platform', () => {
  assert.throws(() => assertRegistry([{ id: 'leaky', relay: leakyProfile }]), (e: unknown) => e instanceof RegistryRefused && e.message === 'registry check failed: allow_matches_must_deny (leaky)');
  assert.doesNotThrow(() => assertRegistry(REGISTRY));
});
