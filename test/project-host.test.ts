// KBOX-13, KBOX-47, KBOX-57: a relay origin of the kind `project-host` is one host per key, `<ref>.<domain>`, the ref being the key's own
// project. The helper, the profile engine and the egress gate each hold the same line: exactly that host, never a wildcard grant.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Origin, RelayProfile } from '../src/ports/relay-profile.ts';
import { hostVerdict } from '../src/pure/egress-policy.ts';
import { checkRegistry, compileProfile } from '../src/pure/profile.ts';
import { projectHostOf, projectOfHost, projectOriginsOf, projectRuleHost } from '../src/pure/project-host.ts';
import { parseRelayTarget } from '../src/pure/target-parse.ts';
import { NO_ISSUER_CLASSIFY, NO_ISSUER_SHAPE, PROJECT_REGISTRY, PROJECT_RULE_HOST, pathProfile, projectProfile } from './fixtures/profiles.ts';

const ORIGIN = { kind: 'project-host', domain: 'projplat.example', refLength: 8 } as const satisfies Origin;
const REF = 'abcdefgh';

test('KBOX-13 a project ref is exactly refLength lower-case letters and gives the host <ref>.<domain>', () => {
  assert.equal(projectHostOf(ORIGIN, REF), 'abcdefgh.projplat.example');
  for (const bad of ['abcdefg', 'abcdefghi', 'abcdefgH', 'abcdefg1', 'abcdefg.', '', 'abcdefg/', 'abcdefg-']) assert.equal(projectHostOf(ORIGIN, bad), undefined, bad);
});

test('KBOX-13 a host is a project host only when it is one label of refLength letters directly under the domain', () => {
  assert.equal(projectOfHost(ORIGIN, 'abcdefgh.projplat.example'), REF);
  for (const bad of ['projplat.example', 'a.abcdefgh.projplat.example', 'abcdefgh.projplat.example.evil.example', 'abcdefghi.projplat.example', 'abcdefgh.xprojplat.example', 'ABCDEFGH.projplat.example', 'abcdefgh.projplat.example.'])
    assert.equal(projectOfHost(ORIGIN, bad), undefined, bad);
});

const profile = (allowHost: string): RelayProfile => ({
  ...pathProfile,
  platform: 'projplat',
  origin: ORIGIN,
  allow: [{ id: 'things', method: 'GET', host: allowHost, pathTemplate: '/v1/things', query: {} }],
  tailRules: [],
});

function decide(p: RelayProfile, project: string | undefined, path = '/r/key001/v1/things'): string {
  const compiled = compileProfile(p);
  if (!compiled.ok) return `compile ${compiled.code}`;
  const target = parseRelayTarget(path);
  if (!target.ok) return `parse ${target.code}`;
  const decided = compiled.engine.decide('GET', target.value, project);
  return decided.ok ? `${decided.rule.id} ${decided.request.upstream}` : decided.code;
}

test('KBOX-13 the engine sends a request to the key own project host and to no other', () => {
  assert.equal(decide(profile(projectRuleHost(ORIGIN)), REF), 'things abcdefgh.projplat.example');
  assert.equal(decide(profile(projectRuleHost(ORIGIN)), 'zyxwvuts'), 'things zyxwvuts.projplat.example');
});

test('KBOX-13 a key with no project, or a project that is not a ref, is forbidden, and so is a ref carried in the path', () => {
  assert.equal(decide(profile(projectRuleHost(ORIGIN)), undefined), 'forbidden');
  assert.equal(decide(profile(projectRuleHost(ORIGIN)), 'abc'), 'forbidden');
  assert.equal(decide(profile(projectRuleHost(ORIGIN)), REF, `/r/key001/${REF}.projplat.example/v1/things`), 'forbidden');
});

test('KBOX-23 a profile whose allow rule names a concrete host, or whose origin is malformed, fails to compile with bad_host', () => {
  assert.equal(decide(profile('abcdefgh.projplat.example'), REF), 'compile bad_host');
  assert.equal(decide({ ...profile(projectRuleHost(ORIGIN)), origin: { ...ORIGIN, refLength: 0 } }, REF), 'compile bad_host');
  assert.equal(decide({ ...profile(projectRuleHost(ORIGIN)), origin: { ...ORIGIN, domain: 'Bad Domain' } }, REF), 'compile bad_host');
});

test('KBOX-47 the gate lets a relay call reach one ref label under a declared project domain, and nothing wider', () => {
  const verdict = (caller: 'relay' | 'adapter', host: string): string => hostVerdict(caller, host, [], [], [], [ORIGIN]);
  assert.equal(verdict('relay', 'abcdefgh.projplat.example'), 'allowed');
  for (const bad of ['projplat.example', 'a.abcdefgh.projplat.example', 'abcdefghi.projplat.example', 'abcdefgh.projplat.example.evil.example', 'abcdefgh.other.example'])
    assert.equal(verdict('relay', bad), 'undeclared_host', bad);
  assert.equal(verdict('adapter', 'abcdefgh.projplat.example'), 'wrong_caller', 'an adapter call never reaches a project host');
});

test('KBOX-47 projectOriginsOf reads the project domains of the registered relay profiles', () => {
  assert.deepEqual(projectOriginsOf([{ id: 'projplat', relay: profile(projectRuleHost(ORIGIN)), unverified: [] }, { id: 'pathplat', relay: pathProfile, unverified: [] }, { id: 'plain', unverified: [] }]), [ORIGIN]);
});

test('KBOX-23 the project-host fixture registry passes the startup checks, and its mustDeny samples fail them once an allow rule widens onto them', () => {
  assert.deepEqual(checkRegistry(PROJECT_REGISTRY), { ok: true });
  const leaky: RelayProfile = { ...projectProfile, allow: [...projectProfile.allow, { id: 'any-post', method: 'POST', host: PROJECT_RULE_HOST, pathTemplate: '/v1/{rest:**}', query: {} }], tailRules: ['any-post'] };
  assert.deepEqual(checkRegistry([{ id: 'projplat', relay: leaky, shape: NO_ISSUER_SHAPE, classify: NO_ISSUER_CLASSIFY, unverified: [] }]), { ok: false, code: 'allow_matches_must_deny', platform: 'projplat' });
});

test('KBOX-25 a mustDeny request of a project-host profile is denied for every key project, not only the ref its sample names', () => {
  const compiled = compileProfile(projectProfile);
  assert.ok(compiled.ok);
  const target = parseRelayTarget('/r/key001/v1/projects/keys');
  assert.ok(target.ok);
  for (const project of ['abcdefgh', 'zyxwvuts']) assert.equal(compiled.engine.isDenied('POST', target.value, project), true, project);
});
