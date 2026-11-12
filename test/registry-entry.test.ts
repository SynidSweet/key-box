// KBOX-23, KBOX-40: the registry checks that concern an entry as a whole (not its relay profile): the one source of a shape, the destination
// kinds, the deny-only list. Each fixture that breaks one check fails with a fixed code naming the platform.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { KeyShape } from '../src/ports/types.ts';
import { checkRegistry } from '../src/pure/profile.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { fakeEntry, pasteOnlyEntry } from './fakes/platform-entry.ts';
import { RecordingDestination } from './fakes/recording-destination.ts';
import { pathProfile } from './fixtures/profiles.ts';
import { seededRandom } from './kit/index.ts';

const SHAPE: KeyShape = { prefix: 'po-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };
const w = new FakePlatformWorld(seededRandom(4));
const failure = (entries: readonly PlatformEntry[]): string => {
  const result = checkRegistry(entries);
  return result.ok ? 'passed' : `${result.code} ${result.platform}`;
};

test('KBOX-23 an entry with an issuer, and a paste-only entry that states its shape, pass', () => {
  assert.equal(failure([fakeEntry(w), pasteOnlyEntry(w, SHAPE)]), 'passed');
});

test('KBOX-23 a shape stated next to an issuer (two sources) fails, and so does neither', () => {
  assert.equal(failure([fakeEntry(w, { shape: SHAPE })]), 'shape_twice fake');
  assert.equal(failure([{ id: 'pasteonly', verifier: w.verifier, unverified: [] }]), 'shape_missing pasteonly');
});

test('KBOX-23 two entries with one id fail, and an issuer that reveals once without a lister fails', () => {
  assert.equal(failure([fakeEntry(w), fakeEntry(w)]), 'duplicate_platform fake');
  assert.equal(failure([{ id: 'fake', issuer: w.issuer, unverified: [] }]), 'reveal_once_without_lister fake');
});

test('KBOX-23 a destination kind that two entries provide fails, naming the second; one entry giving a kind twice fails too', () => {
  const kit = { destination: new RecordingDestination([]) };
  assert.equal(failure([fakeEntry(w, { id: 'one', destinations: [kit] }), fakeEntry(w, { id: 'two', destinations: [kit] })]), 'destination_twice two');
  assert.equal(failure([fakeEntry(w, { destinations: [kit, kit] })]), 'destination_twice fake');
  assert.equal(failure([fakeEntry(w, { id: 'one', destinations: [kit] }), fakeEntry(w, { id: 'two' })]), 'passed');
});

test('KBOX-23 relay and denyOnly together fail on any platform, and denyOnly is allowed only for the platforms the list names', () => {
  assert.equal(failure([fakeEntry(w, { relay: { ...pathProfile, platform: 'fake' }, denyOnly: pathProfile.mustDeny })]), 'deny_only_with_relay fake');
  assert.equal(failure([fakeEntry(w, { denyOnly: pathProfile.mustDeny })]), 'deny_only_not_listed fake');
});

test('KBOX-23 KBOX-40 the class has one source: an entry with an issuer states no classify, one without states its own; two sources or none fail', () => {
  assert.equal(failure([fakeEntry(w, { classify: () => 'ordinary' })]), 'classify_twice fake');
  assert.equal(failure([{ id: 'pasteonly', verifier: w.verifier, shape: SHAPE, unverified: [] }]), 'classify_missing pasteonly');
  assert.equal(failure([pasteOnlyEntry(w, SHAPE)]), 'passed');
});

test('KBOX-23 KBOX-57 an entry\'s location declares only region and project: another field fails, naming the platform', () => {
  const rule = { pattern: /[a-z]{1,8}/, requiredFor: [] };
  assert.equal(failure([fakeEntry(w, { location: { region: rule, project: rule } })]), 'passed');
  assert.equal(failure([fakeEntry(w, { location: {} })]), 'passed', 'an entry may declare none');
  const zoned = { region: rule, zone: rule } as unknown as PlatformEntry['location'];
  assert.equal(failure([fakeEntry(w, { location: zoned })]), 'location_field_unknown fake');
});
