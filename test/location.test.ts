// KBOX-57: a key's one stored location, checked against the fields its registry entry declares; KBOX-15: a location may raise a class and
// never lower it. Pure: a fixture schema, no platform.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { KeyClass, KeyLocation, LocationRule, LocationSchema } from '../src/ports/types.ts';
import { flooredClass } from '../src/pure/class.ts';
import { checkLocation, sameLocation } from '../src/pure/location.ts';

const RANK: readonly KeyClass[] = ['ordinary', 'admin', 'master'];

/** A fixture entry: `region` from a closed list required of every class, `project` a 20-letter ref required of ordinary and admin keys. */
const REGION: LocationRule = { pattern: /^(global|us)$/, requiredFor: ['ordinary', 'admin', 'master'] };
const PROJECT: LocationRule = { pattern: /[a-z]{20}/, requiredFor: ['ordinary', 'admin'] };
const SCHEMA: LocationSchema = { region: REGION, project: PROJECT };
const REF = 'abcdefghijabcdefghij';

test('KBOX-57 a location naming each declared field with an accepted value, as the class requires, is ok', () => {
  assert.equal(checkLocation(SCHEMA, { region: 'us', project: REF }, 'ordinary', ['read']), 'ok');
  assert.equal(checkLocation(SCHEMA, { region: 'global' }, 'master', ['service-account:sa-1']), 'ok', 'project is not required of a master');
});

test('KBOX-57 a field the entry does not declare is location_field_unknown, and an entry that declares none takes no location', () => {
  assert.equal(checkLocation({ region: REGION }, { region: 'us', project: REF }, 'ordinary', []), 'location_field_unknown');
  assert.equal(checkLocation(undefined, { region: 'us' }, 'ordinary', []), 'location_field_unknown');
  assert.equal(checkLocation({}, { project: REF }, 'ordinary', []), 'location_field_unknown');
  assert.equal(checkLocation(undefined, {}, 'master', []), 'ok', 'no declaration and no location');
});

test('KBOX-57 a value the pattern refuses is location_bad_value, and the pattern must match the whole value even when it is not anchored', () => {
  assert.equal(checkLocation(SCHEMA, { region: 'mars', project: REF }, 'ordinary', []), 'location_bad_value');
  assert.equal(checkLocation(SCHEMA, { region: 'us', project: `x${REF}` }, 'ordinary', []), 'location_bad_value', 'one character before the match');
  assert.equal(checkLocation(SCHEMA, { region: 'us', project: `${REF}x` }, 'ordinary', []), 'location_bad_value', 'one character after the match');
  assert.equal(checkLocation(SCHEMA, { region: 'us', project: REF.slice(1) }, 'ordinary', []), 'location_bad_value', 'one character short');
});

test('KBOX-57 a field the class must name and the location lacks is location_missing, for that class only', () => {
  assert.equal(checkLocation(SCHEMA, { region: 'us' }, 'ordinary', []), 'location_missing');
  assert.equal(checkLocation(SCHEMA, { region: 'us' }, 'admin', []), 'location_missing');
  assert.equal(checkLocation(SCHEMA, { region: 'us' }, 'master', []), 'ok');
  assert.equal(checkLocation(SCHEMA, {}, 'master', []), 'location_missing', 'region is required of every class');
});

test('KBOX-57 a region: or project: scope item on an entry that declares that field is location_in_scope; on one that does not, the item is the adapter\'s', () => {
  const at: KeyLocation = { region: 'us', project: REF };
  assert.equal(checkLocation(SCHEMA, at, 'ordinary', ['read', `project:${REF}`]), 'location_in_scope');
  assert.equal(checkLocation(SCHEMA, at, 'ordinary', ['region:us']), 'location_in_scope');
  assert.equal(checkLocation({ project: PROJECT }, { project: REF }, 'ordinary', ['region:us']), 'ok', 'region is not declared, so region: is not placement here');
  assert.equal(checkLocation(SCHEMA, at, 'ordinary', ['regional', 'projects']), 'ok', 'only the prefix with its colon is placement');
});

test('KBOX-57 the same location is field for field over the fields either names: a field on one side only is a difference', () => {
  assert.equal(sameLocation({ region: 'us', project: REF }, { project: REF, region: 'us' }), true);
  assert.equal(sameLocation({}, {}), true);
  assert.equal(sameLocation({ project: REF }, { project: 'zzzzzzzzzzzzzzzzzzzz' }), false);
  assert.equal(sameLocation({ project: REF }, {}), false, 'the answer lacks a field at names');
  assert.equal(sameLocation({}, { region: 'us' }), false, 'the answer names a field at lacks');
});

test('KBOX-15 the class is the highest of the bare classification, the placed one and the mark, for all 27 triples: a location never lowers it', () => {
  for (const [i, bare] of RANK.entries()) {
    for (const [j, placed] of RANK.entries()) {
      for (const [k, mark] of RANK.entries()) assert.equal(flooredClass(bare, placed, mark), RANK[Math.max(i, j, k)]);
      assert.equal(flooredClass(bare, placed, undefined), RANK[Math.max(i, j)]);
    }
  }
});
