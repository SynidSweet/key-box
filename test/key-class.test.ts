// KBOX-15 and KBOX-16: a key's class is computed and never lowered by a caller; admin and master keys go only to runtime destinations.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { KeyClass, KeyShape } from '../src/ports/types.ts';
import { admitDestination, classOf, matchesShape, raiseClass } from '../src/pure/class.ts';

const RANK: readonly KeyClass[] = ['ordinary', 'admin', 'master'];

test('KBOX-15 the class is the higher of the adapter classification and the owner mark, in all nine pairs', () => {
  for (const [i, adapter] of RANK.entries()) {
    for (const [j, mark] of RANK.entries()) assert.equal(classOf(adapter, mark), RANK[Math.max(i, j)]);
  }
});

test('KBOX-15 no mark leaves the adapter class as it is', () => {
  for (const adapter of RANK) assert.equal(classOf(adapter, undefined), adapter);
});

test('KBOX-15 mark_admin raises an ordinary key and a request to lower is refused', () => {
  assert.deepEqual(raiseClass('ordinary', 'admin'), { ok: true, class: 'admin' });
  assert.deepEqual(raiseClass('admin', 'admin'), { ok: true, class: 'admin' });
  assert.deepEqual(raiseClass('admin', 'ordinary'), { ok: false });
  assert.deepEqual(raiseClass('master', 'admin'), { ok: false });
});

test('KBOX-16 a destination readable by the api is refused for admin and master and accepted for ordinary', () => {
  assert.equal(admitDestination('ordinary', 'api'), true);
  assert.equal(admitDestination('ordinary', 'runtime'), true);
  assert.equal(admitDestination('admin', 'runtime'), true);
  assert.equal(admitDestination('admin', 'api'), false);
  assert.equal(admitDestination('master', 'api'), false);
  assert.equal(admitDestination('master', 'runtime'), true);
});

const hexShape: KeyShape = { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 8, max: 8 }, random: true };

test('KBOX-12 the strict shape check: prefix, core alphabet and core length, each at and beside its boundary', () => {
  assert.equal(matchesShape(hexShape, 'fk-0123abcd'), true);
  assert.equal(matchesShape(hexShape, 'fx-0123abcd'), false, 'wrong prefix');
  assert.equal(matchesShape(hexShape, 'fk-0123abc'), false, 'core one short');
  assert.equal(matchesShape(hexShape, 'fk-0123abcde'), false, 'core one long');
  assert.equal(matchesShape(hexShape, 'fk-0123abcg'), false, 'a character outside the alphabet');
  assert.equal(matchesShape(hexShape, ' fk-0123abcd'), false, 'a leading space');
  assert.equal(matchesShape(hexShape, 'fk-0123abcd\n'), false, 'a trailing newline');
  assert.equal(matchesShape({ ...hexShape, prefix: null }, '0123abcd'), true);
  assert.equal(matchesShape({ ...hexShape, alphabet: 'base64url', coreLength: { min: 3, max: 6 } }, 'fk-a_-'), true);
  assert.equal(matchesShape({ ...hexShape, alphabet: 'base62', coreLength: { min: 3, max: 6 } }, 'fk-a_-'), false);
});
