// KBOX-52: when a key is due. A schedule, never a cap: at most one admin or master rotation falls due per day, and no due date is
// ever later than the unstaggered one.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkProperty, seedFor } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';
import type { KeyClass } from '../src/ports/types.ts';
import { dueDates, unstaggeredDue } from '../src/pure/scheduler.ts';
import type { SchedKey } from '../src/pure/scheduler.ts';

const DAY = 24 * 3600_000;
const HOUR = 3600_000;
const key = (keyref: string, klass: KeyClass, over: Partial<SchedKey> = {}): SchedKey => ({
  keyref,
  class: klass,
  rotateEveryDays: 90,
  graceHours: 24,
  lastRotatedAt: 0,
  expiresAt: null,
  manual: false,
  ...over,
});

test('KBOX-52 the unstaggered due date is the schedule: the last rotation plus rotateEvery', () => {
  assert.equal(unstaggeredDue(key('k', 'ordinary', { lastRotatedAt: 5 * DAY, rotateEveryDays: 30 })), 35 * DAY);
});

test('KBOX-52 an expiry earlier than the schedule wins: due at expiresAt minus grace minus one day', () => {
  const k = key('k', 'ordinary', { expiresAt: 40 * DAY, graceHours: 24, rotateEveryDays: 90 });
  assert.equal(unstaggeredDue(k), 40 * DAY - 24 * HOUR - DAY);
});

test('KBOX-52 an expiry later than the schedule changes nothing', () => {
  assert.equal(unstaggeredDue(key('k', 'ordinary', { expiresAt: 900 * DAY })), 90 * DAY);
});

test('KBOX-52 two admin keys due the same day: one moves a day earlier, an ordinary key is never moved', () => {
  const due = dueDates([key('a', 'admin'), key('b', 'admin'), key('c', 'ordinary'), key('d', 'master')]);
  const days = ['a', 'b', 'd'].map((r) => Math.floor((due.get(r) ?? Number.NaN) / DAY));
  assert.equal(new Set(days).size, 3);
  assert.equal(due.get('c'), 90 * DAY);
  for (const r of ['a', 'b', 'd']) assert.ok((due.get(r) ?? Infinity) <= 90 * DAY);
});

test('KBOX-52 a manual rotation is never delayed: it is due at once, whatever the schedule', () => {
  const due = dueDates([key('a', 'admin', { manual: true }), key('b', 'admin')], 10 * DAY);
  assert.equal(due.get('a'), 10 * DAY);
  assert.equal(due.get('b'), 90 * DAY);
});

test('KBOX-52 property: at most one admin or master rotation per day, every due date no later than the unstaggered one', () => {
  const seed = seedFor(process.env);
  checkProperty(seed, 200, (rng: SeededRandom) => {
    const keys: SchedKey[] = Array.from({ length: 1 + rng.int(12) }, (_, i) =>
      key(`k${i}`, (['ordinary', 'admin', 'master'] as const)[rng.int(3)] ?? 'ordinary', {
        lastRotatedAt: rng.int(60) * DAY + rng.int(DAY),
        rotateEveryDays: 1 + rng.int(120),
        graceHours: rng.int(72),
        expiresAt: rng.int(2) === 0 ? null : rng.int(200) * DAY,
      }),
    );
    const due = dueDates(keys);
    const privileged = new Set<number>();
    for (const k of keys) {
      const d = due.get(k.keyref);
      assert.ok(d !== undefined && d <= unstaggeredDue(k), `${k.keyref} is due no later than unstaggered`);
      if (k.class === 'ordinary') continue;
      const day = Math.floor(d / DAY);
      assert.ok(!privileged.has(day), `two privileged keys due on day ${day}`);
      privileged.add(day);
    }
  });
});
