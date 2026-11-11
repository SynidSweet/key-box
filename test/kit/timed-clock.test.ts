// The kit's own behaviour, tested where it is tricky (KBOX-35): timers of the clock the long poll runs on (KBOX-31).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TimedClock } from './timed-clock.ts';

test('KBOX-31 TimedClock timers run in due order as time passes, a timer set by a timer runs, a cancelled one never does', () => {
  const clock = new TimedClock(1000);
  const ran: string[] = [];
  clock.after(300, () => ran.push('c'));
  clock.after(100, () => {
    ran.push('a');
    clock.after(50, () => ran.push('b'));
  });
  const cancel = clock.after(200, () => ran.push('never'));
  cancel();
  assert.equal(clock.pendingTimers, 2);
  clock.advance(99);
  assert.deepEqual(ran, []);
  clock.advance(1);
  assert.deepEqual(ran, ['a']);
  assert.equal(clock.now(), 1100);
  clock.advance(500);
  assert.deepEqual(ran, ['a', 'b', 'c']);
  assert.equal(clock.now(), 1600);
  assert.equal(clock.pendingTimers, 0);
  assert.throws(() => clock.after(-1, () => undefined), RangeError);
  assert.throws(() => clock.advance(-1), RangeError);
});

test('KBOX-31 a timer sees the time it was due at while the clock is still advancing, and the clock ends at the target', () => {
  const clock = new TimedClock(0);
  const seen: number[] = [];
  clock.after(40, () => seen.push(clock.now()));
  clock.after(10, () => seen.push(clock.now()));
  clock.advance(100);
  assert.deepEqual(seen, [10, 40]);
  assert.equal(clock.now(), 100);
});
