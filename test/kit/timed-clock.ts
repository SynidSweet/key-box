import type { Scheduler } from '../../src/ports/clock.ts';
import { FakeClock } from './clock.ts';

interface Timer {
  readonly id: number;
  readonly due: number;
  readonly fn: () => void;
}

/** A FakeClock that is also a Scheduler: timers set with `after` run, in due order, as `advance` passes their time. */
export class TimedClock extends FakeClock implements Scheduler {
  #timers: Timer[] = [];
  #nextId = 1;

  /** How many timers are set and not yet run or cancelled. */
  get pendingTimers(): number {
    return this.#timers.length;
  }

  after(ms: number, fn: () => void): () => void {
    if (!(ms >= 0)) throw new RangeError(`TimedClock.after needs a delay of at least 0, got ${ms}`);
    const timer: Timer = { id: this.#nextId, due: this.now() + ms, fn };
    this.#nextId += 1;
    this.#timers.push(timer);
    return () => {
      this.#timers = this.#timers.filter((t) => t.id !== timer.id);
    };
  }

  override advance(ms: number): void {
    if (!(ms >= 0)) throw new RangeError(`TimedClock.advance needs a number of at least 0, got ${ms}`);
    const target = this.now() + ms;
    for (;;) {
      const next = this.#timers.filter((t) => t.due <= target).sort((a, b) => a.due - b.due || a.id - b.id)[0];
      if (next === undefined) break;
      this.#timers = this.#timers.filter((t) => t.id !== next.id);
      super.advance(Math.max(0, next.due - this.now()));
      next.fn();
    }
    super.advance(target - this.now());
  }
}
