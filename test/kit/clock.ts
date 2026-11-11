import type { Clock, Scheduler } from '../../src/ports/clock.ts';

interface Timer {
  readonly id: number;
  readonly due: number;
  readonly fn: () => void;
}

/** Time moves only when a test says so; timers set with `after` run, in order, as `advance` passes their due time. */
export class FakeClock implements Clock, Scheduler {
  #ms: number;
  #timers: Timer[] = [];
  #nextId = 1;

  constructor(startMs = 0) {
    this.#ms = startMs;
  }

  now(): number {
    return this.#ms;
  }

  /** How many timers are set and not yet run or cancelled. */
  get pendingTimers(): number {
    return this.#timers.length;
  }

  after(ms: number, fn: () => void): () => void {
    if (!(ms >= 0)) throw new RangeError(`FakeClock.after needs a delay of at least 0, got ${ms}`);
    const timer: Timer = { id: this.#nextId, due: this.#ms + ms, fn };
    this.#nextId += 1;
    this.#timers.push(timer);
    return () => {
      this.#timers = this.#timers.filter((t) => t.id !== timer.id);
    };
  }

  advance(ms: number): void {
    if (!(ms >= 0)) throw new RangeError(`FakeClock.advance needs a number of at least 0, got ${ms}`);
    const target = this.#ms + ms;
    for (;;) {
      const next = this.#timers.filter((t) => t.due <= target).sort((a, b) => a.due - b.due || a.id - b.id)[0];
      if (next === undefined) break;
      this.#timers = this.#timers.filter((t) => t.id !== next.id);
      this.#ms = Math.max(this.#ms, next.due);
      next.fn();
    }
    this.#ms = target;
  }
}
