import type { Clock } from '../../src/ports/clock.ts';

/** Time moves only when a test says so. */
export class FakeClock implements Clock {
  #ms: number;

  constructor(startMs = 0) {
    this.#ms = startMs;
  }

  now(): number {
    return this.#ms;
  }

  advance(ms: number): void {
    if (!(ms >= 0)) throw new RangeError(`FakeClock.advance needs a number of at least 0, got ${ms}`);
    this.#ms += ms;
  }
}
