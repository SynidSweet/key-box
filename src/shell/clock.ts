// The real clock and timers: the one place that reads the time or sets a timer.
import type { Clock, Scheduler } from '../ports/clock.ts';

export const systemClock: Clock = { now: () => Date.now() };

export const systemScheduler: Scheduler = {
  after(ms: number, fn: () => void): () => void {
    const timer = setTimeout(fn, ms);
    return () => clearTimeout(timer);
  },
};
