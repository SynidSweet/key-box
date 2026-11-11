// Time comes in through these ports; core code never reads a clock (KBOX-28).
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
}

/** Runs a function after a delay. The call returns a function that cancels it. */
export interface Scheduler {
  after(ms: number, fn: () => void): () => void;
}
