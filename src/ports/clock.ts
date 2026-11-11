// Time comes in through this port; core code never reads a clock (KBOX-28).
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
}
