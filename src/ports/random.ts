// Randomness comes in through this port; core code never draws its own (KBOX-28).
export interface Random {
  /** `n` fresh random bytes. */
  bytes(n: number): Uint8Array;
}
