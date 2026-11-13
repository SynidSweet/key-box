import type { KeyRef, Lent } from './types.ts';

export interface Vault {
  put(ref: KeyRef, gen: number, v: Uint8Array): void;
  /** Throws for a ref and generation that is unknown or retired. */
  lend(ref: KeyRef, gen: number): Lent;
  retire(ref: KeyRef, gen: number): void;
  /** KBOX-62: every generation of the ref the vault holds, ascending, whether or not a row names it (a crash between a put and its row leaves one). */
  generations(ref: KeyRef): readonly number[];
}
