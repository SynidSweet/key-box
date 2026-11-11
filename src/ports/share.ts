// KBOX-33: what the share writer needs from outside. The source holds the keys it fingerprints; the signing key store holds the
// writer's own Ed25519 seed; the value reader gives a stored value as text. None of them names a path: the adapters that sit on the
// key store implement them (src/shell/core.ts).
import type { ShareKey } from '../pure/share-build.ts';

/** Every current and retired generation of every admin and master key, one entry each. */
export interface ShareSource {
  keys(): Promise<readonly ShareKey[]>;
}

/** The share signing key: a 32-byte Ed25519 seed, kept as a master value. */
export interface ShareSigningKey {
  /** The seed, or null when none has been made. A seed that cannot be read is a fixed `ShareError`. */
  read(): Promise<Uint8Array | null>;
  /** Stores the seed. */
  create(seed: Uint8Array): void;
}

/** A stored value as UTF-8 text, or '' when there is none or it is not text. Other failures are fixed errors. */
export interface ShareValues {
  text(keyref: string, gen: number): Promise<string>;
}
