// The real randomness: the one place that draws from the operating system.
import { randomBytes } from 'node:crypto';
import type { Random } from '../ports/random.ts';

export const systemRandom: Random = { bytes: (n: number) => Uint8Array.from(randomBytes(n)) };
