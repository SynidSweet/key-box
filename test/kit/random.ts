import { randomBytes } from 'node:crypto';

export interface SeededRandom {
  readonly seed: number;
  /** A float in [0, 1). */
  next(): number;
  /** An integer in [0, n). */
  int(n: number): number;
  bytes(n: number): Uint8Array;
}

/** mulberry32: small, fast and the same on every machine. */
export function seededRandom(seed: number): SeededRandom {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number): number => Math.floor(next() * n);
  const bytes = (n: number): Uint8Array => Uint8Array.from({ length: n }, () => int(256));
  return { seed, next, int, bytes };
}

const drawSeed = (): number => randomBytes(4).readUInt32BE(0);
const printSeed = (seed: number): void => {
  process.stderr.write(`KB_SEED=${seed}\n`);
};

/** The seed of a property test: `KB_SEED` when set, else a fresh draw. Always reported. */
export function seedFor(
  env: Readonly<Record<string, string | undefined>>,
  draw: () => number = drawSeed,
  report: (seed: number) => void = printSeed,
): number {
  const raw = env['KB_SEED'];
  let seed: number;
  if (raw === undefined) {
    seed = draw();
  } else {
    if (!/^\d+$/.test(raw) || Number(raw) > 0xffffffff) throw new Error(`KB_SEED must be an integer from 0 to 4294967295, got "${raw}"`);
    seed = Number(raw);
  }
  report(seed);
  return seed;
}

/** Runs `check` `runs` times on one seeded stream; a failure names the seed and keeps the cause. */
export function checkProperty(seed: number, runs: number, check: (rng: SeededRandom, run: number) => void): void {
  const rng = seededRandom(seed);
  for (let run = 0; run < runs; run += 1) {
    try {
      check(rng, run);
    } catch (cause) {
      const why = cause instanceof Error ? cause.message : String(cause);
      throw new Error(`property failed at run ${run} with seed ${seed} (KB_SEED=${seed}): ${why}`, { cause });
    }
  }
}
