// M1 counters (design 3.8): hardware-free counts of the work one operation does, taken from the seams the tests already run through.
// SHA-256 and ES256 work is counted by wrapping node:crypto's `createHash`, `createHmac` and `verify` with a counting twin that calls the
// real one (node's own module, not ours); commits are the `COMMIT` statements the real SQLite connection receives. The counters live in
// test code only: production carries none.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync } from 'node:sqlite';

export interface Counts {
  /** `createHash('sha256')` and `createHmac('sha256')` calls. */
  sha256: number;
  /** `crypto.verify` calls (ES256 verifies; Ed25519 verifies are counted apart). */
  es256: number;
  ed25519: number;
  commits: number;
}

/** Runs `work` with the counters on and returns what it counted; the real functions are back when it ends, pass or fail. */
export async function counting(work: () => Promise<void> | void): Promise<Counts> {
  const counts: Counts = { sha256: 0, es256: 0, ed25519: 0, commits: 0 };
  const realHash = crypto.createHash;
  const realHmac = crypto.createHmac;
  const realVerify = crypto.verify;
  const realExec = DatabaseSync.prototype.exec;
  crypto.createHash = ((algorithm: string, ...rest: unknown[]) => {
    if (algorithm === 'sha256') counts.sha256 += 1;
    return (realHash as (...a: unknown[]) => crypto.Hash)(algorithm, ...rest);
  }) as typeof crypto.createHash;
  crypto.createHmac = ((algorithm: string, ...rest: unknown[]) => {
    if (algorithm === 'sha256') counts.sha256 += 1;
    return (realHmac as (...a: unknown[]) => crypto.Hmac)(algorithm, ...rest);
  }) as typeof crypto.createHmac;
  crypto.verify = ((algorithm: string | null | undefined, ...rest: unknown[]) => {
    if (algorithm === 'sha256') counts.es256 += 1;
    else counts.ed25519 += 1;
    return (realVerify as (...a: unknown[]) => boolean)(algorithm, ...rest);
  }) as typeof crypto.verify;
  DatabaseSync.prototype.exec = function (this: DatabaseSync, sql: string): void {
    if (sql.trim().toUpperCase() === 'COMMIT') counts.commits += 1;
    realExec.call(this, sql);
  };
  syncBuiltinESMExports();
  try {
    await work();
  } finally {
    crypto.createHash = realHash;
    crypto.createHmac = realHmac;
    crypto.verify = realVerify;
    DatabaseSync.prototype.exec = realExec;
    syncBuiltinESMExports();
  }
  return counts;
}
