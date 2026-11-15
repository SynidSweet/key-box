// M1 counters (design 3.8): hardware-free counts of the work one operation does, taken from the seams the tests already run through.
// SHA-256 and ES256 work is counted by wrapping node:crypto's `createHash`, `createHmac` and `verify` with a counting twin that calls the
// real one (node's own module, not ours); a commit is one durable write transaction: an explicit `COMMIT` the real SQLite connection receives,
// or a write statement run while its connection is in no transaction (it commits itself). The counters live in
// test code only: production carries none.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync, StatementSync } from 'node:sqlite';

/** Which connection each prepared statement belongs to, filled the moment it is prepared (even before any counting), so a statement a world
 * prepared at setup is still attributed to its connection when the counted work runs it. */
const connectionOf = new WeakMap<StatementSync, DatabaseSync>();
const realPrepare = DatabaseSync.prototype.prepare;
DatabaseSync.prototype.prepare = function (this: DatabaseSync, sql: string): StatementSync {
  const statement = realPrepare.call(this, sql);
  connectionOf.set(statement, this);
  return statement;
};

/** A statement that writes (and so, outside a transaction, commits by itself: one fsync under synchronous=FULL). */
const WRITES = /^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b/i;
const COMMIT = /^\s*COMMIT\s*;?\s*$/i;

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
    if (COMMIT.test(sql) || (WRITES.test(sql) && !this.isTransaction)) counts.commits += 1;
    realExec.call(this, sql);
  };
  const realStatement = { run: StatementSync.prototype.run, get: StatementSync.prototype.get, all: StatementSync.prototype.all };
  const counted = <K extends keyof typeof realStatement>(method: K): void => {
    const real = realStatement[method] as (this: StatementSync, ...a: unknown[]) => unknown;
    const wrapped = function (this: StatementSync, ...args: unknown[]): unknown {
      const db = connectionOf.get(this);
      if (db !== undefined && WRITES.test(this.sourceSQL) && !db.isTransaction) counts.commits += 1;
      return real.apply(this, args);
    };
    Object.assign(StatementSync.prototype, { [method]: wrapped });
  };
  counted('run');
  counted('get');
  counted('all');
  syncBuiltinESMExports();
  try {
    await work();
  } finally {
    crypto.createHash = realHash;
    crypto.createHmac = realHmac;
    crypto.verify = realVerify;
    DatabaseSync.prototype.exec = realExec;
    Object.assign(StatementSync.prototype, realStatement);
    syncBuiltinESMExports();
  }
  return counts;
}
