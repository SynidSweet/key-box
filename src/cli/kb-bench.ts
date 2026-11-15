// kb-bench (design 3.8, M3 and M-E): run once by the bootstrap at first start, on the real Pi, before any key exists. It times four unit costs,
// reads MemTotal and MemAvailable, and rehearses an update: the installer's read, SHA-256 and fsync-write over the running release, then
// the installer's own full check (`selfCheck`, then `joinCheck`, one window). It writes `bench` into the facts file: names and numbers,
// no value and no environment text. It takes at most 120 s: the unit costs are cut there, and a rehearsal is not started after it.
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { basename, dirname, isAbsolute, join } from 'node:path';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { Random } from '../ports/random.ts';
import type { JudgedCosts } from '../pure/bench.ts';
import { RELEASE_HASH } from '../pure/release-hash.ts';
import { judge, meminfoKib, overItems, p95 } from '../pure/bench.ts';
import { TIME_OK_FILE } from '../pure/time-gate.ts';
import { systemScheduler } from '../shell/clock.ts';
import { updateFacts } from '../shell/facts-file.ts';
import { SELF_CHECK_WITHIN_MS } from '../shell/installer.ts';
import type { ReleaseUnits } from '../shell/installer.ts';
import { systemRandom } from '../shell/random.ts';
import { systemdUnits } from '../shell/systemd.ts';
import type { CopyMeasure } from '../shell/update-rehearsal.ts';
import { REHEARSAL_PREFIX, rehearseCopy } from '../shell/update-rehearsal.ts';

const LIMIT_MS = 120_000;
const SHA_CALLS = 1_000;
const ES256_CALLS = 50;
const COMMITS = 200;
const JSON_CALLS = 1_000;

/** One call of each measured operation; the loops and the clock are kb-bench's. */
export interface Workloads {
  /** One SHA-256 of 56 bytes. */
  readonly sha256: () => void | Promise<void>;
  /** One ES256 verify. */
  readonly es256: () => void | Promise<void>;
  /** One SQLite WAL commit with `synchronous=FULL`. */
  readonly walCommit: () => void | Promise<void>;
  /** One JSON stringify, parse and regex test. */
  readonly jsonRegex: () => void | Promise<void>;
}

export interface BenchDeps {
  /** A clock that reads in fractions of a millisecond on the box; a fake in tests. */
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly factsFile: string;
  readonly meminfoFile: string;
  /** The process's peak resident set (VmHWM), kB. */
  readonly peakRssKb: () => number;
  /** The resolved release directory (see `resolveRelease`), or undefined when `current` names none. */
  readonly releaseDir: string | undefined;
  readonly installDir: string;
  readonly random: Random;
  /** The installer's own checks (the port `systemdUnits` implements). */
  readonly units: Pick<ReleaseUnits, 'selfCheck' | 'joinCheck'>;
  readonly workloads: Workloads;
  readonly writeDurable?: (path: string, bytes: Uint8Array) => void;
}

/** The units port as kb-install builds it, for the check only: the self-check spawn gets TIME_OK_FILE as KB_TIME_OK_FILE, which its `--for-update` run compares with its own constant. */
export function benchUnits(clock: Clock, nodeOf?: (releaseDir: string) => string): Pick<ReleaseUnits, 'selfCheck' | 'joinCheck'> {
  const wait = (ms: number): Promise<void> => new Promise<void>((resolve) => void systemScheduler.after(ms, resolve));
  return systemdUnits({ systemctl: 'systemctl', units: [], healthSockets: [], clock, wait, timeOkFile: TIME_OK_FILE, ...(nodeOf === undefined ? {} : { nodeOf }) });
}

async function timed(clock: Clock, calls: number, fn: () => void | Promise<void>): Promise<number> {
  const started = clock.now();
  for (let i = 0; i < calls; i += 1) await fn();
  return clock.now() - started;
}

async function commitsP95(clock: Clock, fn: () => void | Promise<void>): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < COMMITS; i += 1) {
    const started = clock.now();
    await fn();
    samples.push(clock.now() - started);
  }
  return p95(samples);
}

/** The four unit costs: the three the judge reads, and the JSON loop. */
interface UnitCosts extends JudgedCosts {
  readonly json_regex_loop_ms: number;
}

/** The four unit costs. */
async function unitCosts(deps: BenchDeps): Promise<UnitCosts> {
  const { clock, workloads: w } = deps;
  return {
    sha256_56b_x1000_ms: await timed(clock, SHA_CALLS, w.sha256),
    es256_verify_x50_ms: await timed(clock, ES256_CALLS, w.es256),
    wal_commit_p95_ms: await commitsP95(clock, w.walCommit),
    json_regex_loop_ms: await timed(clock, JSON_CALLS, w.jsonRegex),
  };
}

/** The full update check as the installer runs it: `selfCheck` then `joinCheck` with one `until`, timed as one window. A failed or hung check is the bound itself: the update would roll back. */
async function timeFullCheck(deps: BenchDeps, releaseDir: string): Promise<number> {
  const started = deps.clock.now();
  const until = started + SELF_CHECK_WITHIN_MS;
  const ok = (await deps.units.selfCheck(releaseDir, until)) && (await deps.units.joinCheck(releaseDir, until));
  return ok ? deps.clock.now() - started : Math.max(deps.clock.now() - started, SELF_CHECK_WITHIN_MS);
}

type Costs = { readonly kind: 'done'; readonly costs: UnitCosts } | { readonly kind: 'timeout' };

/** The unit costs, or `timeout` when 120 s pass first (a workload that hangs). */
function costsWithin(deps: BenchDeps): Promise<Costs> {
  return new Promise<Costs>((resolve, reject) => {
    const cancel = deps.scheduler.after(LIMIT_MS, () => resolve({ kind: 'timeout' }));
    unitCosts(deps).then(
      (costs) => {
        cancel();
        resolve({ kind: 'done', costs });
      },
      (error: unknown) => {
        cancel();
        reject(error instanceof Error ? error : new Error('a unit-cost workload failed'));
      },
    );
  });
}

export async function runBench(deps: BenchDeps): Promise<number> {
  const meminfo = readFileSync(deps.meminfoFile, 'utf8');
  const memory = { mem_total_kb: meminfoKib(meminfo, 'MemTotal'), mem_available_kb: meminfoKib(meminfo, 'MemAvailable') };
  const measured = await costsWithin(deps);
  if (measured.kind === 'timeout') {
    updateFacts(deps.factsFile, (facts) => void (facts['bench'] = { ...memory, timed_out: true, over: [] }));
    return 0;
  }
  const { estimates, over: judged } = judge(measured.costs);
  const first = { unit_costs: measured.costs, estimates, ...memory };
  updateFacts(deps.factsFile, (facts) => void (facts['bench'] = { ...first, over: judged }));
  const update = await rehearse(deps);
  const over = 'error' in update ? judged : [...judged, ...overItems(update, null, null, null)];
  updateFacts(deps.factsFile, (facts) => void (facts['bench'] = { ...first, update, over }));
  return 0;
}

/** The fixed words a failed update rehearsal is recorded as: never a path or a message. */
export type UpdateError = 'no current release' | 'rehearsal copy failed' | 'rehearsal check failed';

type Rehearsed = { readonly copy_ms: number; readonly bytes: number; readonly self_check_ms: number; readonly peak_rss_kb: number } | { readonly error: UpdateError };

/** The copy rehearsal and the full check over one resolved release; every failure is a recorded word, so a fresh box's setup never stops on the bench. */
async function rehearse(deps: BenchDeps): Promise<Rehearsed> {
  const releaseDir = deps.releaseDir;
  if (releaseDir === undefined) return { error: 'no current release' };
  let copy: CopyMeasure;
  try {
    copy = rehearseCopy({ clock: deps.clock, random: deps.random, releaseDir, installDir: deps.installDir, ...(deps.writeDurable === undefined ? {} : { writeDurable: deps.writeDurable }) });
  } catch {
    return { error: 'rehearsal copy failed' };
  }
  try {
    const self_check_ms = await timeFullCheck(deps, releaseDir);
    return { copy_ms: copy.copy_ms, bytes: copy.bytes, self_check_ms, peak_rss_kb: deps.peakRssKb() };
  } catch {
    return { error: 'rehearsal check failed' };
  }
}

/** The release `current` names, resolved as the installer does: a directory directly under a `releases` directory with a 64-hex name; otherwise undefined. */
export function resolveRelease(current: string): string | undefined {
  if (!existsSync(current)) return undefined;
  const target = realpathSync(current);
  return RELEASE_HASH.test(basename(target)) && basename(dirname(target)) === 'releases' ? target : undefined;
}

// ------------------------------------------------------------------------------------------------ the real workloads

/** The real operations over a scratch directory this makes; `close` removes it. */
export function realWorkloads(dir: string): Workloads & { close(): void } {
  mkdirSync(dir, { recursive: true });
  const db = new DatabaseSync(join(dir, 'bench.db'));
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = FULL');
  db.exec('CREATE TABLE bench (n INTEGER)');
  const insert = db.prepare('INSERT INTO bench (n) VALUES (?)');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const message = Buffer.alloc(56, 7);
  const signature = sign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const sample = { a: 'text', n: [1, 2, 3], nested: { key: 'abc-123-def' } };
  let n = 0;
  return {
    sha256: () => void createHash('sha256').update(message).digest(),
    es256: () => {
      if (!verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)) throw new Error('the bench signature did not verify');
    },
    walCommit: () => void insert.run((n += 1)),
    jsonRegex: () => void /abc-(\d+)-def/.test(JSON.stringify(JSON.parse(JSON.stringify(sample)))),
    close: () => {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ------------------------------------------------------------------------------------------------ the entry

const absolute = (value: string | undefined, fallback: string): string => {
  const path = value ?? fallback;
  if (!isAbsolute(path)) throw new RangeError('a kb-bench path must be absolute');
  return path;
};

/** The process's peak resident set from /proc/self/status (VmHWM), kB. */
function peakRssKb(): number {
  const match = /^VmHWM:\s+(\d+) kB$/m.exec(readFileSync('/proc/self/status', 'utf8'));
  if (match === null) throw new Error('VmHWM is not in /proc/self/status');
  return Number(match[1]);
}

async function main(env: NodeJS.ProcessEnv): Promise<number> {
  const stateDir = absolute(env['KB_STATE_DIR'], '/var/lib/keybox');
  const installDir = absolute(env['KB_INSTALL_RESULTS'], '/var/lib/keybox-install');
  const clock: Clock = { now: () => performance.now() };
  // Inside the install directory under a rehearsal.* name: a power cut here is cleaned by kb-join like the rehearsal's own.
  const workloads = realWorkloads(join(installDir, `${REHEARSAL_PREFIX}wal`));
  try {
    return await runBench({
      clock, scheduler: systemScheduler, workloads, installDir, random: systemRandom, peakRssKb,
      factsFile: join(stateDir, 'bootstrap-facts.json'),
      meminfoFile: '/proc/meminfo',
      releaseDir: resolveRelease(absolute(env['KB_CURRENT'], '/opt/keybox/current')),
      units: benchUnits(clock),
    });
  } finally {
    workloads.close();
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.env).catch((e: unknown) => {
    process.stderr.write(`kb-bench stopped: ${e instanceof Error ? e.message : 'unknown error'}\n`);
    return 1;
  });
}
