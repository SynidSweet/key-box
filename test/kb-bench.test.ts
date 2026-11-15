// kb-bench (3.8 M3, M-E, N-M4): the first-start measurement of the Pi. Fake workloads and fake release checks on an injected clock,
// a temporary directory for the facts, the release fixture and the install directory; no real /opt, no real systemctl.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { TimedClock, tempDir } from './kit/index.ts';
import { BUDGET, judge, overItems } from '../src/pure/bench.ts';
import { runReady } from '../src/cli/kb-join.ts';
import { COPY_DEADLINE_MS, SELF_CHECK_WITHIN_MS } from '../src/shell/installer.ts';
import { benchUnits, realWorkloads, runBench } from '../src/cli/kb-bench.ts';
import type { BenchDeps, Workloads } from '../src/cli/kb-bench.ts';
import { TIME_OK_FILE } from '../src/pure/time-gate.ts';

const MEMINFO = 'MemTotal:         948136 kB\nMemFree:          300000 kB\nMemAvailable:     610500 kB\nBuffers: 1 kB\n';
const RANDOM = Uint8Array.from([1, 2, 3, 4, 5, 6]);
const REHEARSAL = 'rehearsal.010203040506';

interface World {
  readonly clock: TimedClock;
  readonly dir: string;
  readonly release: string;
  readonly install: string;
  readonly facts: string;
  /** Writes `(path)` in order; `fail` makes the n-th (1-based) write throw after `slow` ms of clock. */
  readonly writes: string[];
  readonly events: string[];
  deps(over?: Partial<BenchDeps>): BenchDeps;
  bench(): Record<string, unknown>;
}

const FILES: Readonly<Record<string, string>> = {
  'runtime.lock': '# pins\n',
  'src/cli/kb-install.ts': 'export {};\n',
  'src/pure/a.ts': 'export const a = 1;\n',
  'bin/node': 'NODE-BINARY-BYTES',
  'bin/caddy': 'CADDY-BINARY-BYTES-LONGER',
};
const BYTES = Object.values(FILES).reduce((n, v) => n + Buffer.byteLength(v), 0);

const instant: Workloads = { sha256: () => undefined, es256: () => undefined, walCommit: () => undefined, jsonRegex: () => undefined };

async function world(t: TestContext): Promise<World> {
  const dir = await tempDir(t);
  const release = join(dir, 'current');
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(join(release, rel, '..'), { recursive: true });
    writeFileSync(join(release, rel), text, { mode: rel.startsWith('bin/') ? 0o755 : 0o644 });
  }
  const install = join(dir, 'install');
  mkdirSync(install);
  writeFileSync(join(dir, 'meminfo'), MEMINFO);
  const facts = join(dir, 'state', 'bootstrap-facts.json');
  const clock = new TimedClock(1_000);
  const events: string[] = [];
  const writes: string[] = [];
  const w: World = {
    clock, dir, release, install, facts, writes, events,
    deps: (over = {}) => ({
      clock,
      scheduler: clock,
      factsFile: facts,
      meminfoFile: join(dir, 'meminfo'),
      peakRssKb: () => 51_200,
      releaseDir: release,
      installDir: install,
      random: { bytes: () => RANDOM },
      units: { selfCheck: () => Promise.resolve(true), joinCheck: () => Promise.resolve(true) },
      workloads: instant,
      ...over,
    }),
    bench: () => (JSON.parse(readFileSync(facts, 'utf8')) as { bench: Record<string, unknown> }).bench,
  };
  return w;
}

const tree = (root: string): Record<string, string> => {
  const out: Record<string, string> = {};
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out[relative(root, p)] = readFileSync(p, 'utf8');
    }
  };
  walk(root);
  return out;
};

/** A check that takes `ms` on the injected clock and answers `answer`, noting its start and end. */
const check = (w: World, name: string, ms: number, answer = true) => async (_dir: string, until: number): Promise<boolean> => {
  w.events.push(`${name}:start:until=${until}`);
  await Promise.resolve();
  w.clock.advance(ms);
  w.events.push(`${name}:end`);
  return answer;
};

test('unit costs: 1,000 SHA-256, 50 ES256, 200 commits at the 95th percentile and the JSON loop are timed on the clock, with MemTotal and MemAvailable', async (t) => {
  const w = await world(t);
  let commit = 0;
  const workloads: Workloads = {
    sha256: () => void w.clock.advance(1),
    es256: () => void w.clock.advance(2),
    walCommit: () => void w.clock.advance((commit += 1)),
    jsonRegex: () => void w.clock.advance(3),
  };
  assert.equal(await runBench(w.deps({ workloads })), 0);
  const bench = w.bench();
  assert.deepEqual(bench['unit_costs'], { sha256_56b_x1000_ms: 1000, es256_verify_x50_ms: 100, wal_commit_p95_ms: 190, json_regex_loop_ms: 3000 });
  assert.equal(bench['mem_total_kb'], 948136);
  assert.equal(bench['mem_available_kb'], 610500);
});

test('the 120 s limit: a workload that hangs is cut at 120 s, the rest is not run, and the run still writes what it has', async (t) => {
  const w = await world(t);
  const workloads: Workloads = { ...instant, es256: () => new Promise<void>(() => undefined) };
  const done = runBench(w.deps({ workloads }));
  await new Promise((resolve) => setImmediate(resolve));
  w.clock.advance(119_999);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(existsSync(w.facts), false, 'not cut before 120 s');
  w.clock.advance(1);
  assert.equal(await done, 0);
  const bench = w.bench();
  assert.equal(bench['timed_out'], true);
  assert.equal('update' in bench, false, 'no rehearsal after the time ran out');
  assert.deepEqual(readdirSync(w.install), []);
});

test('the facts hold names and numbers only: every leaf of bench is a number or a boolean', async (t) => {
  const w = await world(t);
  await runBench(w.deps());
  const leaves: unknown[] = [];
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (typeof v === 'object' && v !== null) {
      for (const [k, x] of Object.entries(v)) {
        if (k === 'item' || k === 'unit') assert.equal(typeof x, 'string');
        else walk(x);
      }
    } else leaves.push(v);
  };
  walk(w.bench());
  assert.ok(leaves.length > 8);
  for (const leaf of leaves) assert.ok(typeof leaf === 'number' || typeof leaf === 'boolean', `a ${typeof leaf} leaf`);
  assert.equal(readFileSync(w.facts, 'utf8').includes(w.dir), false, 'no path in the facts');
});

test('a facts file with other members keeps them: only bench is replaced', async (t) => {
  const w = await world(t);
  mkdirSync(join(w.dir, 'state'));
  writeFileSync(w.facts, JSON.stringify({ directories: ['/etc/sudoers.d'], bench: { old: 1 } }));
  await runBench(w.deps());
  const all = JSON.parse(readFileSync(w.facts, 'utf8')) as Record<string, Record<string, unknown>>;
  assert.deepEqual(all['directories'], ['/etc/sudoers.d']);
  assert.equal('old' in (all['bench'] ?? {}), false);
});

test('rehearsal: every file of the release and each pinned binary is written under rehearsal.<random>, byte for byte, then the directory is gone', async (t) => {
  const w = await world(t);
  const seen: Record<string, string> = {};
  const writeDurable = (path: string, bytes: Uint8Array): void => {
    w.writes.push(path);
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, bytes);
    seen[relative(join(w.install, REHEARSAL), path)] = Buffer.from(bytes).toString('utf8');
  };
  await runBench(w.deps({ writeDurable }));
  assert.deepEqual(seen, FILES);
  assert.ok(w.writes.every((p) => p.startsWith(join(w.install, REHEARSAL, ''))));
  assert.deepEqual(readdirSync(w.install), [], 'the directory is removed when the rehearsal ends');
  assert.equal((w.bench()['update'] as Record<string, unknown>)['bytes'], BYTES);
});

test('rehearsal: the release tree is byte-identical before and after, and nothing is written inside it', async (t) => {
  const w = await world(t);
  const before = tree(w.release);
  await runBench(w.deps());
  assert.deepEqual(tree(w.release), before);
});

test('rehearsal N-L5: a write that throws leaves no rehearsal.* and the error is not swallowed', async (t) => {
  const w = await world(t);
  let n = 0;
  const writeDurable = (path: string, bytes: Uint8Array): void => {
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, bytes);
    n += 1;
    if (n === 2) throw new Error('disk full');
  };
  await assert.rejects(runBench(w.deps({ writeDurable })), /disk full/);
  assert.deepEqual(readdirSync(w.install), []);
});

test('rehearsal records copy_ms from the clock, the bytes, the check window and the process peak RSS', async (t) => {
  const w = await world(t);
  const writeDurable = (path: string, bytes: Uint8Array): void => {
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, bytes);
    w.clock.advance(7);
  };
  const units = { selfCheck: check(w, 'self', 1000), joinCheck: check(w, 'join', 500) };
  await runBench(w.deps({ writeDurable, units }));
  assert.deepEqual(w.bench()['update'], { copy_ms: 7 * Object.keys(FILES).length, bytes: BYTES, self_check_ms: 1500, peak_rss_kb: 51_200 });
});

test('N-M4: two checks of 3 s are one 6 s window, over the 5 s budget though each alone is under it; selfCheck runs first and ends before joinCheck starts', async (t) => {
  const w = await world(t);
  await runBench(w.deps({ units: { selfCheck: check(w, 'self', 3000), joinCheck: check(w, 'join', 3000) } }));
  assert.deepEqual(w.events.map((e) => e.replace(/:until=.*/, '')), ['self:start', 'self:end', 'join:start', 'join:end']);
  const untils = w.events.filter((e) => e.includes('until=')).map((e) => e.replace(/.*until=/, ''));
  assert.equal(untils[0], untils[1], 'one bound for both spawns');
  const bench = w.bench();
  assert.equal((bench['update'] as Record<string, unknown>)['self_check_ms'], 6000);
  assert.deepEqual(bench['over'], [{ item: 'update.self_check', measured: 6000, budget: 5000, unit: 'ms' }]);
});

test('N-M4: two checks of 2 s are a 4 s window, not over', async (t) => {
  const w = await world(t);
  await runBench(w.deps({ units: { selfCheck: check(w, 'self', 2000), joinCheck: check(w, 'join', 2000) } }));
  assert.deepEqual(w.bench()['over'], []);
});

test('a check that hangs, either spawn, is cut at the installer bound and is over; a failed selfCheck stops the window as the installer does', async (t) => {
  const hangs = (w: World) => (_d: string, until: number): Promise<boolean> => {
    w.clock.advance(until - w.clock.now());
    return Promise.resolve(false);
  };
  for (const which of ['selfCheck', 'joinCheck'] as const) {
    const w = await world(t);
    const units = which === 'selfCheck' ? { selfCheck: hangs(w), joinCheck: check(w, 'join', 0) } : { selfCheck: check(w, 'self', 0), joinCheck: hangs(w) };
    await runBench(w.deps({ units }));
    const bench = w.bench();
    assert.equal((bench['update'] as Record<string, unknown>)['self_check_ms'], SELF_CHECK_WITHIN_MS, which);
    assert.deepEqual(bench['over'], [{ item: 'update.self_check', measured: SELF_CHECK_WITHIN_MS, budget: 5000, unit: 'ms' }], which);
    if (which === 'selfCheck') assert.equal(w.events.some((e) => e.startsWith('join')), false, 'joinCheck is not run after a failed selfCheck');
  }
});

test('a check that fails at once is still over: the update would roll back, so the window records the bound', async (t) => {
  const w = await world(t);
  await runBench(w.deps({ units: { selfCheck: () => Promise.resolve(false), joinCheck: () => Promise.resolve(true) } }));
  assert.deepEqual(w.bench()['over'], [{ item: 'update.self_check', measured: SELF_CHECK_WITHIN_MS, budget: 5000, unit: 'ms' }]);
});

test('bench.over lists the update.copy item when the copy is over 30 s and nothing the bench does not own', async (t) => {
  const w = await world(t);
  const slow = (path: string, bytes: Uint8Array): void => {
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, bytes);
    w.clock.advance(6001);
  };
  await runBench(w.deps({ writeDurable: slow }));
  assert.deepEqual(w.bench()['over'], [{ item: 'update.copy', measured: 6001 * Object.keys(FILES).length, budget: 30_000, unit: 'ms' }]);
});

test('the budgets are the installer bounds halved, and an item is over only strictly above its budget', () => {
  assert.equal(BUDGET.copy_ms, COPY_DEADLINE_MS / 2);
  assert.equal(BUDGET.self_check_ms, SELF_CHECK_WITHIN_MS / 2);
  assert.deepEqual(overItems({ copy_ms: 30_000, self_check_ms: 5000 }, null, null, null), []);
  assert.deepEqual(overItems({ copy_ms: 30_001, self_check_ms: 5001 }, null, null, null).map((o) => o.item), ['update.copy', 'update.self_check']);
});

test('the real units, as the installer builds them: selfCheck passes --for-update and KB_TIME_OK_FILE=TIME_OK_FILE, joinCheck passes --self-check and no environment', async (t) => {
  const dir = await tempDir(t);
  const release = join(dir, 'rel');
  mkdirSync(join(release, 'src', 'cli'), { recursive: true });
  writeFileSync(join(release, 'src', 'cli', 'kb-install.ts'),
    `const ok = process.argv[2] === '--self-check' && process.argv[3] === '--for-update' && process.env['KB_TIME_OK_FILE'] === ${JSON.stringify(TIME_OK_FILE)};\nprocess.exitCode = ok ? 0 : 1;\n`);
  writeFileSync(join(release, 'src', 'cli', 'kb-join.ts'),
    `process.exitCode = process.argv[2] === '--self-check' && process.env['KB_TIME_OK_FILE'] === undefined ? 0 : 1;\n`);
  const clock = new TimedClock(0);
  const units = benchUnits({ now: () => Date.now() }, () => process.execPath);
  void clock;
  assert.equal(await units.selfCheck(release, Date.now() + 20_000), true);
  assert.equal(await units.joinCheck(release, Date.now() + 20_000), true);
  // the control: a release whose kb-install insists on a different file fails the check, as it does on the box
  writeFileSync(join(release, 'src', 'cli', 'kb-install.ts'), `process.exitCode = process.env['KB_TIME_OK_FILE'] === '/elsewhere' ? 0 : 1;\n`);
  assert.equal(await units.selfCheck(release, Date.now() + 20_000), false);
});

test('the real workloads run once each over a temporary database and leave nothing behind', async (t) => {
  const dir = await tempDir(t);
  const real = realWorkloads(join(dir, 'wal'));
  await real.sha256();
  await real.es256();
  await real.walCommit();
  await real.jsonRegex();
  real.close();
  assert.deepEqual(readdirSync(dir), []);
});

// ------------------------------------------------------------------------------------------------ the judge: counts times costs (3.8)

/** Unit costs as kb-bench records them, built from the per-call times the estimates use: commit p95, one SHA-256, one ES256 verify. */
const costs = (commit: number, shaMs: number, es256Ms: number) => ({ wal_commit_p95_ms: commit, sha256_56b_x1000_ms: shaMs * 1000, es256_verify_x50_ms: es256Ms * 50 });
const overOf = (c: ReturnType<typeof costs>, only?: string): string[] => judge(c).over.map((o) => o.item).filter((item) => only === undefined || item === only);

test('the judge: the estimates are counts times costs (approval 6 commits + 2 verifies, relay 5 commits + 1 SHA-256, share 13,351 SHA-256)', () => {
  assert.deepEqual(judge(costs(10, 2, 3)).estimates, { approval_ms: 6 * 10 + 2 * 3, relay_ms: 5 * 10 + 1 * 2, share_ms: 13_351 * 2 });
});

test('the judge: the budgets are 50 ms commit p95, 500 ms approval, 100 ms relay, 10,000 ms share', () => {
  assert.deepEqual([BUDGET.commit_p95_ms, BUDGET.approval_ms, BUDGET.relay_ms, BUDGET.share_ms], [50, 500, 100, 10_000]);
});

test('the judge: commit.p95 is over only strictly above 50 ms (at, just below, just above)', () => {
  assert.deepEqual(overOf(costs(50, 0, 0), 'commit.p95'), []);
  assert.deepEqual(overOf(costs(49.9, 0, 0), 'commit.p95'), []);
  assert.deepEqual(judge(costs(50.1, 0, 0)).over.filter((o) => o.item === 'commit.p95'), [{ item: 'commit.p95', measured: 50.1, budget: 50, unit: 'ms' }]);
});

test('the judge: approval.estimate is over only strictly above 500 ms (6 x 40 + 2 x 130 is exactly 500)', () => {
  assert.deepEqual(overOf(costs(40, 0, 130), 'approval.estimate'), []);
  assert.deepEqual(overOf(costs(40, 0, 129.9), 'approval.estimate'), []);
  assert.deepEqual(judge(costs(40, 0, 130.1)).over.filter((o) => o.item === 'approval.estimate'), [{ item: 'approval.estimate', measured: 6 * 40 + 2 * 130.1, budget: 500, unit: 'ms' }]);
});

test('the judge: relay.estimate is over only strictly above 100 ms (5 x 10 + 50 is exactly 100)', () => {
  assert.deepEqual(overOf(costs(10, 50, 0), 'relay.estimate'), []);
  assert.deepEqual(overOf(costs(10, 49.9, 0), 'relay.estimate'), []);
  assert.deepEqual(judge(costs(10, 50.1, 0)).over.filter((o) => o.item === 'relay.estimate'), [{ item: 'relay.estimate', measured: 5 * 10 + 50.1, budget: 100, unit: 'ms' }]);
});

test('the judge: share.estimate is over only strictly above 10,000 ms (13,351 SHA-256 at 0.7489 ms is under, at 0.7491 ms over)', () => {
  assert.deepEqual(overOf(costs(0, 0.7489, 0)), []);
  assert.deepEqual(overOf(costs(0, 0.7491, 0)), ['share.estimate']);
});

test('the judge: the items come in the order commit, approval, relay, share', () => {
  assert.deepEqual(overOf(costs(60, 100, 300)), ['commit.p95', 'approval.estimate', 'relay.estimate', 'share.estimate']);
});

test('the judge in a run: bench.estimates and bench.over are written from the measured unit costs, in both writes', async (t) => {
  const w = await world(t);
  const workloads: Workloads = { ...instant, sha256: () => void w.clock.advance(1), es256: () => void w.clock.advance(2), walCommit: () => void w.clock.advance(60) };
  assert.equal(await runBench(w.deps({ workloads })), 0);
  const bench = w.bench();
  assert.deepEqual(bench['estimates'], { approval_ms: 6 * 60 + 2 * 2, relay_ms: 5 * 60 + 1, share_ms: 13_351 });
  assert.deepEqual(bench['over'], [
    { item: 'commit.p95', measured: 60, budget: 50, unit: 'ms' },
    { item: 'relay.estimate', measured: 301, budget: 100, unit: 'ms' },
    { item: 'share.estimate', measured: 13_351, budget: 10_000, unit: 'ms' },
  ]);
});

test('the judge in a run: costs within every budget write the estimates and no over item', async (t) => {
  const w = await world(t);
  assert.equal(await runBench(w.deps()), 0);
  assert.deepEqual(w.bench()['estimates'], { approval_ms: 0, relay_ms: 0, share_ms: 0 });
  assert.deepEqual(w.bench()['over'], []);
});

test('kb-ready rewrites only its own over items: the judge items kb-bench wrote are still there, and so are the estimates', async (t) => {
  const w = await world(t);
  const workloads: Workloads = { ...instant, sha256: () => void w.clock.advance(1), es256: () => void w.clock.advance(2), walCommit: () => void w.clock.advance(60) };
  await runBench(w.deps({ workloads }));
  const before = w.bench();
  const tty = join(w.dir, 'tty1');
  assert.equal(
    await runReady({
      env: {}, clock: w.clock, wait: () => Promise.resolve(), tty, factsFile: w.facts, domain: 'keybox.example.ts.net', tlsOk: () => Promise.resolve(true),
      meminfoFile: join(w.dir, 'meminfo'), uptimeMs: () => 100_000, socketBornMs: () => Number.NaN, coreSocket: '/run/keybox/http.sock', relaySocket: '/run/keyrelay/http.sock',
    }),
    0,
  );
  const after = w.bench();
  assert.deepEqual(after['over'], before['over']);
  assert.deepEqual(after['estimates'], before['estimates']);
  assert.equal((after['over'] as { item: string }[]).length, 3);
});
