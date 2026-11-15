// The Pi's budgets (design 3.8) and what is measured against them: the one home both kb-bench (the update rehearsal, first start) and
// kb-join's ready mode (the start times and the memory with every service up) read. Availability budgets: a miss is a fact, never a stop.

/** The `update.*` budgets are half of the installer's bounds (COPY_DEADLINE_MS 60 s, SELF_CHECK_WITHIN_MS 10 s): the pass is 2x headroom. */
export const BUDGET = { copy_ms: 30_000, self_check_ms: 5_000, update_memory_kib: 65_536, core_start_ms: 20_000, relay_start_ms: 10_000, commit_p95_ms: 50, approval_ms: 500, relay_ms: 100, share_ms: 10_000 } as const;

export interface OverItem {
  readonly item: string;
  readonly measured: number;
  readonly budget: number;
  readonly unit: 'ms' | 'KiB';
}

const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/** The items of bench.over: the bench's `update` numbers, the memory with every service up and the start times against the budgets. A number that is not there is no item. */
export function overItems(update: Readonly<Record<string, unknown>>, memKib: number | null, core: number | null, relay: number | null): OverItem[] {
  const over: OverItem[] = [];
  const copy = num(update['copy_ms']);
  const selfCheck = num(update['self_check_ms']);
  const peak = num(update['peak_rss_kb']);
  if (copy !== undefined && copy > BUDGET.copy_ms) over.push({ item: 'update.copy', measured: copy, budget: BUDGET.copy_ms, unit: 'ms' });
  if (selfCheck !== undefined && selfCheck > BUDGET.self_check_ms) over.push({ item: 'update.self_check', measured: selfCheck, budget: BUDGET.self_check_ms, unit: 'ms' });
  if (memKib !== null && peak !== undefined && memKib - peak < BUDGET.update_memory_kib) over.push({ item: 'update.memory', measured: memKib - peak, budget: BUDGET.update_memory_kib, unit: 'KiB' });
  if (core !== null && core > BUDGET.core_start_ms) over.push({ item: 'core.start', measured: core, budget: BUDGET.core_start_ms, unit: 'ms' });
  if (relay !== null && relay > BUDGET.relay_start_ms) over.push({ item: 'relay.start', measured: relay, budget: BUDGET.relay_start_ms, unit: 'ms' });
  return over;
}

/** The 95th percentile by nearest rank. */
export function p95(samples: readonly number[]): number {
  if (samples.length === 0) throw new RangeError('p95 of no samples');
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.ceil(0.95 * sorted.length) - 1] ?? 0;
}

/** One `/proc/meminfo` figure in kB (`MemTotal`, `MemAvailable`), or null when the line is not there. */
export function meminfoKib(text: string, key: 'MemTotal' | 'MemAvailable'): number | null {
  const match = new RegExp(`^${key}:\\s+(\\d+) kB$`, 'm').exec(text);
  return match === null ? null : Number(match[1]);
}

/** The work one operation does, as counted by test/perf/counts.test.ts (M1; the test asserts the code still does exactly this). */
export const PER_OPERATION = {
  approval: { commits: 6, es256: 2 },
  relay: { commits: 1, sha256: 1 },
  share: { sha256: 13351 },
} as const;

/** Unit costs as kb-bench records them in `bench.unit_costs` (the ones the judge reads). */
export interface JudgedCosts {
  readonly wal_commit_p95_ms: number;
  readonly sha256_56b_x1000_ms: number;
  readonly es256_verify_x50_ms: number;
}

export interface Estimates {
  readonly approval_ms: number;
  readonly relay_ms: number;
  readonly share_ms: number;
}

/** Counts times costs (design 3.8): each operation's work (PER_OPERATION) times the Pi's measured unit costs is its estimate; an estimate over its
 * budget, and a commit p95 over its own, is an item of bench.over. Over is strictly above the budget. */
export function judge(costs: JudgedCosts): { estimates: Estimates; over: OverItem[] } {
  const commit = costs.wal_commit_p95_ms;
  const sha = costs.sha256_56b_x1000_ms / 1000;
  const es256 = costs.es256_verify_x50_ms / 50;
  const estimates: Estimates = {
    approval_ms: PER_OPERATION.approval.commits * commit + PER_OPERATION.approval.es256 * es256,
    relay_ms: PER_OPERATION.relay.commits * commit + PER_OPERATION.relay.sha256 * sha,
    share_ms: PER_OPERATION.share.sha256 * sha,
  };
  const checks: readonly [string, number, number][] = [
    ['commit.p95', commit, BUDGET.commit_p95_ms],
    ['approval.estimate', estimates.approval_ms, BUDGET.approval_ms],
    ['relay.estimate', estimates.relay_ms, BUDGET.relay_ms],
    ['share.estimate', estimates.share_ms, BUDGET.share_ms],
  ];
  const over = checks.filter(([, measured, budget]) => measured > budget).map(([item, measured, budget]): OverItem => ({ item, measured, budget, unit: 'ms' }));
  return { estimates, over };
}
