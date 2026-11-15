// The Pi's budgets (design 3.8) and what is measured against them: the one home both kb-bench (the update rehearsal, first start) and
// kb-join's ready mode (the start times and the memory with every service up) read. Availability budgets: a miss is a fact, never a stop.

/** The `update.*` budgets are half of the installer's bounds (COPY_DEADLINE_MS 60 s, SELF_CHECK_WITHIN_MS 10 s): the pass is 2x headroom. */
export const BUDGET = { copy_ms: 30_000, self_check_ms: 5_000, update_memory_kib: 65_536, core_start_ms: 20_000, relay_start_ms: 10_000 } as const;

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
