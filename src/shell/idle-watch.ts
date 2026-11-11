// KBOX-21: not looking idle. Oracle may reclaim an Always Free instance when, over 7 days, CPU p95, network and memory are
// all under 20%. Core samples the same three figures from /proc (no call to Oracle's monitoring API), keeps a touched memory
// reserve so memory stays at or above 30% of MemTotal, and sends one push when all three come within 5 points of the line.
// How Oracle computes its network figure, and whether these match its MemoryUtilization, is UNVERIFIED (design section 12).
import { readFileSync } from 'node:fs';
import type { Clock } from '../ports/clock.ts';
import type { Push } from '../ports/push.ts';

export const WINDOW_MS = 7 * 24 * 3600_000;
const LINE_PCT = 20;
const MARGIN_PCT = 5;
const RESERVE_TARGET = 0.3;

export interface ProcSample {
  readonly at: number;
  /** Cumulative busy and total jiffies of the `cpu` line. */
  readonly cpuBusy: number;
  readonly cpuTotal: number;
  /** Cumulative received plus sent bytes of every interface but `lo`. */
  readonly netBytes: number;
  readonly memUsedPct: number;
}

export interface IdleFigures {
  readonly cpuP95: number;
  readonly netPct: number;
  readonly memPct: number;
}

/** All three within 5 points of the 20% line (at most 25%). */
export const nearReclaim = (f: IdleFigures): boolean => [f.cpuP95, f.netPct, f.memPct].every((v) => v <= LINE_PCT + MARGIN_PCT);

const p95 = (values: readonly number[]): number => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)] ?? 0;
};

/** The figures over consecutive samples: CPU busy share per interval (p95), mean throughput against the link, memory (p95). */
export function idleFigures(samples: readonly ProcSample[], linkMbps: number): IdleFigures {
  const cpu: number[] = [];
  for (let i = 1; i < samples.length; i += 1) {
    const a = samples[i - 1];
    const b = samples[i];
    if (a === undefined || b === undefined || b.cpuTotal <= a.cpuTotal) continue;
    cpu.push(((b.cpuBusy - a.cpuBusy) / (b.cpuTotal - a.cpuTotal)) * 100);
  }
  const first = samples[0];
  const last = samples.at(-1);
  const seconds = first === undefined || last === undefined ? 0 : (last.at - first.at) / 1000;
  const netPct = seconds <= 0 || first === undefined || last === undefined ? 0 : ((last.netBytes - first.netBytes) / seconds / (linkMbps * 125_000)) * 100;
  return { cpuP95: p95(cpu), netPct, memPct: p95(samples.map((s) => s.memUsedPct)) };
}

const number = (v: string | undefined): number => {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new RangeError('a /proc figure is not a number');
  return n;
};

export function parseStat(text: string): { busy: number; total: number } {
  const line = text.split('\n').find((l) => /^cpu\s/.test(l));
  if (line === undefined) throw new RangeError('no cpu line in /proc/stat');
  const v = line.trim().split(/\s+/).slice(1).map(number);
  const total = v.slice(0, 8).reduce((s, x) => s + x, 0);
  const idle = (v[3] ?? 0) + (v[4] ?? 0);
  return { busy: total - idle, total };
}

export function parseMeminfo(text: string): { totalKb: number; usedPct: number } {
  const field = (name: string): number => number(new RegExp(`^${name}:\\s+(\\d+) kB$`, 'm').exec(text)?.[1]);
  const totalKb = field('MemTotal');
  if (totalKb <= 0) throw new RangeError('MemTotal is zero');
  return { totalKb, usedPct: ((totalKb - field('MemAvailable')) / totalKb) * 100 };
}

export function parseNetDev(text: string): number {
  let bytes = 0;
  for (const line of text.split('\n').slice(2)) {
    const m = /^\s*([^:\s]+):\s*(.*)$/.exec(line);
    if (m === null || m[1] === 'lo') continue;
    const v = (m[2] ?? '').trim().split(/\s+/).map(number);
    bytes += (v[0] ?? 0) + (v[8] ?? 0);
  }
  return bytes;
}

export interface IdleWatchDeps {
  readonly files: { readonly stat: string; readonly meminfo: string; readonly netdev: string };
  readonly clock: Clock;
  readonly push: Push;
  /** The nominal link speed of `deploy/runtime.config.json`. */
  readonly linkMbps: number;
  readonly notifier: { notice(code: 'proc_unreadable'): void };
}

export interface IdleWatch {
  /** Reads /proc once: records a sample, resizes the reserve, pushes once when near the line. */
  sample(): void;
  reserveBytes(): number;
  /** Releases the reserve (shutdown). */
  stop(): void;
}

type Read = { readonly ok: true; readonly sample: ProcSample; readonly totalKb: number } | { readonly ok: false };

export function createIdleWatch(deps: IdleWatchDeps): IdleWatch {
  let samples: ProcSample[] = [];
  let reserve: Buffer = Buffer.alloc(0);
  let warned = false;
  let reportedUnreadable = false;

  const read = (): Read => {
    try {
      const stat = parseStat(readFileSync(deps.files.stat, 'utf8'));
      const mem = parseMeminfo(readFileSync(deps.files.meminfo, 'utf8'));
      const net = parseNetDev(readFileSync(deps.files.netdev, 'utf8'));
      return { ok: true, totalKb: mem.totalKb, sample: { at: deps.clock.now(), cpuBusy: stat.busy, cpuTotal: stat.total, netBytes: net, memUsedPct: mem.usedPct } };
    } catch {
      return { ok: false }; // sample() reports it, once, as a notice
    }
  };

  return {
    sample() {
      const got = read();
      if (!got.ok) {
        if (!reportedUnreadable) deps.notifier.notice('proc_unreadable');
        reportedUnreadable = true;
        return;
      }
      const s = got.sample;
      // The reserve is part of what is used, so the gap to 30% is measured with it and only the gap is kept.
      const totalBytes = got.totalKb * 1024;
      const usedBytes = (s.memUsedPct / 100) * totalBytes;
      const want = Math.max(0, Math.round(reserve.length + RESERVE_TARGET * totalBytes - usedBytes));
      if (want !== reserve.length) reserve = Buffer.alloc(want, 1); // filled, so the pages are touched
      samples = [...samples.filter((x) => x.at >= s.at - WINDOW_MS), s];
      const first = samples[0];
      if (first === undefined || s.at - first.at < WINDOW_MS) return;
      const near = nearReclaim(idleFigures(samples, deps.linkMbps));
      if (near && !warned) deps.push.send({ title: 'The box looks idle to Oracle', kind: 'idle' });
      warned = near;
    },
    reserveBytes: () => reserve.length,
    stop() {
      reserve = Buffer.alloc(0);
    },
  };
}
