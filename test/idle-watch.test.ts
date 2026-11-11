// KBOX-21: not looking idle. Synthetic /proc files and a FakeClock: the figures Oracle's reclaim rule looks at (CPU p95,
// network, memory over 7 days), the warning push within 5 points of the 20% line, the memory reserve at 30% of MemTotal,
// and a failing /proc read reported once.
import assert from 'node:assert/strict';
import { writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { FakeClock, tempDir } from './kit/index.ts';
import { FakePush } from './fakes/push.ts';
import { createIdleWatch, idleFigures, nearReclaim } from '../src/shell/idle-watch.ts';

const MIB = 1024 * 1024;
const HOUR = 3600_000;

test('KBOX-21 near the line means all three figures within 5 points of 20%: 25 is near, 26 (6 points away) is not', () => {
  assert.equal(nearReclaim({ cpuP95: 25, netPct: 25, memPct: 25 }), true);
  assert.equal(nearReclaim({ cpuP95: 10, netPct: 0, memPct: 24.9 }), true);
  assert.equal(nearReclaim({ cpuP95: 26, netPct: 0, memPct: 0 }), false, 'CPU 6 points away');
  assert.equal(nearReclaim({ cpuP95: 0, netPct: 26, memPct: 0 }), false, 'network 6 points away');
  assert.equal(nearReclaim({ cpuP95: 0, netPct: 0, memPct: 26 }), false, 'memory 6 points away');
});

test('KBOX-21 the figures: CPU as the 95th percentile of busy over total per interval, network against the nominal link, memory used over MemTotal', () => {
  // 20 intervals of one hour: 19 at 10% busy and one at 90%: p95 of 20 values is the 19th smallest, 10%.
  const samples = Array.from({ length: 21 }, (_, i) => ({ at: i * HOUR, cpuBusy: 0, cpuTotal: 0, netBytes: 0, memUsedPct: 40 }));
  let busy = 0;
  let total = 0;
  for (let i = 1; i < samples.length; i += 1) {
    total += 1000;
    busy += i === 7 ? 900 : 100;
    samples[i] = { at: i * HOUR, cpuBusy: busy, cpuTotal: total, netBytes: i * 450_000_000, memUsedPct: 40 };
  }
  const f = idleFigures(samples, 1); // 1 Mbit/s nominal = 125,000 bytes/s; 450 MB per hour = 125,000 bytes/s
  assert.equal(f.cpuP95, 10);
  assert.equal(f.netPct, 100);
  assert.equal(f.memPct, 40);
});

async function procWorld(t: Parameters<typeof tempDir>[0]) {
  const dir = await tempDir(t);
  const files = { stat: join(dir, 'stat'), meminfo: join(dir, 'meminfo'), netdev: join(dir, 'net_dev') };
  let busy = 0;
  let total = 0;
  let net = 0;
  const step = (cpuPct: number, memAvailableKb: number, netBytes: number): void => {
    total += 10_000;
    busy += cpuPct * 100;
    net += netBytes;
    writeFileSync(files.stat, `cpu  ${busy} 0 0 ${total - busy} 0 0 0 0 0 0\ncpu0 ${busy} 0 0 ${total - busy} 0 0 0 0 0 0\n`);
    writeFileSync(files.meminfo, `MemTotal:       10240 kB\nMemFree:        ${memAvailableKb} kB\nMemAvailable:   ${memAvailableKb} kB\n`);
    writeFileSync(files.netdev, `Inter-|   Receive\n face |bytes\n    lo: 999999999 0 0 0 0 0 0 0 999999999 0 0 0 0 0 0 0\n  eth0: ${net} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n`);
  };
  const clock = new FakeClock(1_700_000_000_000);
  const push = new FakePush();
  const notices: string[] = [];
  const watch = createIdleWatch({ files, clock, push, linkMbps: 1, notifier: { notice: (code) => void notices.push(code) } });
  return { files, step, clock, push, notices, watch };
}

test('KBOX-21 a week of quiet sends one push; a week with CPU 6 points away from the line sends none', async (t) => {
  const quiet = await procWorld(t);
  for (let h = 0; h <= 7 * 24; h += 1) {
    quiet.step(2, 9000, 1000);
    quiet.watch.sample();
    quiet.clock.advance(HOUR);
  }
  assert.equal(quiet.push.sent.filter((m) => m.kind === 'idle').length, 1, 'one push, not one per sample');

  const busy = await procWorld(t);
  for (let h = 0; h <= 7 * 24; h += 1) {
    busy.step(26, 9000, 1000);
    busy.watch.sample();
    busy.clock.advance(HOUR);
  }
  assert.equal(busy.push.sent.filter((m) => m.kind === 'idle').length, 0);
});

test('KBOX-21 the reserve keeps memory at or above 30% of MemTotal and is released on shutdown', async (t) => {
  const w = await procWorld(t);
  w.step(5, 9216, 0); // 1 MiB of 10 MiB used: 10%
  w.watch.sample();
  assert.equal(w.watch.reserveBytes(), 2 * MIB, 'the reserve tops memory up to 3 MiB of 10 MiB');
  w.step(5, 5120, 0); // 5 MiB used, the reserve included: no more is needed... and none is kept beyond the gap
  w.watch.sample();
  assert.ok(w.watch.reserveBytes() <= 2 * MIB);
  w.watch.stop();
  assert.equal(w.watch.reserveBytes(), 0);
});

test('KBOX-21 a failing /proc read is reported once as a notice, not swallowed', async (t) => {
  const w = await procWorld(t);
  w.step(5, 9000, 0);
  rmSync(w.files.meminfo);
  w.watch.sample();
  w.watch.sample();
  assert.deepEqual(w.notices, ['proc_unreadable']);
});
