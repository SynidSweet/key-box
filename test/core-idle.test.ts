import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { startCore } from '../src/main-core.ts';
import type { CoreRuntime } from '../src/main-core.ts';
import { TimedClock, drive, seededRandom, tempDir } from './kit/index.ts';

type ProcFiles = NonNullable<CoreRuntime['proc']>;

/** Starts an in-process core with KB_DOMAIN set (the shape that builds the idle watch) and returns what its journal recorded and whether it served. */
async function startedWith(t: TestContext, proc: (dir: string) => ProcFiles | undefined) {
  const dir = await tempDir(t);
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(1_700_000_000_000);
  const socket = join(dir, 'http.sock');
  const env = { KB_STATE_DIR: join(dir, 'state'), KB_SOCKET: socket, KB_INSTALL_RESULTS: join(dir, 'results'), KB_CURRENT: join(dir, 'current'), KB_DOMAIN: 'box.example' };
  const journal: string[] = [];
  const files = proc(dir);
  const core = await startCore(env, { clock, scheduler: clock, random: seededRandom(3), journal: (code) => void journal.push(code), ...(files === undefined ? {} : { proc: files }) });
  t.after(() => core.stop());
  const reply = await drive(socket).request({ path: '/api/share', method: 'GET', headers: { 'x-kb-client-ip': '203.0.113.9' } });
  return { journal, status: reply.status };
}

const writeProc = (dir: string, withMeminfo: boolean): ProcFiles => {
  const stat = join(dir, 'stat');
  const meminfo = join(dir, 'meminfo');
  const netdev = join(dir, 'netdev');
  writeFileSync(stat, 'cpu  100 0 100 800 0 0 0 0 0 0\n');
  if (withMeminfo) writeFileSync(meminfo, 'MemTotal:        2048 kB\nMemAvailable:    1024 kB\n');
  writeFileSync(netdev, 'Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 1 0 0 0 0 0 0 1000 1 0 0 0 0 0 0\n');
  return { stat, meminfo, netdev };
};

test('KBOX-21 a runtime whose idle-watch files are unreadable journals proc_unreadable once (the core reads the files its runtime names, not the host /proc)', async (t) => {
  const w = await startedWith(t, (dir) => writeProc(dir, false));
  assert.equal(w.journal.filter((c) => c === 'proc_unreadable').length, 1);
});

test('KBOX-21 a runtime naming readable synthetic files starts and serves, with no proc_unreadable', async (t) => {
  const w = await startedWith(t, (dir) => writeProc(dir, true));
  assert.notEqual(w.status, 0);
  assert.equal(w.journal.includes('proc_unreadable'), false);
});

test('KBOX-21 a runtime naming no files runs no idle watch: the core starts and serves, with no proc_unreadable', async (t) => {
  const w = await startedWith(t, () => undefined);
  assert.notEqual(w.status, 0);
  assert.equal(w.journal.includes('proc_unreadable'), false);
});
