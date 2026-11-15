// KBOX-64: kb-join, the root oneshot that checks the time, joins Tailscale, checks the box's own name and writes the time gate file.
// A fake `tailscale`, `chronyc`, `nft` and `systemctl` sit on PATH (the real ones are never run); the fake `tailscale status --json`
// plays a scripted sequence from a file. A file stands in for tty1, the clock is injected, and the `ok` file is written into a
// temporary directory through the `okFile` dependency whose default is TIME_OK_FILE.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer as createTlsServer } from 'node:tls';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { FakeClock, directives, tempDir, words } from './kit/index.ts';
import { selfSignedCertificate } from './kit/tls.ts';
import { runJoin, runReady, tlsCheck } from '../src/cli/kb-join.ts';
import type { JoinDeps, ReadyDeps } from '../src/cli/kb-join.ts';
import { TIME_OK_FILE } from '../src/pure/time-gate.ts';

const CLI = new URL('../src/cli/kb-join.ts', import.meta.url).pathname;
const REPO = new URL('../', import.meta.url).pathname;
const DOMAIN = 'keybox.tail09a879.ts.net';
const NOW = Date.UTC(2026, 10, 15, 12, 0, 0);
const FLOOR_S = Math.floor(NOW / 1000) - 3600;
const UP_ARGS = 'up --qr --hostname=keybox --advertise-tags=tag:keybox --ssh=false --accept-dns=false --accept-routes=false';
const L1 =
  'This box joined Tailscale as "keybox-1" because another machine already has the name "keybox". In Tailscale\'s Machines page, remove that other machine, then rename this one to "keybox". Then restart this box (unplug it and plug it back in).';
const TAG_LINE = 'This box does not carry the tag keybox with key expiry off. Fix it on its Machines page; the box goes on by itself.';
const LINE_START = '\r\x1b[2K';

/** Scripts the fake commands read: a sequence file whose line n answers call n and whose last line answers every later call. */
const SEQ = `
seq() { n=$(cat "$KBT_DIR/$1.n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$KBT_DIR/$1.n"
  total=$(wc -l < "$KBT_DIR/$1.seq"); if [ "$n" -gt "$total" ]; then n=$total; fi; sed -n "\${n}p" "$KBT_DIR/$1.seq"; }
`;
const FAKES: Readonly<Record<string, string>> = {
  tailscale: `#!/bin/sh
${SEQ}
ok=no; [ -e "$KBT_OK" ] && ok=yes
echo "tailscale $*|ok=$ok" >> "$KBT_DIR/calls.log"
case "$1" in
  status) line=$(seq status); if [ "$line" = FAIL ]; then echo "tailscaled is not running" >&2; exit 1; fi; printf '%s\\n' "$line" ;;
  up) cat "$KBT_DIR/up.out"; cat "$KBT_DIR/up.err" >&2; exit "$(seq up)" ;;
  *) exit 64 ;;
esac
`,
  chronyc: `#!/bin/sh
${SEQ}
debris=no; [ -e "$KBT_INSTALL/rehearsal.abc" ] && debris=yes
echo "chronyc $*|debris=$debris" >> "$KBT_DIR/calls.log"
case "$*" in
  "-n waitsync 60 1") [ "$(seq sync)" = sync ] ;;
  "-n -c sources") cat "$KBT_DIR/sources.csv" ;;
  *) exit 64 ;;
esac
`,
  nft: `#!/bin/sh
echo "nft $*" >> "$KBT_DIR/calls.log"
[ "$*" = "list table inet keybox" ] || exit 64
exit "$(cat "$KBT_DIR/nft.rc" 2>/dev/null || echo 0)"
`,
  systemctl: `#!/bin/sh
echo "systemctl $*" >> "$KBT_DIR/calls.log"
case "$*" in
  "show -P ActiveEnterTimestampMonotonic keybox.service") echo 40000000 ;;
  "show -P ActiveEnterTimestampMonotonic keyrelay.service") echo 41000000 ;;
  *) exit 64 ;;
esac
`,
};

const SOURCES_2 = '^,*,time.cloudflare.com,3,6,377,10,0.0001,0.0002,0.0001\n^,+,nts.netnod.se,2,6,377,12,0.0002,0.0003,0.0002\n^,?,ptbtime1.ptb.de,0,6,0,-,0,0,0\n';
const SOURCES_0 = '^,?,time.cloudflare.com,0,6,0,-,0,0,0\n^,?,nts.netnod.se,0,6,0,-,0,0,0\n^,?,ptbtime1.ptb.de,0,6,0,-,0,0,0\n';

interface Stop extends Error {
  readonly stopped: true;
}
const stop = (): Stop => Object.assign(new Error('the test stopped the run'), { stopped: true as const });

interface World {
  readonly dir: string;
  readonly bin: string;
  readonly tty: string;
  readonly ok: string;
  readonly facts: string;
  readonly trust: string;
  readonly install: string;
  readonly env: Record<string, string>;
  readonly clock: FakeClock;
  readonly waits: number[];
}

async function world(t: TestContext): Promise<World> {
  const dir = await tempDir(t);
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const [name, body] of Object.entries(FAKES)) {
    writeFileSync(join(bin, name), body);
    chmodSync(join(bin, name), 0o755);
  }
  const install = join(dir, 'keybox-install');
  mkdirSync(install);
  const ok = join(dir, 'keybox-time', 'ok');
  mkdirSync(join(dir, 'keybox-time'));
  const w: World = {
    dir,
    bin,
    tty: join(dir, 'tty1'),
    ok,
    facts: join(dir, 'state', 'bootstrap-facts.json'),
    trust: join(dir, 'etc-keybox-trust.json'),
    install,
    env: { PATH: `${bin}:/usr/bin:/bin`, KBT_DIR: dir, KBT_OK: ok, KBT_INSTALL: install },
    clock: new FakeClock(NOW),
    waits: [],
  };
  writeFileSync(join(dir, 'sync.seq'), 'sync\n');
  writeFileSync(join(dir, 'sources.csv'), SOURCES_2);
  writeFileSync(join(dir, 'up.out'), 'QR-BLOCKS\n');
  writeFileSync(join(dir, 'up.err'), '');
  writeFileSync(join(dir, 'up.seq'), '0\n');
  return w;
}

const state = (backend: string, self?: { dns?: string; tags?: string[] | null; expiry?: string | null }): string =>
  JSON.stringify({ BackendState: backend, ...(self === undefined ? {} : { Self: { DNSName: self.dns ?? `${DOMAIN}.`, Tags: self.tags === undefined ? ['tag:keybox'] : self.tags, KeyExpiry: self.expiry ?? null } }) });
const GOOD = state('Running', {});

function script(w: World, states: readonly string[]): void {
  writeFileSync(join(w.dir, 'status.seq'), `${states.join('\n')}\n`);
}

/** Waits move the injected clock and are recorded; the run is stopped after `limit` waits so an endless loop ends the test. */
function deps(w: World, over: Partial<JoinDeps> = {}, limit = 200): JoinDeps {
  return {
    env: w.env,
    clock: w.clock,
    wait: (ms) => {
      w.waits.push(ms);
      w.clock.advance(ms);
      return w.waits.length > limit ? Promise.reject(stop()) : Promise.resolve();
    },
    tty: w.tty,
    okFile: w.ok,
    factsFile: w.facts,
    trustFile: w.trust,
    installDir: w.install,
    domain: DOMAIN,
    timeFloorMs: FLOOR_S * 1000,
    ...over,
  };
}

const read = (path: string): string => (existsSync(path) ? readFileSync(path, 'utf8') : '');
const calls = (w: World): string[] => read(join(w.dir, 'calls.log')).split('\n').filter((l) => l !== '');
const tailscaleCalls = (w: World, verb: string): string[] => calls(w).filter((l) => l.startsWith(`tailscale ${verb}`));
const screen = (w: World): string => read(w.tty);
/** The status lines of the screen: each rewrite of the line starts with the erase sequence. */
const lines = (w: World): string[] => screen(w).split(LINE_START).slice(1).map((l) => l.split('\n')[0] ?? '');
const stopped = async (run: Promise<number>): Promise<void> =>
  assert.rejects(run, (e: unknown) => typeof e === 'object' && e !== null && 'stopped' in e);

// ------------------------------------------------------------------ the time stage (step 1)

test('KBOX-64 chrony not yet synced: the step-1 line says "0 of 3 answer", no tailscale is called and no ok file exists', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'sync.seq'), 'nosync\n');
  writeFileSync(join(w.dir, 'sources.csv'), SOURCES_0);
  script(w, [GOOD]);
  await stopped(runJoin(deps(w, {}, 3)));
  assert.ok(lines(w).some((l) => l.startsWith('Key box, step 1 of 4: getting the time from secure time servers (0 of 3 answer)')), screen(w));
  assert.ok(calls(w).some((l) => l.startsWith('chronyc -n waitsync 60 1')));
  assert.deepEqual(tailscaleCalls(w, ''), []);
  assert.equal(existsSync(w.ok), false);
});

test('KBOX-64 synced with 2 authenticated sources and now at or above the floor: the ok file is written before the first tailscale call', async (t) => {
  const w = await world(t);
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(readFileSync(w.ok, 'utf8'), '', 'the ok file is empty');
  const first = tailscaleCalls(w, '')[0];
  assert.equal(first, 'tailscale status --json|ok=yes');
  assert.equal(JSON.parse(read(w.facts)).join.nts_sources, 2);
});

test('KBOX-64 synced but below the floor: the floor line, no ok file and no tailscale call', async (t) => {
  const w = await world(t);
  script(w, [GOOD]);
  await stopped(runJoin(deps(w, { timeFloorMs: NOW + 3_600_000 }, 3)));
  assert.ok(lines(w).some((l) => l.includes('the time servers report a time before this release; check the network cable')), screen(w));
  assert.equal(existsSync(w.ok), false);
  assert.deepEqual(tailscaleCalls(w, ''), []);
});

test('KBOX-64 synced but fewer than 2 sources answer: waits at step 1 and writes no ok file', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'sources.csv'), '^,*,time.cloudflare.com,3,6,377,10,0.0001,0.0002,0.0001\n^,?,nts.netnod.se,0,6,0,-,0,0,0\n');
  script(w, [GOOD]);
  await stopped(runJoin(deps(w, {}, 3)));
  assert.ok(lines(w).some((l) => l.includes('(1 of 3 answer)')), screen(w));
  assert.equal(existsSync(w.ok), false);
});

test('KBOX-64 the line shows the minutes elapsed', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'sync.seq'), 'nosync\n');
  script(w, [GOOD]);
  await stopped(runJoin(deps(w, {}, 30)));
  assert.ok(lines(w).some((l) => l.endsWith('(2 min)')), lines(w).join(' | '));
});

// ------------------------------------------------------------------ transient states never exit (M-D)

const TRANSIENT: readonly (readonly [string, readonly string[], string])[] = [
  ['status failing for 3 reads', ['FAIL', 'FAIL', 'FAIL'], 'Key box, step 2 of 4: waiting for Tailscale to start'],
  ['Starting for 3 reads', [state('Starting'), state('Starting'), state('Starting')], 'Key box, step 2 of 4: waiting for Tailscale to connect'],
  ['NoState', [state('NoState')], 'Key box, step 2 of 4: waiting for Tailscale to connect'],
  ['Running with no Self', [state('Running')], 'Key box, step 2 of 4: waiting for Tailscale to connect'],
  ['Running with an empty DNSName', [state('Running', { dns: '' })], 'Key box, step 2 of 4: waiting for Tailscale to connect'],
  ['NeedsMachineAuth', [state('NeedsMachineAuth')], "Key box, step 2 of 4: approve this box on Tailscale's Machines page"],
  ['an unknown state "Weird"', [state('Weird')], 'Key box, step 2 of 4: waiting for Tailscale (state: Weird)'],
  ['an output that is not JSON', ['not json at all'], 'Key box, step 2 of 4: waiting for Tailscale to start'],
];
for (const [title, sequence, line] of TRANSIENT) {
  test(`KBOX-64 ${title}: waits, never exits 1, and ends exit 0 once Running with the right name`, async (t) => {
    const w = await world(t);
    script(w, [...sequence, GOOD]);
    assert.equal(await runJoin(deps(w)), 0);
    assert.ok(lines(w).includes(line), `${line}\n${lines(w).join('\n')}`);
    assert.equal(tailscaleCalls(w, 'status').length, sequence.length + 1, 'one read per state, then the good one');
    assert.deepEqual(tailscaleCalls(w, 'up'), [], 'no login is started for a transient state');
    assert.ok(w.waits.every((ms) => ms === 5000), 'it rereads every 5 s');
  });
}

// ------------------------------------------------------------------ the join

test('KBOX-64 NeedsLogin with no trust.json runs exactly the tailscale up of 3.2, its output only in the tty file', async (t) => {
  const w = await world(t);
  script(w, [state('NeedsLogin'), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.deepEqual(tailscaleCalls(w, 'up').map((l) => l.split('|')[0]), [`tailscale ${UP_ARGS}`]);
  assert.ok(screen(w).includes('QR-BLOCKS'), 'the QR code is on the screen');
  assert.ok(lines(w).includes('Key box, step 2 of 4: scan this code with your phone to add the key box to Tailscale'), lines(w).join('\n'));
});

test('KBOX-64 tailscale up exiting 1 shows its first line and tries again after 60 s', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'up.seq'), '1\n0\n');
  writeFileSync(join(w.dir, 'up.err'), 'ERR-FIRST tag not defined\nsecond line\n');
  script(w, [state('NeedsLogin'), state('NeedsLogin'), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(tailscaleCalls(w, 'up').length, 2);
  assert.ok(lines(w).some((l) => l.includes('ERR-FIRST tag not defined') && l.includes('again in 60 s') && !l.includes('second line')), lines(w).join('\n'));
  assert.ok(w.waits.includes(60_000));
});

test('KBOX-64 up runs once per run: a successful up followed by another NeedsLogin read does not start it again', async (t) => {
  const w = await world(t);
  script(w, [state('NeedsLogin'), state('NeedsLogin'), state('NeedsLogin'), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(tailscaleCalls(w, 'up').length, 1);
});

// ------------------------------------------------------------------ after setup

test('KBOX-64 after setup NeedsLogin never runs up: the "no longer in Tailscale" line, still waiting after 3 reads, then exit 0', async (t) => {
  const w = await world(t);
  writeFileSync(w.trust, JSON.stringify({ domain: DOMAIN, approvers: [] }));
  script(w, [state('NeedsLogin'), state('NeedsLogin'), state('Stopped'), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.deepEqual(tailscaleCalls(w, 'up'), []);
  const line = 'This box is no longer in Tailscale. It has to be set up again (guide: If the card dies).';
  assert.equal(lines(w).filter((l) => l === line).length >= 1, true, lines(w).join('\n'));
  assert.equal(w.waits.filter((ms) => ms === 60_000).length, 3, 'it rereads every 60 s');
  assert.equal(screen(w).includes('QR-BLOCKS'), false);
});

// ------------------------------------------------------------------ the name

test('KBOX-64 a wrong name on two reads 30 s apart: the L1 text, exit 1, no facts', async (t) => {
  const w = await world(t);
  script(w, [state('Running', { dns: 'keybox-1.tail09a879.ts.net.' })]);
  assert.equal(await runJoin(deps(w)), 1);
  assert.ok(screen(w).includes(L1), screen(w));
  assert.equal(existsSync(w.facts), false, 'no facts');
  assert.deepEqual(w.waits.filter((ms) => ms === 30_000), [30_000], 'the second read comes 30 s after the first');
  assert.equal(tailscaleCalls(w, 'status').length, 2);
});

test('KBOX-64 negative control: keybox-1 once, then the right name, exits 0', async (t) => {
  const w = await world(t);
  script(w, [state('Running', { dns: 'keybox-1.tail09a879.ts.net.' }), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(screen(w).includes(L1), false);
});

test('KBOX-64 the two wrong reads must be consecutive: a wrong name, a transient state, a wrong name again does not exit', async (t) => {
  const w = await world(t);
  const wrong = state('Running', { dns: 'keybox-1.tail09a879.ts.net.' });
  script(w, [wrong, state('Starting'), wrong, GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
});

test('KBOX-64 two reads that name different wrong hosts are not the same mismatch', async (t) => {
  const w = await world(t);
  script(w, [state('Running', { dns: 'keybox-1.tail09a879.ts.net.' }), state('Running', { dns: 'keybox-2.tail09a879.ts.net.' }), GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
});

test('KBOX-64 Tailscale\'s name carries the trailing dot: the matching name, with or without the dot or in capitals, is the joined case and exits 0', async (t) => {
  for (const dns of [`${DOMAIN}.`, DOMAIN, `${DOMAIN.toUpperCase()}.`]) {
    const w = await world(t);
    script(w, [state('Running', { dns })]);
    assert.equal(await runJoin(deps(w)), 0, dns);
    assert.deepEqual(tailscaleCalls(w, 'up'), []);
  }
});

test('KBOX-64 a later boot where the name differs from the pinned host, on two reads: one line, exit 1', async (t) => {
  const w = await world(t);
  writeFileSync(w.trust, JSON.stringify({ domain: 'pinned.tail09a879.ts.net', approvers: [] }));
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 1);
  assert.equal(tailscaleCalls(w, 'status').length, 2);
  assert.equal(existsSync(w.facts), false);
  const last = screen(w).split(LINE_START).pop() ?? '';
  assert.equal(last.trim().split('\n').length, 1, 'one line');
  assert.ok(last.includes('pinned.tail09a879.ts.net'), last);
});

const DAMAGED_LINE = "This box's setup record cannot be read. The box needs a new setup.";

test('KBOX-64 M1 a damaged trust.json ({}, not JSON, a directory) shows one line and exits 1, with no tailscale up, whatever the state', async (t) => {
  for (const content of ['{}', 'not json', '{"domain":7}', 'DIR']) {
    for (const backend of [GOOD, state('NeedsLogin')]) {
      const w = await world(t);
      if (content === 'DIR') mkdirSync(w.trust);
      else writeFileSync(w.trust, content);
      script(w, [backend]);
      assert.equal(await runJoin(deps(w)), 1, `${content} ${backend}`);
      const last = screen(w).split(LINE_START).pop() ?? '';
      assert.equal(last.trim(), DAMAGED_LINE);
      assert.deepEqual(tailscaleCalls(w, 'up'), []);
      assert.equal(existsSync(w.facts), false);
    }
  }
});

test('KBOX-64 M1 the name matches KB_DOMAIN but not the pinned host: the pinned-mismatch line on two reads, exit 1', async (t) => {
  const w = await world(t);
  writeFileSync(w.trust, JSON.stringify({ domain: 'pinned.tail09a879.ts.net' }));
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 1);
  assert.equal(tailscaleCalls(w, 'status').length, 2);
  const last = screen(w).split(LINE_START).pop() ?? '';
  assert.ok(last.includes('not the name it was set up with ("pinned.tail09a879.ts.net")'), last);
});

test('KBOX-64 M1 the name matches the pinned host but not KB_DOMAIN: the L1 line on two reads, exit 1', async (t) => {
  const w = await world(t);
  writeFileSync(w.trust, JSON.stringify({ domain: 'keybox-1.tail09a879.ts.net' }));
  script(w, [state('Running', { dns: 'keybox-1.tail09a879.ts.net.' })]);
  assert.equal(await runJoin(deps(w)), 1);
  assert.equal(tailscaleCalls(w, 'status').length, 2);
  assert.ok(screen(w).includes(L1), screen(w));
});

// ------------------------------------------------------------------ tags and expiry

const TAG_CASES: readonly (readonly [string, string])[] = [
  ['a missing tag', state('Running', { tags: [] })],
  ['no Tags at all', state('Running', { tags: null })],
  ['an extra tag', state('Running', { tags: ['tag:keybox', 'tag:other'] })],
  ['another tag only', state('Running', { tags: ['tag:other'] })],
  ['a key expiry set', state('Running', { expiry: '2027-05-15T12:00:00Z' })],
];
for (const [title, bad] of TAG_CASES) {
  test(`KBOX-64 ${title}: the tag/expiry line and waiting every 30 s; fixed on the next read, exit 0`, async (t) => {
    const w = await world(t);
    script(w, [bad, GOOD]);
    assert.equal(await runJoin(deps(w)), 0);
    assert.ok(lines(w).includes(TAG_LINE), lines(w).join('\n'));
    assert.ok(w.waits.includes(30_000));
  });
}

// ------------------------------------------------------------------ joined, facts, debris

test('KBOX-64 already joined and matching: no up, exit 0, the join facts written 0644 into the existing facts file', async (t) => {
  const w = await world(t);
  mkdirSync(join(w.dir, 'state'));
  writeFileSync(w.facts, JSON.stringify({ directories: ['/etc/sudoers.d'], bench: { update: { copy_ms: 1 } } }));
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.deepEqual(tailscaleCalls(w, 'up'), []);
  assert.equal(statSync(w.facts).mode & 0o777, 0o644);
  const facts = JSON.parse(read(w.facts));
  assert.deepEqual(facts.join, { name: `${DOMAIN}.`, tags: ['tag:keybox'], key_expiry: 'none', nts_sources: 2, nft_table: true });
  assert.deepEqual(facts.directories, ['/etc/sudoers.d'], 'the other facts stay');
  assert.deepEqual(facts.bench, { update: { copy_ms: 1 } });
  assert.deepEqual(readdirSync(join(w.dir, 'state')), ['bootstrap-facts.json'], 'no temporary file is left');
});

test('KBOX-64 the facts say when the firewall table was not there', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'nft.rc'), '1\n');
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(JSON.parse(read(w.facts)).join.nft_table, false);
});

test('KBOX-64 a rehearsal.* directory is gone before the first chronyc call; a sibling not named rehearsal.* stays', async (t) => {
  const w = await world(t);
  mkdirSync(join(w.install, 'rehearsal.abc'));
  writeFileSync(join(w.install, 'rehearsal.abc', 'copy'), 'bytes');
  mkdirSync(join(w.install, 'keep'));
  writeFileSync(join(w.install, 'results.json'), '{}');
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.equal(calls(w).find((l) => l.startsWith('chronyc'))?.endsWith('|debris=no'), true);
  assert.deepEqual(readdirSync(w.install).sort(), ['keep', 'results.json']);
  assert.equal(screen(w).includes('rehearsal'), false, 'it writes no line for this');
});

test('KBOX-64 a missing install directory is not a failure', async (t) => {
  const w = await world(t);
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w, { installDir: join(w.dir, 'nowhere') })), 0);
});

test('KBOX-64 M2 a chronyc that is not on PATH counts as 0 sources: the step-1 line, no ok file, no exit; a synced chronyc that appears lets the run go on', async (t) => {
  const w = await world(t);
  const util = join(w.dir, 'util');
  mkdirSync(util);
  for (const tool of ['cat', 'wc', 'sed']) symlinkSync(`/usr/bin/${tool}`, join(util, tool));
  const chronyc = join(w.bin, 'chronyc');
  rmSync(chronyc);
  script(w, [GOOD]);
  const base = deps(w, { env: { ...w.env, PATH: `${w.bin}:${util}` } });
  const seen: boolean[] = [];
  const result = await runJoin({
    ...base,
    wait: async (ms) => {
      await base.wait(ms);
      seen.push(existsSync(w.ok));
      if (w.waits.length === 3) {
        assert.ok(lines(w).some((l) => l.startsWith('Key box, step 1 of 4: getting the time from secure time servers (0 of 3 answer)')), screen(w));
        writeFileSync(chronyc, FAKES['chronyc'] ?? '');
        chmodSync(chronyc, 0o755);
      }
    },
  });
  assert.equal(result, 0);
  assert.deepEqual(seen, [false, false, false]);
});

test('KBOX-64 L1 refclock rows (mode #) never count: two #* rows and one ^* row is not enough and waits', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'sources.csv'), '#,*,GPS,0,4,377,1,0,0,0\n#,*,PPS,0,4,377,1,0,0,0\n^,*,time.cloudflare.com,3,6,377,10,0.0001,0.0002,0.0001\n');
  script(w, [GOOD]);
  await stopped(runJoin(deps(w, {}, 3)));
  assert.ok(lines(w).some((l) => l.includes('(1 of 3 answer)')), screen(w));
  assert.equal(existsSync(w.ok), false);
});

test('KBOX-64 L4 debris rules: a rehearsal.x symlink goes but not its target, rehearsal and xrehearsal.y stay, a file rehearsal.z goes', async (t) => {
  const w = await world(t);
  const target = join(w.dir, 'victim');
  mkdirSync(target);
  writeFileSync(join(target, 'data'), 'keep');
  symlinkSync(target, join(w.install, 'rehearsal.x'));
  mkdirSync(join(w.install, 'rehearsal'));
  mkdirSync(join(w.install, 'xrehearsal.y'));
  writeFileSync(join(w.install, 'rehearsal.z'), 'bytes');
  script(w, [GOOD]);
  assert.equal(await runJoin(deps(w)), 0);
  assert.deepEqual(readdirSync(w.install).sort(), ['rehearsal', 'xrehearsal.y']);
  assert.equal(readFileSync(join(target, 'data'), 'utf8'), 'keep');
});

// ------------------------------------------------------------------ stdout and stderr

test('KBOX-64 nothing reaches stdout or stderr: tailscale up and a failing status are shown on the tty file only', async (t) => {
  const w = await world(t);
  writeFileSync(join(w.dir, 'up.err'), 'LOGIN-URL https://login.example/abc\n');
  script(w, ['FAIL', state('NeedsLogin'), GOOD]);
  const driver = `
    import { runJoin } from ${JSON.stringify(CLI)};
    const cfg = JSON.parse(process.env.KBT_CFG);
    let now = cfg.now;
    const code = await runJoin({ ...cfg.deps, env: cfg.env, clock: { now: () => now }, wait: async (ms) => { now += ms; } });
    process.exitCode = code;`;
  const base = deps(w);
  const { env, clock: _clock, wait: _wait, ...plain } = base;
  const run = spawnSync(process.execPath, ['--input-type=module', '-e', driver], {
    encoding: 'utf8',
    cwd: REPO,
    env: { PATH: process.env['PATH'] ?? '', KBT_CFG: JSON.stringify({ now: NOW, env, deps: plain }) },
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, '');
  assert.equal(run.stderr, '');
  assert.ok(screen(w).includes('QR-BLOCKS') && screen(w).includes('LOGIN-URL'));
});

// ------------------------------------------------------------------ ready mode

const READY_NOW = NOW;
function readyDeps(w: World, over: Partial<ReadyDeps> = {}): ReadyDeps {
  writeFileSync(join(w.dir, 'meminfo'), 'MemTotal:        948000 kB\nMemFree:          90000 kB\nMemAvailable:     400000 kB\n');
  return {
    env: w.env,
    clock: w.clock,
    wait: (ms) => {
      w.waits.push(ms);
      w.clock.advance(ms);
      return w.waits.length > 3 ? Promise.reject(stop()) : Promise.resolve();
    },
    tty: w.tty,
    factsFile: w.facts,
    domain: DOMAIN,
    tlsOk: () => Promise.resolve(true),
    meminfoFile: join(w.dir, 'meminfo'),
    uptimeMs: () => 100_000,
    socketBornMs: (path) => (path.includes('keyrelay') ? READY_NOW - 59_000 + 9_000 : READY_NOW - 60_000 + 12_000),
    coreSocket: '/run/keybox/http.sock',
    relaySocket: '/run/keyrelay/http.sock',
    ...over,
  };
}
const seedBench = (w: World, update: Record<string, number>, over: unknown[] = []): void => {
  mkdirSync(join(w.dir, 'state'), { recursive: true });
  writeFileSync(w.facts, JSON.stringify({ join: { name: DOMAIN }, bench: { update, over } }));
};

test('KBOX-64 ready: the TLS check failing shows the step-4 line and never "Key box ready."', async (t) => {
  const w = await world(t);
  seedBench(w, {});
  await stopped(runReady(readyDeps(w, { tlsOk: () => Promise.resolve(false) })));
  assert.ok(lines(w).includes('Key box, step 4 of 4: waiting for its certificate (if this lasts over 10 minutes: HTTPS must be on in Tailscale\'s DNS page)'), lines(w).join('\n'));
  assert.equal(screen(w).includes('Key box ready.'), false);
});

test('KBOX-64 ready: a pass records the start times and MemAvailable, none of the update items over, then "Key box ready."', async (t) => {
  const w = await world(t);
  seedBench(w, { copy_ms: 30_000, bytes: 150_000_000, self_check_ms: 5_000, peak_rss_kb: 400_000 - 65_536 });
  assert.equal(await runReady(readyDeps(w)), 0);
  const facts = JSON.parse(read(w.facts));
  assert.deepEqual(facts.ready, { core_start_ms: 12_000, relay_start_ms: 9_000, mem_available_kb: 400_000 });
  assert.deepEqual(facts.bench.over, []);
  assert.deepEqual(facts.join, { name: DOMAIN }, 'the other facts stay');
  assert.ok(screen(w).includes('Key box ready.'));
  assert.equal(statSync(w.facts).mode & 0o777, 0o644);
});

test('KBOX-64 ready: each update item over its budget is listed in bench.over with its measured value and budget', async (t) => {
  const w = await world(t);
  seedBench(w, { copy_ms: 30_001, bytes: 1, self_check_ms: 5_001, peak_rss_kb: 400_000 - 65_535 }, [{ item: 'sha256', measured: 9, budget: 5 }]);
  assert.equal(await runReady(readyDeps(w)), 0);
  const over = JSON.parse(read(w.facts)).bench.over;
  assert.deepEqual(over, [
    { item: 'sha256', measured: 9, budget: 5 },
    { item: 'update.copy', measured: 30_001, budget: 30_000, unit: 'ms' },
    { item: 'update.self_check', measured: 5_001, budget: 5_000, unit: 'ms' },
    { item: 'update.memory', measured: 65_535, budget: 65_536, unit: 'KiB' },
  ]);
});

test('KBOX-64 ready: a start time over its budget is listed, and running again does not list an item twice', async (t) => {
  const w = await world(t);
  seedBench(w, { copy_ms: 1, bytes: 1, self_check_ms: 1, peak_rss_kb: 1 });
  const slow = readyDeps(w, { socketBornMs: (p) => (p.includes('keyrelay') ? READY_NOW - 59_000 + 10_001 : READY_NOW - 60_000 + 20_001) });
  assert.equal(await runReady(slow), 0);
  assert.equal(await runReady(slow), 0);
  assert.deepEqual(JSON.parse(read(w.facts)).bench.over, [
    { item: 'core.start', measured: 20_001, budget: 20_000, unit: 'ms' },
    { item: 'relay.start', measured: 10_001, budget: 10_000, unit: 'ms' },
  ]);
});

test('KBOX-64 ready: a start time that cannot be measured is recorded as null and never stops the box being ready', async (t) => {
  const w = await world(t);
  seedBench(w, { copy_ms: 1, bytes: 1, self_check_ms: 1, peak_rss_kb: 1 });
  assert.equal(await runReady(readyDeps(w, { socketBornMs: () => Number.NaN })), 0);
  const facts = JSON.parse(read(w.facts));
  assert.equal(facts.ready.core_start_ms, null);
  assert.ok(screen(w).includes('Key box ready.'));
});

test('KBOX-64 the real TLS check passes for the right name against a trusted chain and fails for a wrong name, an unknown chain and a closed port', async (t) => {
  const cert = await selfSignedCertificate(t, DOMAIN);
  const server = createTlsServer({ key: cert.key, cert: cert.cert }, (socket) => socket.end());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address !== null && typeof address === 'object');
  assert.equal(await tlsCheck(DOMAIN, address.port, cert.cert), true);
  assert.equal(await tlsCheck('other.tail09a879.ts.net', address.port, cert.cert), false, 'the name is checked');
  assert.equal(await tlsCheck(DOMAIN, address.port), false, 'the chain is checked');
  const closed = address.port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  assert.equal(await tlsCheck(DOMAIN, closed, cert.cert), false);
});

// ------------------------------------------------------------------ the real entry

test('KBOX-64 --self-check loads every module, exits 0, touches no file and calls no command', async (t) => {
  const w = await world(t);
  const before = readdirSync(w.dir).sort();
  const run = spawnSync(process.execPath, [CLI, '--self-check'], { encoding: 'utf8', cwd: w.dir, env: { ...w.env } });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout + run.stderr, '');
  assert.deepEqual(readdirSync(w.dir).sort(), before, 'nothing was created');
  assert.equal(existsSync(join(w.dir, 'calls.log')), false, 'no command was called');
});

test('KBOX-64 join without KB_DOMAIN stops on the tty file with a non-zero exit before any command or file', async (t) => {
  const w = await world(t);
  const run = spawnSync(process.execPath, [CLI, 'join'], { encoding: 'utf8', cwd: w.dir, env: { ...w.env, KB_TTY: w.tty } });
  assert.notEqual(run.status, 0);
  assert.equal(run.stdout + run.stderr, '');
  assert.ok(screen(w).includes('KB_DOMAIN'), screen(w));
  assert.equal(existsSync(join(w.dir, 'calls.log')), false);
});

test('KBOX-64 an unknown mode is refused on the tty file, not run', async (t) => {
  const w = await world(t);
  const run = spawnSync(process.execPath, [CLI, 'frobnicate'], { encoding: 'utf8', cwd: w.dir, env: { ...w.env, KB_TTY: w.tty } });
  assert.notEqual(run.status, 0);
  assert.equal(run.stdout + run.stderr, '');
  assert.equal(existsSync(join(w.dir, 'calls.log')), false);
});

test('KBOX-64 L2 KB_TIME_FLOOR unset or not a number is a configuration error on the tty file naming it: exit 2, no command', async (t) => {
  for (const floor of [undefined, 'abc', '-5']) {
    const w = await world(t);
    const env: Record<string, string> = { ...w.env, KB_TTY: w.tty, KB_DOMAIN: DOMAIN, KB_STATE_DIR: join(w.dir, 'state') };
    if (floor !== undefined) env['KB_TIME_FLOOR'] = floor;
    const run = spawnSync(process.execPath, [CLI, 'join'], { encoding: 'utf8', cwd: w.dir, env });
    assert.equal(run.status, 2, `${floor}`);
    assert.equal(run.stdout + run.stderr, '');
    assert.ok(screen(w).includes('KB_TIME_FLOOR'), screen(w));
    assert.equal(existsSync(join(w.dir, 'calls.log')), false);
  }
});

test('KBOX-64 L3 a relative KB_TTY is a configuration error with no stack trace, exit 2 (exit 1 stays for the name and the setup record)', async (t) => {
  const w = await world(t);
  const run = spawnSync(process.execPath, [CLI, 'join'], { encoding: 'utf8', cwd: w.dir, env: { ...w.env, KB_TTY: 'relative/path', KB_DOMAIN: DOMAIN, KB_TIME_FLOOR: '1' } });
  assert.equal(run.status, 2);
  assert.equal(run.stdout, '');
  assert.ok(run.stderr.includes('KB_TTY'), run.stderr);
  assert.equal(/\n\s+at /.test(run.stderr), false, run.stderr);
  assert.equal(existsSync(join(w.dir, 'calls.log')), false);
});

// ------------------------------------------------------------------ the unit files and the gate path

const unit = (name: string): string => readFileSync(join(REPO, 'deploy', name), 'utf8');
const service = (name: string): Map<string, string[]> => directives(unit(name), 'Service');
const section = (name: string, which: string): Map<string, string[]> => directives(unit(name), which);

test('KBOX-64 the gate path in src/pure/time-gate.ts is /run/keybox-time/ok and the file holds exactly that line', () => {
  assert.equal(TIME_OK_FILE, '/run/keybox-time/ok');
  assert.equal(readFileSync(join(REPO, 'src/pure/time-gate.ts'), 'utf8'), "export const TIME_OK_FILE = '/run/keybox-time/ok';\n");
});

test('KBOX-64 kb-join.service is a root oneshot on tty1 that waits for ever, never restarts, and has no device access', () => {
  const s = service('kb-join.service');
  const one = (key: string): string | undefined => s.get(key)?.[0];
  assert.equal(one('Type'), 'oneshot');
  assert.equal(one('RemainAfterExit'), 'yes');
  assert.equal(one('TimeoutStartSec'), 'infinity');
  assert.equal(one('Restart'), 'no');
  assert.equal(one('User'), 'root');
  assert.equal(one('StandardOutput'), 'tty');
  assert.equal(one('StandardError'), 'tty');
  assert.equal(one('TTYPath'), '/dev/tty1');
  assert.equal(one('ExecStart'), '/opt/keybox/current/bin/node /opt/keybox/current/src/cli/kb-join.ts join');
  assert.equal(s.has('DeviceAllow'), false);
  assert.equal(s.has('SupplementaryGroups'), false);
  assert.deepEqual(section('kb-join.service', 'Install').get('WantedBy'), ['multi-user.target']);
});

test('KBOX-64 kb-join.service is ordered after kb-install.service with no Wants or Requires on it, and requires the firewall', () => {
  const u = section('kb-join.service', 'Unit');
  const after = words(u.get('After'));
  assert.ok(after.includes('kb-install.service'));
  for (const key of ['Wants', 'Requires', 'BindsTo', 'PartOf', 'Upholds']) assert.equal(words(u.get(key)).includes('kb-install.service'), false, `${key} does not name kb-install.service`);
  assert.deepEqual(words(u.get('Requires')), ['kb-firewall.service']);
  assert.ok(after.includes('kb-firewall.service'));
  assert.deepEqual(words(u.get('Wants')).sort(), ['chrony.service', 'network-online.target', 'tailscaled.service']);
  for (const name of ['chrony.service', 'tailscaled.service', 'network-online.target']) assert.ok(after.includes(name), name);
  assert.equal(after.includes('time-sync.target'), false, 'no unit relies on time-sync.target');
});

test('KBOX-64 kb-join.service makes /run/keybox-time 0755 and keeps it across the unit stopping', () => {
  const s = service('kb-join.service');
  assert.deepEqual(s.get('RuntimeDirectory'), ['keybox-time']);
  assert.deepEqual(s.get('RuntimeDirectoryMode'), ['0755']);
  assert.deepEqual(s.get('RuntimeDirectoryPreserve'), ['yes']);
});

test('KBOX-64 kb-ready.service has the same output settings and requires caddy and keybox, wanting the relay', () => {
  const s = service('kb-ready.service');
  const u = section('kb-ready.service', 'Unit');
  for (const [key, value] of [['Type', 'oneshot'], ['RemainAfterExit', 'yes'], ['TimeoutStartSec', 'infinity'], ['User', 'root'], ['StandardOutput', 'tty'], ['StandardError', 'tty'], ['TTYPath', '/dev/tty1']] as const) {
    assert.deepEqual(s.get(key), [value], key);
  }
  assert.equal(s.get('ExecStart')?.[0], '/opt/keybox/current/bin/node /opt/keybox/current/src/cli/kb-join.ts ready');
  assert.equal(s.has('DeviceAllow'), false);
  assert.equal(s.has('SupplementaryGroups'), false);
  assert.deepEqual(words(u.get('Requires')).sort(), ['caddy.service', 'keybox.service']);
  assert.deepEqual(words(u.get('Wants')), ['keyrelay.service']);
  for (const name of ['caddy.service', 'keybox.service', 'keyrelay.service']) assert.ok(words(u.get('After')).includes(name), name);
});
