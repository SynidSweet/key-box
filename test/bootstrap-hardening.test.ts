// The hardening item of deploy/cloud-init.yaml run alone under sh, with $K at a temp tree and stand-ins on PATH. The radios go off
// through /sys/class/rfkill (the Ubuntu raspi image has no `rfkill` program), and the config.txt lines land under [all].
// Nothing here runs a real userdel, passwd, apt-get, systemctl, setterm, sysctl or rfkill, and nothing writes under the real /sys.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { runShell, tempDir } from './kit/index.ts';

const repo = new URL('../', import.meta.url).pathname;
const cloudInit = readFileSync(join(repo, 'deploy/cloud-init.yaml'), 'utf8');

const LINES = ['dtoverlay=disable-wifi', 'dtoverlay=disable-bt', 'hdmi_force_hotplug=1', 'gpu_mem=16'];
const CM4 = '[all]\narm_64bit=1\n[cm4]\ndtoverlay=dwc2,dr_mode=host\n';

/** The runcmd item that holds `step hardening`, as the script text cloud-init hands to sh. */
function hardeningItem(): string {
  const lines = cloudInit.split('\n');
  const from = lines.indexOf('runcmd:');
  assert.ok(from >= 0, 'cloud-init has runcmd');
  const items: string[] = [];
  for (const line of lines.slice(from + 1)) {
    if (/^\S/.test(line)) break;
    if (/^ {2}#/.test(line)) continue;
    if (/^ {2}- \|$/.test(line)) items.push('');
    else if (/^ {2}- /.test(line)) items.push(`${line.slice(4)}\n`);
    else if (line.startsWith('    ') || line === '') items[items.length - 1] = `${items.at(-1) ?? ''}${line.slice(4)}\n`;
  }
  const found = items.filter((i) => i.includes('step hardening'));
  assert.equal(found.length, 1, 'exactly one runcmd item says step hardening');
  return found[0] ?? '';
}

const STAND_INS: Readonly<Record<string, string>> = {
  userdel: 'echo "userdel $*" >> "$EVENTS"',
  passwd: 'echo "passwd $*" >> "$EVENTS"',
  'apt-get': 'echo "apt-get $*" >> "$EVENTS"',
  systemctl: 'echo "systemctl $*" >> "$EVENTS"',
  setterm: 'echo "setterm $*" >> "$EVENTS"',
  sysctl: 'echo "sysctl $*" >> "$EVENTS"',
  step: 'echo "step $*" >> "$EVENTS"',
  rfkill: 'echo "rfkill $*" >> "$EVENTS"; exit 127',
};

interface Run {
  readonly status: number | null;
  readonly stderr: string;
  readonly read: (path: string) => string;
  readonly events: string;
}

interface Setup {
  /** rfkill entries: name -> [type, soft]. Absent: no sys/class/rfkill at all. */
  readonly radios?: Readonly<Record<string, readonly [string, string]>>;
  /** Names of entries whose `soft` is a directory, which fails any write even as root. */
  readonly softIsDir?: readonly string[];
  readonly config?: string;
}

/** Runs the hardening item (under the item's `set -eu`) once or more over one fixture tree. */
async function harden(t: TestContext, setup: Setup = {}, times = 1): Promise<Run> {
  const dir = await tempDir(t);
  const k = join(dir, 'root');
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const d of ['boot/firmware', 'etc/sysctl.d', 'etc/systemd', 'dev']) mkdirSync(join(k, d), { recursive: true });
  writeFileSync(join(k, 'boot/firmware/config.txt'), setup.config ?? '[all]\narm_64bit=1\n');
  writeFileSync(join(k, 'boot/firmware/cmdline.txt'), 'console=tty1 root=LABEL=writable\n');
  writeFileSync(join(k, 'dev/tty1'), '');
  for (const [name, [type, soft]] of Object.entries(setup.radios ?? {})) {
    const r = join(k, 'sys/class/rfkill', name);
    mkdirSync(r, { recursive: true });
    writeFileSync(join(r, 'type'), `${type}\n`);
    if (setup.softIsDir?.includes(name) === true) mkdirSync(join(r, 'soft'));
    else writeFileSync(join(r, 'soft'), `${soft}\n`);
  }
  for (const [name, body] of Object.entries(STAND_INS)) writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  const item = hardeningItem();
  const script = [`export PATH='${bin}':"$PATH" K='${k}' EVENTS='${join(dir, 'events.log')}'`, 'set -eu', ...Array<string>(times).fill(`( ${item.replace(/\n$/, '')}\n)`)].join('\n');
  const run = runShell(script, dir);
  const read = (p: string): string => readFileSync(join(k, p), 'utf8');
  const log = join(dir, 'events.log');
  return { status: run.status, stderr: run.stderr, read, events: existsSync(log) ? readFileSync(log, 'utf8') : '' };
}

const withLines = (config: string): string => config + LINES.map((l) => `${l}\n`).join('');

test('radio-off: Wi-Fi and Bluetooth are soft-blocked through sysfs, any other radio is left, and the rfkill program is never called', async (t) => {
  const r = await harden(t, { radios: { rfkill0: ['wlan', '0'], rfkill1: ['bluetooth', '0'], rfkill2: ['nfc', '0'] } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.read('sys/class/rfkill/rfkill0/soft'), '1\n');
  assert.equal(r.read('sys/class/rfkill/rfkill1/soft'), '1\n');
  assert.equal(r.read('sys/class/rfkill/rfkill2/soft'), '0\n');
  assert.doesNotMatch(r.events, /^rfkill/m, 'the item must not need an rfkill program');
});

test('radio-off: a tree with no sys/class/rfkill is nothing to do, and the lines after the radio step still run', async (t) => {
  const r = await harden(t);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.read('boot/firmware/config.txt'), withLines('[all]\narm_64bit=1\n[all]\n'));
});

test('radio-off: a soft that cannot be written stops the item, and nothing after it runs', async (t) => {
  const r = await harden(t, { radios: { rfkill0: ['wlan', '0'] }, softIsDir: ['rfkill0'] });
  assert.notEqual(r.status, 0);
  assert.equal(r.read('boot/firmware/config.txt'), '[all]\narm_64bit=1\n', 'the config.txt lines come after the radio step');
});

test('radio-off: config.txt that ends inside a [cm4] section gets its lines under a new [all]', async (t) => {
  const r = await harden(t, { config: CM4 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.read('boot/firmware/config.txt'), `${CM4}[all]\n${LINES.join('\n')}\n`);
});

test('radio-off: a second run adds nothing to config.txt', async (t) => {
  const once = await harden(t, { config: CM4 }, 1);
  const twice = await harden(t, { config: CM4 }, 2);
  assert.equal(twice.status, 0, twice.stderr);
  assert.equal(twice.read('boot/firmware/config.txt'), once.read('boot/firmware/config.txt'));
});

test('radio-off: with all four lines already present config.txt is byte-identical', async (t) => {
  const config = withLines(CM4);
  const r = await harden(t, { config });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.read('boot/firmware/config.txt'), config);
});

test('radio-off: a config.txt with no final newline keeps its last line whole when the [all] line is appended', async (t) => {
  const r = await harden(t, { config: CM4.slice(0, -1) });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.read('boot/firmware/config.txt'), `${CM4}[all]\n${LINES.join('\n')}\n`);
});
