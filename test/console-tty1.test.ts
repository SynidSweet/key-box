// KBOX-66: the console is tty1 and kb-code shows each code with the box's address as text and a QR code. The console sink is a
// temp file in every test; no real tty, systemctl or tailscale is touched.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { FakeClock, directives, runNode, seededRandom, tempDir, words } from './kit/index.ts';
import { parseWordlist } from '../src/pure/codes.ts';
import { pagesOrigin } from '../src/pure/box-origins.ts';
import { renderQr } from '../src/pure/qr.ts';
import { createCodeRoot } from '../src/shell/console.ts';

const WORDLIST = parseWordlist(readFileSync(new URL('../src/data/wordlist.txt', import.meta.url), 'utf8'));
const DEPLOY = new URL('../deploy/', import.meta.url).pathname;
const KB_CODE = new URL('../src/cli/kb-code.ts', import.meta.url).pathname;
const HOST = 'keybox.tail09a879.ts.net';
const BOOT_A = 'c0ffee00-0000-4000-8000-00000000000a';
const BOOT_B = 'c0ffee00-0000-4000-8000-00000000000b';
const NO_NAME = 'Key box: this box has no name configured. Write the card again.';

interface Box {
  readonly dir: string;
  readonly device: string;
  readonly codesDir: string;
  /** Runs kb-code once; `domain` undefined leaves KB_DOMAIN unset. */
  run(mode: string, options?: { readonly domain?: string | undefined; readonly bootId?: string }): { status: number | null; stdout: string; stderr: string };
  trust(): void;
  shown(): string;
  /** Root's check of a typed code against the kept hash, as the installer does it. */
  check(kind: 'setup' | 'recovery', typed: string, bootId?: string): ReturnType<ReturnType<typeof createCodeRoot>['check']>;
}

async function box(t: Parameters<typeof tempDir>[0]): Promise<Box> {
  const dir = await tempDir(t);
  const device = join(dir, 'console');
  writeFileSync(device, '');
  const config = join(dir, 'runtime.config.json');
  writeFileSync(config, JSON.stringify({ console_device: device }));
  const bootFile = join(dir, 'boot_id');
  const trustFile = join(dir, 'trust.json');
  const codesDir = join(dir, 'codes');
  const codes = createCodeRoot({ dir: codesDir, sink: () => undefined, random: seededRandom(1), clock: new FakeClock(), wordlist: WORDLIST });
  return {
    dir,
    device,
    codesDir,
    run(mode, options = {}) {
      writeFileSync(bootFile, `${options.bootId ?? BOOT_A}\n`);
      const env = { KB_CODES_DIR: codesDir, KB_BOOT_ID_FILE: bootFile, KB_RUNTIME_CONFIG: config, KB_TRUST_FILE: trustFile, KB_DOMAIN: 'domain' in options ? options.domain : HOST };
      const set = Object.entries(env).map(([k, v]) => (v === undefined ? `delete process.env.${k};` : `process.env.${k}=${JSON.stringify(v)};`)).join('');
      return runNode(['--input-type=module', '-e', `${set}process.argv[2]=${JSON.stringify(mode)};await import(${JSON.stringify(KB_CODE)});`], dir);
    },
    trust: () => writeFileSync(trustFile, '{"domain":"x"}'),
    shown: () => readFileSync(device, 'utf8'),
    check: (kind, typed, bootId = BOOT_A) => codes.check(kind, typed, { bootId, trustExists: existsSync(trustFile) }),
  };
}

const codeIn = (shown: string, kind: 'setup' | 'recovery'): string => {
  const found = new RegExp(`key box ${kind} code: ([a-z]+(?: [a-z]+){11})`).exec(shown)?.[1];
  assert.ok(found !== undefined, `the console shows a ${kind} code`);
  return found;
};

// --- the device and the unit -------------------------------------------------------------------------------------------

test('KBOX-66 the console device is /dev/tty1 and kb-code.service may write exactly that device (catches the old ttyAMA0 left in either file)', () => {
  const config = JSON.parse(readFileSync(join(DEPLOY, 'runtime.config.json'), 'utf8')) as { console_device: string };
  assert.equal(config.console_device, '/dev/tty1');
  const unit = directives(readFileSync(join(DEPLOY, 'kb-code.service'), 'utf8'), 'Service');
  assert.deepEqual(words(unit.get('DeviceAllow')), ['/dev/tty1', 'w']);
});

test('KBOX-66 kb-code.service runs the boot mode after and requiring kb-join, before core, with default dependencies off (catches a unit that shows a code before the name is settled)', () => {
  const text = readFileSync(join(DEPLOY, 'kb-code.service'), 'utf8');
  const service = directives(text, 'Service');
  assert.deepEqual(words(service.get('ExecStart')), ['/opt/keybox/current/bin/node', '/opt/keybox/current/src/cli/kb-code.ts', 'boot']);
  const unit = directives(text, 'Unit');
  assert.ok((unit.get('After') ?? []).flatMap((v) => words([v])).includes('kb-join.service'), 'After=kb-join.service');
  assert.ok((unit.get('Requires') ?? []).flatMap((v) => words([v])).includes('kb-join.service'), 'Requires=kb-join.service');
  assert.ok((unit.get('Before') ?? []).flatMap((v) => words([v])).includes('keybox.service'), 'Before=keybox.service');
  assert.deepEqual(unit.get('DefaultDependencies'), ['no']);
});

// --- boot mode ---------------------------------------------------------------------------------------------------------

test('KBOX-66 boot with no trust.json shows a setup code, the /setup address and exactly that address as a QR code (catches boot mode showing a recovery code or the wrong path)', async (t) => {
  const b = await box(t);
  const run = b.run('boot');
  assert.equal(run.status, 0, run.stderr);
  const shown = b.shown();
  codeIn(shown, 'setup');
  assert.equal(shown.includes('recovery code'), false);
  assert.ok(shown.includes(renderQr(`${pagesOrigin(HOST)}/setup`)), 'the QR block of the /setup address, with its text under it');
  assert.ok(shown.includes('https://keybox.tail09a879.ts.net:8443/setup'));
  assert.equal(shown.includes('/recover'), false);
});

test('KBOX-66 a second boot before setup makes a new code; the first is dead and only the second passes root\'s check (catches boot mode that keeps the old hash)', async (t) => {
  const b = await box(t);
  assert.equal(b.run('boot', { bootId: BOOT_A }).status, 0);
  const first = codeIn(b.shown(), 'setup');
  const before = b.shown().length;
  assert.equal(b.run('boot', { bootId: BOOT_B }).status, 0);
  const second = codeIn(b.shown().slice(before), 'setup');
  assert.notEqual(second, first);
  assert.deepEqual(b.check('setup', first), { ok: false, code: 'wrong_code' });
  assert.deepEqual(b.check('setup', second), { ok: true });
});

test('KBOX-66 boot with trust.json makes the recovery code and the /recover address and QR; a second boot run in the same boot shows nothing new (catches boot mode ignoring trust or same_boot)', async (t) => {
  const b = await box(t);
  b.trust();
  assert.equal(b.run('boot').status, 0);
  const shown = b.shown();
  const code = codeIn(shown, 'recovery');
  assert.equal(shown.includes('setup code'), false);
  assert.ok(shown.includes(renderQr(`${pagesOrigin(HOST)}/recover`)));
  assert.ok(shown.includes('https://keybox.tail09a879.ts.net:8443/recover'));
  assert.deepEqual(b.check('recovery', code), { ok: true });
  assert.equal(existsSync(join(b.codesDir, 'setup.hash')), false, 'no setup hash is made once trust exists');
  assert.equal(b.run('boot').status, 0);
  assert.equal(b.shown(), shown, 'the same boot id writes no new code and no new address');
});

// --- the address under each mode ---------------------------------------------------------------------------------------

test('KBOX-66 setup writes the /setup address and QR; recovery writes the /recover address and QR (catches a mode that shows no address or the other mode\'s)', async (t) => {
  const s = await box(t);
  assert.equal(s.run('setup').status, 0);
  codeIn(s.shown(), 'setup');
  assert.ok(s.shown().includes(renderQr(`${pagesOrigin(HOST)}/setup`)));
  const r = await box(t);
  assert.equal(r.run('recovery').status, 0);
  codeIn(r.shown(), 'recovery');
  assert.ok(r.shown().includes(renderQr(`${pagesOrigin(HOST)}/recover`)));
});

test('KBOX-66 setup after trust.json exists writes nothing to the console (catches an address shown without a code)', async (t) => {
  const b = await box(t);
  b.trust();
  const run = b.run('setup');
  assert.equal(run.status, 0, run.stderr);
  assert.equal(b.shown(), '');
});

test('KBOX-20 the boot-mode code reaches the sink only: not stdout, stderr or any kept file (catches the new mode printing the code)', async (t) => {
  const b = await box(t);
  const run = b.run('boot');
  assert.equal(run.status, 0, run.stderr);
  const code = codeIn(b.shown(), 'setup');
  assert.equal(run.stdout.includes(code) || run.stderr.includes(code), false);
  for (const f of readdirSync(b.codesDir)) assert.equal(readFileSync(join(b.codesDir, f), 'utf8').includes(code), false, f);
  assert.match(run.stdout, /^kb-code: \w+\n$/, 'stdout carries one fixed status word');
});

// --- KB_DOMAIN missing or malformed -----------------------------------------------------------------------------------

const BAD_DOMAINS: readonly (string | undefined)[] = [undefined, '', 'localhost', 'Keybox.Tail09a879.ts.net', 'keybox.ts.net:8443', 'https://keybox.ts.net', 'key box.ts.net', 'keybox.ts.net/setup'];

for (const mode of ['setup', 'recovery', 'boot']) {
  test(`KBOX-66 ${mode} with KB_DOMAIN missing or malformed makes no code, leaves the kept hash alone and writes the one no-name line (catches a code shown with no address or a hand-built URL)`, async (t) => {
    const b = await box(t);
    assert.equal(b.run(mode).status, 0);
    const kept = readdirSync(b.codesDir).map((f) => [f, readFileSync(join(b.codesDir, f), 'utf8')]);
    assert.equal(kept.length, 1, 'the valid run kept one hash');
    for (const domain of BAD_DOMAINS) {
      const before = b.shown().length;
      const run = b.run(mode, { domain, bootId: BOOT_B });
      assert.equal(run.status, 0, `${String(domain)}: ${run.stderr}`);
      assert.equal(b.shown().slice(before), `${NO_NAME}\n`, String(domain));
      assert.deepEqual(readdirSync(b.codesDir).map((f) => [f, readFileSync(join(b.codesDir, f), 'utf8')]), kept, `hash unchanged for ${String(domain)}`);
    }
  });
}
