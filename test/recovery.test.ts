// KBOX-20: recovery of the approver. This file holds the root half (kb-code makes the code, root checks it), the unit text,
// and core's half through the TrustPort. Times come from a FakeClock.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { FakeClock, runNode, seededRandom, tempDir } from './kit/index.ts';
import { directives, words } from './kit/index.ts';
import { codeHash, parseWordlist } from '../src/pure/codes.ts';
import { createCodeRoot } from '../src/shell/console.ts';

const WORDLIST = parseWordlist(readFileSync(new URL('../src/data/wordlist.txt', import.meta.url), 'utf8'));
const MINUTE = 60_000;

async function root(t: import('node:test').TestContext, seed = 5) {
  const dir = join(await tempDir(t), 'codes');
  const clock = new FakeClock(1_700_000_000_000);
  const sink: string[] = [];
  const codes = createCodeRoot({ dir, sink: (text) => void sink.push(text), random: seededRandom(seed), clock, wordlist: WORDLIST });
  const lastCode = (): string => {
    const line = sink.at(-1) ?? '';
    const found = /([a-z]+(?: [a-z]+){11})/.exec(line);
    assert.ok(found, 'the sink got a 12-word code');
    return found[1] ?? '';
  };
  return { dir, clock, sink, codes, lastCode };
}

test('KBOX-20 no recovery code exists until a boot is seen', async (t) => {
  const { dir, codes, sink } = await root(t);
  assert.deepEqual(codes.check('recovery', 'abandon '.repeat(12), { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'no_code' });
  assert.deepEqual(sink, []);
  assert.equal(readdirSync(join(dir, '..')).includes('codes') && readdirSync(dir).includes('recovery.hash'), false);
});

test('KBOX-20 a core restart in the same boot writes no new code and the first stays valid; a new boot voids it', async (t) => {
  const { codes, sink, lastCode } = await root(t);
  assert.equal(codes.writeRecoveryCode('boot-a'), 'written');
  const first = lastCode();
  assert.equal(codes.writeRecoveryCode('boot-a'), 'same_boot');
  assert.equal(sink.length, 1, 'no second code on the console');
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-a', trustExists: true }), { ok: true });
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-b', trustExists: true }), { ok: false, code: 'stale_boot' });
  assert.equal(codes.writeRecoveryCode('boot-b'), 'written');
  assert.notEqual(lastCode(), first);
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-b', trustExists: true }), { ok: false, code: 'wrong_code' }, 'the old code is void');
});

test('KBOX-20 the recovery code is valid at 30 minutes and refused at 30 minutes plus 1 ms', async (t) => {
  for (const [after, verdict] of [[30 * MINUTE, { ok: true }], [30 * MINUTE + 1, { ok: false, code: 'expired' }]] as const) {
    const { codes, clock, lastCode } = await root(t);
    codes.writeRecoveryCode('boot-a');
    clock.advance(after);
    assert.deepEqual(codes.check('recovery', lastCode(), { bootId: 'boot-a', trustExists: true }), verdict, `${after} ms`);
  }
});

test('KBOX-20 a wrong code is refused and the code stays valid; a used code is refused the second time', async (t) => {
  const { codes, lastCode } = await root(t);
  codes.writeRecoveryCode('boot-a');
  const code = lastCode();
  const wrong = code.split(' ').reverse().join(' ');
  assert.deepEqual(codes.check('recovery', wrong, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('recovery', 'not words', { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('recovery', code.toUpperCase().replaceAll(' ', '   '), { bootId: 'boot-a', trustExists: true }), { ok: true }, 'case and spacing are normalised');
  codes.consume('recovery');
  assert.deepEqual(codes.check('recovery', code, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'no_code' });
});

test('KBOX-20 KBOX-49 root keeps only the hash, in a 0700 directory with 0600 files that the keybox user cannot read', async (t) => {
  const { dir, codes, lastCode } = await root(t);
  codes.writeRecoveryCode('boot-a');
  const recoveryCode = lastCode();
  assert.equal(codes.writeSetupCode(false), 'written');
  const setupCode = lastCode();
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  for (const f of readdirSync(dir)) assert.equal(statSync(join(dir, f)).mode & 0o777, 0o600, f);
  assert.deepEqual(readdirSync(dir).sort(), ['recovery.hash', 'setup.hash']);
  const kept = JSON.parse(readFileSync(join(dir, 'recovery.hash'), 'utf8')) as Record<string, unknown>;
  assert.deepEqual(kept, { hash: codeHash(recoveryCode), boot_id: 'boot-a', written_at: 1_700_000_000_000 });
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'setup.hash'), 'utf8')), { hash: codeHash(setupCode), written_at: 1_700_000_000_000 });
  for (const f of readdirSync(dir)) {
    const body = readFileSync(join(dir, f), 'utf8');
    assert.equal(body.includes(recoveryCode) || body.includes(setupCode), false, `no words in ${f}`);
  }
});

test('KBOX-49 the setup code is refused by root once trust.json exists, even when it is right; a wrong one leaves it valid', async (t) => {
  const { codes, lastCode } = await root(t);
  assert.equal(codes.writeSetupCode(false), 'written');
  const code = lastCode();
  assert.deepEqual(codes.check('setup', code, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'trust_exists' });
  assert.deepEqual(codes.check('setup', code.split(' ').slice(1).join(' '), { bootId: 'boot-a', trustExists: false }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('setup', code, { bootId: 'boot-a', trustExists: false }), { ok: true });
  assert.equal(codes.writeSetupCode(true), 'trust_exists', 'no setup code once trust.json exists');
});

test('KBOX-49 the code is 12 words from the 2048-word BIP-39 English list, 11 bits each (BIP-39 published vectors)', async (t) => {
  // trezor/python-mnemonic vectors.json, the reference vectors of BIP-39: entropy 00..00 gives "abandon x11 about" and
  // 7f..7f gives "legal winner ... yellow". Their 132 bits are the 128 entropy bits and 4 checksum bits (SHA-256, first nibble).
  const { createHash } = await import('node:crypto');
  const { codeFromBytes } = await import('../src/pure/codes.ts');
  const bits132 = (entropy: Buffer): Uint8Array => Uint8Array.from([...entropy, (createHash('sha256').update(entropy).digest()[0] ?? 0) & 0xf0]);
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0)), WORDLIST), `${'abandon '.repeat(11)}about`);
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0x7f)), WORDLIST), 'legal winner thank year wave sausage worth useful legal winner thank yellow');
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0x80)), WORDLIST), 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above');
  assert.equal(WORDLIST.length, 2048);
  void t;
});

test('KBOX-20 kb-code writes the code to the console sink only: not to stdout, stderr, or any other file', async (t) => {
  const dir = await tempDir(t);
  const device = join(dir, 'console');
  writeFileSync(device, '');
  const bootFile = join(dir, 'boot_id');
  writeFileSync(bootFile, 'c0ffee00-0000-4000-8000-000000000001\n');
  const config = join(dir, 'runtime.config.json');
  writeFileSync(config, JSON.stringify({ console_device: device }));
  const codesDir = join(dir, 'codes');
  const env = `KB_CODES_DIR=${codesDir}`;
  const run = runNode(['--input-type=module', '-e', `process.env.KB_CODES_DIR=${JSON.stringify(codesDir)};process.env.KB_BOOT_ID_FILE=${JSON.stringify(bootFile)};process.env.KB_RUNTIME_CONFIG=${JSON.stringify(config)};process.env.KB_TRUST_FILE=${JSON.stringify(join(dir, 'trust.json'))};process.argv[2]='recovery';await import(${JSON.stringify(new URL('../src/cli/kb-code.ts', import.meta.url).pathname)});`], dir);
  assert.equal(run.status, 0, run.stderr);
  const shown = readFileSync(device, 'utf8');
  const code = /([a-z]+(?: [a-z]+){11})/.exec(shown)?.[1];
  assert.ok(code !== undefined, 'the console got the code');
  for (const [name, text] of [['stdout', run.stdout], ['stderr', run.stderr], ['env', env]] as const) assert.equal(text.includes(code), false, name);
  for (const f of readdirSync(codesDir)) assert.equal(readFileSync(join(codesDir, f), 'utf8').includes(code), false, f);
  const again = runNode(['--input-type=module', '-e', `process.env.KB_CODES_DIR=${JSON.stringify(codesDir)};process.env.KB_BOOT_ID_FILE=${JSON.stringify(bootFile)};process.env.KB_RUNTIME_CONFIG=${JSON.stringify(config)};process.env.KB_TRUST_FILE=${JSON.stringify(join(dir, 'trust.json'))};process.argv[2]='recovery';await import(${JSON.stringify(new URL('../src/cli/kb-code.ts', import.meta.url).pathname)});`], dir);
  assert.equal(again.status, 0, again.stderr);
  assert.equal(readFileSync(device, 'utf8'), shown, 'a second run in the same boot writes no new code');
});

test('KBOX-20 the kb-code unit (not core) has tty, a DeviceAllow for the configured console device only, and PrivateDevices=no', () => {
  const deploy = new URL('../deploy/', import.meta.url).pathname;
  const config = JSON.parse(readFileSync(join(deploy, 'runtime.config.json'), 'utf8')) as { console_device: string };
  const unit = directives(readFileSync(join(deploy, 'kb-code.service'), 'utf8'), 'Service');
  assert.deepEqual(words(unit.get('SupplementaryGroups')), ['tty']);
  assert.deepEqual(words(unit.get('DeviceAllow')), [config.console_device, 'w']);
  assert.deepEqual(unit.get('PrivateDevices'), ['no']);
  assert.deepEqual(unit.get('User'), ['root']);
  assert.deepEqual(unit.get('Type'), ['oneshot']);
  for (const name of readdirSync(deploy).filter((f) => f.endsWith('.service') && f !== 'kb-code.service')) {
    const other = directives(readFileSync(join(deploy, name), 'utf8'), 'Service');
    assert.equal(other.get('DeviceAllow'), undefined, name);
    assert.equal(other.get('SupplementaryGroups'), undefined, name);
  }
});
