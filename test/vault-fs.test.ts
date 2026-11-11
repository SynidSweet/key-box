// KBOX-4: values are lent, never returned; the vault is one 0600 file per generation under a 0700 directory.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { vaultContract } from './contracts/vault.contract.ts';
import { bytesOf, canary, tempDir, tempDirSync } from './kit/index.ts';
import { createFileVault } from '../src/shell/vault-fs.ts';
import { mapError, wrapAdapterCall } from '../src/pure/errors.ts';
import { parseUpstreamJson } from '../src/pure/schemas.ts';
import { fakePlatform } from './kit/index.ts';

vaultContract('vault-fs', () => createFileVault(join(tempDirSync(), 'vault')));

const modeOf = (path: string): number => statSync(path).mode & 0o777;

test('KBOX-4 String, template string, JSON.stringify, inspect and console.log of a Lent give the placeholder and nothing else', async (t) => {
  const vault = createFileVault(join(await tempDir(t), 'vault'));
  const c = canary();
  vault.put('openai/master', 3, c.bytes);
  const lent = vault.lend('openai/master', 3);
  const logged: string[] = [];
  t.mock.method(console, 'log', (...args: unknown[]) => void logged.push(args.map((a) => inspect(a)).join(' ')));
  console.log(lent);
  console.log({ lent });
  const shown = '[key openai/master:3]';
  assert.equal(String(lent), shown);
  assert.equal(`${lent}`, shown);
  assert.equal(JSON.stringify(lent), JSON.stringify(shown));
  assert.equal(inspect(lent), shown);
  assert.equal(logged[0], shown);
  assert.equal(logged[1], `{ lent: ${shown} }`);
  c.assertAbsent({ string: String(lent), json: JSON.stringify({ lent }), inspect: inspect(lent, { showHidden: true, depth: 9 }), logged: logged.join('\n') });
});

test('KBOX-4 the bytes handed to use() are wiped when use() ends, so a kept reference holds nothing', async (t) => {
  const vault = createFileVault(join(await tempDir(t), 'vault'));
  vault.put('k', 1, Buffer.from('twenty-four byte secret!'));
  let kept: Uint8Array = new Uint8Array(0);
  await vault.lend('k', 1).use((bytes) => {
    kept = bytes;
    assert.equal(Buffer.from(bytes).toString(), 'twenty-four byte secret!');
    return Promise.resolve();
  });
  assert.deepEqual([...kept], new Array<number>(24).fill(0));
  assert.equal(Buffer.from(await bytesOf(vault.lend('k', 1))).toString(), 'twenty-four byte secret!');
});

test('KBOX-4 vault files are 0600 in 0700 directories, one file per generation', async (t) => {
  const root = join(await tempDir(t), 'vault');
  const vault = createFileVault(root);
  vault.put('openai/master', 1, Buffer.from('one'));
  vault.put('openai/master', 2, Buffer.from('two'));
  assert.deepEqual(readdirSync(join(root, 'openai', 'master')).sort(), ['1', '2']);
  assert.equal(modeOf(join(root, 'openai', 'master', '1')), 0o600);
  assert.equal(modeOf(join(root, 'openai', 'master', '2')), 0o600);
  for (const dir of [root, join(root, 'openai'), join(root, 'openai', 'master')]) assert.equal(modeOf(dir), 0o700);
});

test('KBOX-4 retiring removes the generation file and leaves the others', async (t) => {
  const root = join(await tempDir(t), 'vault');
  const vault = createFileVault(root);
  vault.put('k', 1, Buffer.from('one'));
  vault.put('k', 2, Buffer.from('two'));
  vault.retire('k', 1);
  assert.deepEqual(readdirSync(join(root, 'k')), ['2']);
  assert.throws(() => vault.lend('k', 1), /unknown/);
});

test('KBOX-4 a crash between write and rename leaves the old file readable and no temp file behind', async (t) => {
  const root = join(await tempDir(t), 'vault');
  let crash = false;
  const vault = createFileVault(root, {
    rename: (from, to) => {
      if (crash) throw new Error('simulated crash before rename');
      renameSync(from, to);
    },
  });
  vault.put('k', 1, Buffer.from('old'));
  crash = true;
  assert.throws(() => vault.put('k', 1, Buffer.from('new')), /vault write failed/);
  assert.throws(() => vault.put('k', 2, Buffer.from('new two')), /vault write failed/);
  assert.equal(readFileSync(join(root, 'k', '1'), 'utf8'), 'old');
  assert.deepEqual(readdirSync(join(root, 'k')), ['1']);
  assert.equal(Buffer.from(await bytesOf(vault.lend('k', 1))).toString(), 'old');
  assert.throws(() => vault.lend('k', 2), /unknown/);
});

test('KBOX-4 a ref that is not a plain relative path, and a generation that is not a positive integer, are refused before any file is touched', async (t) => {
  const root = join(await tempDir(t), 'vault');
  const vault = createFileVault(root);
  for (const ref of ['', '/etc/passwd', '../x', 'a/../b', 'a//b', 'a/./b', '.', '..', 'a\0b', 'a b', 'a\nb', 'a/', 'ü']) {
    assert.throws(() => vault.put(ref, 1, Buffer.from('x')), /vault ref refused/, JSON.stringify(ref));
    assert.throws(() => vault.lend(ref, 1), /vault ref refused/, JSON.stringify(ref));
    assert.throws(() => vault.retire(ref, 1), /vault ref refused/, JSON.stringify(ref));
  }
  for (const gen of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
    assert.throws(() => vault.put('k', gen, Buffer.from('x')), /vault ref refused/, String(gen));
  }
  assert.throws(() => readdirSync(root));
});

test('KBOX-4 a vault that cannot be written fails with a fixed text and the OS error code, never the path or the value', async (t) => {
  const base = await tempDir(t);
  writeFileSync(join(base, 'a-file'), 'not a directory');
  const c = canary();
  const vault = createFileVault(join(base, 'a-file', 'vault'));
  assert.throws(
    () => vault.put('k', 1, c.bytes),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, 'vault write failed (ENOTDIR)');
      c.assertAbsent({ message: error.message, stack: error.stack ?? '' });
      return true;
    },
  );
});

test('KBOX-4 an adapter call that throws a message quoting the value reaches no surface: fixed text plus the HTTP status', async () => {
  const c = canary();
  const quoted = Buffer.from(c.bytes).toString('latin1');
  const quotedEverywhere = `bad key ${Buffer.from(c.bytes).toString('base64')} ${Buffer.from(c.bytes).toString('hex')} ${quoted}`;
  const failures: unknown[] = [];
  for (const thrown of [
    Object.assign(new Error(quotedEverywhere, { cause: new Error(quotedEverywhere) }), { status: 401, body: quotedEverywhere }),
    Object.assign(new Error(quotedEverywhere), { status: 'forbidden-' + quotedEverywhere }),
    Object.assign(new Error(quotedEverywhere), { status: 99 }),
    Object.assign(new Error(quotedEverywhere), { status: 600 }),
    Object.assign(new Error(quotedEverywhere), { status: 4.5 }),
    quotedEverywhere,
    { message: quotedEverywhere, status: 503 },
    null,
  ]) {
    const error = await wrapAdapterCall(() => Promise.reject(thrown)).then(
      () => new Error('the call was expected to fail'),
      (e: unknown) => e,
    );
    failures.push(error);
    assert.ok(error instanceof Error);
    assert.equal(error.cause, undefined);
    const mapped = mapError(error);
    c.assertAbsent({
      message: error.message,
      stack: error.stack ?? '',
      string: String(error),
      inspect: inspect(error, { depth: 10, showHidden: true }),
      json: JSON.stringify(error),
      mapped: JSON.stringify(mapped),
    });
  }
  const messages = failures.map((f) => (f instanceof Error ? f.message : ''));
  assert.equal(messages[0], 'adapter call failed with status 401');
  assert.equal(messages[3], 'adapter call failed');
  assert.equal(messages[6], 'adapter call failed with status 503');
  assert.deepEqual(messages.slice(1, 3).concat(messages.slice(4, 6)), ['adapter call failed', 'adapter call failed', 'adapter call failed', 'adapter call failed']);
});

test('KBOX-4 a create response holding a new value that fails to parse is absent from the error, its mapping and the platform echo', async (t) => {
  const c = canary(32);
  const value = Buffer.from(c.bytes).toString('base64url');
  for (const okBody of [`sk-${value}`, { key: value }]) {
    const platform = await fakePlatform(t, { okBody });
    const create = async (): Promise<string> => {
      const res = await fetch(`${platform.url}/v1/keys`, { method: 'POST' });
      const parsed = parseUpstreamJson(await res.text());
      if (typeof parsed !== 'object' || parsed === null || !('id' in parsed)) throw new Error(`unexpected create response ${JSON.stringify(parsed)}`);
      return 'created';
    };
    const error = await wrapAdapterCall(create).then(
      () => new Error('the call was expected to fail'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof Error);
    c.assertAbsent({ message: error.message, stack: error.stack ?? '', inspect: inspect(error, { depth: 10 }), mapped: JSON.stringify(mapError(error)) });
  }
  for (const text of [`{"key":"${value}`, `sk-${value}`, '']) {
    assert.throws(
      () => parseUpstreamJson(text),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message, 'adapter response was not understood');
        c.assertAbsent({ message: error.message, stack: error.stack ?? '', inspect: inspect(error, { depth: 10 }) });
        return true;
      },
    );
  }
});
