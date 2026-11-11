// KBOX-19: there is no backup of vault files and no code path that writes one. The spec words the test as a grep of the shell adapters, so
// the grep stays (it also covers the wiring that names the vault path); the behavioural test below is the proof on the files themselves.
import assert from 'node:assert/strict';
import { createFileVault } from '../src/shell/vault-fs.ts';
import { tempDir } from './kit/index.ts';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const shell = new URL('../src/shell/', import.meta.url).pathname;
const sources = readdirSync(shell).filter((f) => f.endsWith('.ts')).map((f) => ({ file: f, text: readFileSync(join(shell, f), 'utf8') }));

const COPY_OR_LINK = /\b(copyFile|copyFileSync|cp|cpSync|link|linkSync|symlink|symlinkSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync)\b/;

test('KBOX-19 the shell adapters that name the vault path contain no copy, link or stream-out call, and none mentions a backup', () => {
  const naming = sources.filter((s) => /vault/i.test(s.text));
  assert.deepEqual(naming.map((s) => s.file).sort(), ['core.ts', 'vault-fs.ts'], 'only the vault adapter and the wiring name the vault');
  for (const s of naming) assert.doesNotMatch(s.text, COPY_OR_LINK, `${s.file} copies or links a file`);
  for (const s of sources) assert.doesNotMatch(s.text, /backup|snapshot.*vault|vault.*snapshot/i, `${s.file} mentions a backup of the vault`);
});

test('KBOX-19 the grep itself finds a planted copy of a vault path', () => {
  const planted = "import { copyFileSync } from 'node:fs';\ncopyFileSync(join(vaultDir, ref), join(backupDir, ref));";
  assert.match(planted, COPY_OR_LINK);
  assert.match(planted, /vault/i);
});

const filesUnder = (root: string, at = ''): string[] =>
  readdirSync(join(root, at), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? filesUnder(root, join(at, e.name)) : [join(at, e.name)]));

test('KBOX-19 after put, rotate and retire the vault holds exactly the live generation files: no .bak, no ~, no copy, no extra generation', async (t) => {
  const root = join(await tempDir(t), 'vault');
  const vault = createFileVault(root);
  vault.put('openai/master', 1, Buffer.from('one'));
  assert.deepEqual(filesUnder(root), [join('openai', 'master', '1')]);
  vault.put('openai/master', 2, Buffer.from('two'));
  vault.put('other', 1, Buffer.from('side'));
  assert.deepEqual(filesUnder(root).sort(), [join('openai', 'master', '1'), join('openai', 'master', '2'), join('other', '1')]);
  vault.put('openai/master', 2, Buffer.from('two again'));
  assert.deepEqual(filesUnder(root).sort(), [join('openai', 'master', '1'), join('openai', 'master', '2'), join('other', '1')], 'replacing a generation leaves no old copy');
  vault.retire('openai/master', 1);
  assert.deepEqual(filesUnder(root).sort(), [join('openai', 'master', '2'), join('other', '1')], 'retiring leaves no copy of the retired generation');
  vault.retire('openai/master', 2);
  assert.deepEqual(filesUnder(root).sort(), [join('other', '1')]);
});
