// KBOX-19, behavioural half: the vault directory holds only live generation files. The spec words the rule's test as a grep of the shell
// adapters, so test/vault-no-backup.test.ts keeps that grep (it also covers the wiring that names the vault path); a grep misses a copy
// spelled another way, so this file checks the files themselves.
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { createFileVault } from '../src/shell/vault-fs.ts';
import { tempDir } from './kit/index.ts';

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
