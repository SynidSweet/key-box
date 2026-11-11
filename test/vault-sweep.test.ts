// KBOX-4, KBOX-19: a hard kill between open and rename leaves `.<gen>.tmp-*` holding a full copy of a value. Core start zero-fills and
// unlinks each one and writes an audit row that names the key and nothing else.
import assert from 'node:assert/strict';
import { linkSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { createFileVault, sweepOrphanTemps } from '../src/shell/vault-fs.ts';
import { canary, startCore, tempDir } from './kit/index.ts';
import { findDerived } from './kit/derived-forms.ts';

const plant = (root: string, ref: string, name: string, bytes: Uint8Array): string => {
  const dir = join(root, ...ref.split('/'));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, name);
  writeFileSync(path, bytes, { mode: 0o600 });
  return path;
};

test('KBOX-4 the sweep zero-fills each leftover temp file before it unlinks it, and returns the key it sat under', async (t) => {
  const root = join(await tempDir(t), 'vault');
  const c = canary(32);
  const left = plant(root, 'openai/master', '.3.tmp-4242-7', c.bytes);
  const alias = join(await tempDir(t), 'alias');
  linkSync(left, alias);
  assert.deepEqual(sweepOrphanTemps(root), ['openai/master']);
  assert.deepEqual(readdirSync(join(root, 'openai', 'master')), []);
  assert.deepEqual([...readFileSync(alias)], new Array<number>(32).fill(0), 'the bytes were overwritten before the unlink, not only unlinked');
  assert.equal(statSync(alias).size, 32);
});

test('KBOX-4 the sweep leaves generation files, other dot files and symlinks alone, and a missing vault is no error', async (t) => {
  const root = join(await tempDir(t), 'vault');
  assert.deepEqual(sweepOrphanTemps(root), []);
  const vault = createFileVault(root);
  vault.put('k', 1, Buffer.from('live'));
  plant(root, 'k', '.keep', Buffer.from('mine'));
  plant(root, 'k', '.1.tmp-x', Buffer.from('not a temp name'));
  const outside = join(await tempDir(t), 'target');
  writeFileSync(outside, 'precious');
  symlinkSync(outside, join(root, 'k', '.2.tmp-1-1'));
  assert.deepEqual(sweepOrphanTemps(root), []);
  assert.deepEqual(readdirSync(join(root, 'k')).sort(), ['.1.tmp-x', '.2.tmp-1-1', '.keep', '1']);
  assert.equal(readFileSync(outside, 'utf8'), 'precious');
  assert.equal(readFileSync(join(root, 'k', '1'), 'utf8'), 'live');
});

test('KBOX-4 core start sweeps a planted temp file, audits the key without the value or its length, and the vault directory scans clean', async (t) => {
  const stateDir = join(await tempDir(t), 'state');
  const c = canary(40);
  const vaultRoot = join(stateDir, 'vault');
  plant(vaultRoot, 'openai/master', '.1.tmp-99-0', c.bytes);
  plant(vaultRoot, 'openai/master', '.2.tmp-99-1', c.bytes);
  const box = await startCore(t, { stateDir });
  assert.deepEqual(readdirSync(join(vaultRoot, 'openai', 'master')), []);
  const rows = box.audit.read(0).entries.filter((r) => r.action === 'vault.temp_swept');
  assert.deepEqual(rows.map((r) => [r.ref, r.actor, r.detail]), [['openai/master', 'box', {}], ['openai/master', 'box', {}]]);
  const files = (dir: string): Record<string, Buffer> =>
    Object.fromEntries(readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => [join(e.parentPath, e.name), readFileSync(join(e.parentPath, e.name))]));
  const surfaces = { ...files(vaultRoot), audit: JSON.stringify(box.audit.read(0).entries), events: JSON.stringify(box.events.after(0)) };
  c.assertAbsent(surfaces);
  assert.deepEqual(findDerived(c.bytes, 'openai/master', surfaces), []);
});
