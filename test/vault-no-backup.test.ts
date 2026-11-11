// KBOX-19: there is no backup of vault files and no code path that writes one.
import assert from 'node:assert/strict';
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
