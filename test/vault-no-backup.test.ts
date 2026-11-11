// KBOX-19: there is no backup of vault files and no code path that writes one.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const shell = new URL('../src/shell/', import.meta.url).pathname;
const sources = readdirSync(shell).filter((f) => f.endsWith('.ts')).map((f) => ({ file: f, text: readFileSync(join(shell, f), 'utf8') }));

const COPY_OR_LINK = /\b(copyFile|copyFileSync|cp|cpSync|link|linkSync|symlink|symlinkSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync)\b/;

const LITERAL = /(['"`])((?:(?!\1)[^\\\n]|\\.)*)\1/g;
const VAULT_IDENTIFIER = /\b(vaultRoot|vaultDir|VAULT_DIR)\b/;
const VAULT_ADAPTER = /\bexport function createFileVault\b/;

// A file holds a vault path when a string literal has a path segment that is exactly `vault`, it uses a vault-root identifier,
// or it is the vault adapter itself (which receives the root as a parameter and so names no literal).
function holdsVaultPath(text: string): boolean {
  if (VAULT_IDENTIFIER.test(text) || VAULT_ADAPTER.test(text)) return true;
  return [...text.matchAll(LITERAL)].some((m) => (m[2] ?? '').split('/').includes('vault'));
}

const importsVaultFs = (text: string): boolean => /\bfrom\s+['"]\.\/vault-fs\.ts['"]/.test(text);

test('KBOX-19 only the wiring imports the vault adapter, only the adapter and the wiring hold a vault path, those contain no copy, link or stream-out call, and none mentions a backup', () => {
  assert.deepEqual(sources.filter((s) => importsVaultFs(s.text)).map((s) => s.file), ['core.ts'], 'only core.ts imports the vault adapter');
  const holding = sources.filter((s) => holdsVaultPath(s.text));
  assert.deepEqual(holding.map((s) => s.file).sort(), ['core.ts', 'vault-fs.ts'], 'only the vault adapter and the wiring hold a vault path');
  for (const s of holding) assert.doesNotMatch(s.text, COPY_OR_LINK, `${s.file} copies or links a file`);
  for (const s of sources) assert.doesNotMatch(s.text, /backup|snapshot.*vault|vault.*snapshot/i, `${s.file} mentions a backup of the vault`);
});

test('KBOX-19 the grep itself finds a planted copy of a vault path', () => {
  const planted = "import { copyFileSync } from 'node:fs';\ncopyFileSync(join(vaultDir, ref), join(backupDir, ref));";
  assert.match(planted, COPY_OR_LINK);
  assert.ok(holdsVaultPath(planted));
});

test('KBOX-19 a file that only uses the Vault port holds no vault path, and a joined vault directory does', () => {
  const portOnly = "import type { Vault } from '../ports/vault.ts';\nexport function f(vault: Vault, ref: string, gen: number, bytes: Uint8Array) {\n  vault.put(ref, gen, bytes);\n  audit('vault.temp_swept');\n}";
  assert.equal(holdsVaultPath(portOnly), false);
  assert.ok(holdsVaultPath("const root = join(stateDir, 'vault');"));
  assert.ok(holdsVaultPath('const p = `state/vault/x`;'));
});
