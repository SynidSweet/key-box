import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after } from 'node:test';

/** A fresh directory for a synchronous factory (a contract suite's `make`), removed when the test file ends. */
export function tempDirSync(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kbt-'));
  after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
