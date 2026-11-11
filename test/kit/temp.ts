import { mkdtempSync, rmSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after } from 'node:test';
import type { TestContext } from 'node:test';

/** A fresh directory, removed in an `after` hook of the test that asked for it. */
export async function tempDir(t: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'kbt-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** A fresh directory for a synchronous factory (a contract suite's `make`), removed when the test file ends. */
export function tempDirSync(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kbt-'));
  after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
