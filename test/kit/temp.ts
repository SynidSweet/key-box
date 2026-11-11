import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';

/** A fresh directory, removed in an `after` hook of the test that asked for it. */
export async function tempDir(t: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'kbt-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
