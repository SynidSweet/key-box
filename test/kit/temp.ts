import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { onTestEnd } from './cleanup.ts';

/** A fresh directory, removed when the test that asked for it ends, after any process the kit started for that test has been killed. */
export async function tempDir(t: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'kbt-'));
  onTestEnd(t, 'directory', () => rm(dir, { recursive: true, force: true }));
  return dir;
}
