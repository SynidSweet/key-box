// The kit's per-test cleanup: a started process is always killed, whatever else fails at the end of the test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnNode, tempDir, waitUntil } from './kit/index.ts';
import type { NodeRun } from './kit/index.ts';

const kitUrl = pathToFileURL(join(import.meta.dirname, 'kit', 'index.ts')).href;

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    if (e instanceof Error && 'code' in e && e.code === 'ESRCH') return false;
    throw e;
  }
};

/**
 * Runs a one-test file in a separate `node --test`: the test makes a temp directory, runs `body`, then starts a long-lived child that records its pid.
 * Resolves with the exit of that run once its child is dead; fails (and kills the child itself) when the child outlives the test.
 */
async function runFixture(t: Parameters<typeof tempDir>[0], body: string): Promise<NodeRun> {
  const dir = await tempDir(t);
  const pidFile = join(dir, 'child.pid');
  const file = join(dir, 'fixture.test.ts');
  await writeFile(
    file,
    `import { test } from 'node:test';
import { startNode, tempDir, onTestEnd } from ${JSON.stringify(kitUrl)};
test('fixture', async (t) => {
  await tempDir(t);
  ${body}
  const child = startNode(t, ['-e', 'require("node:fs").writeFileSync(process.env.PID_FILE, String(process.pid)); console.log("up"); setInterval(() => {}, 1000)'], process.cwd(), { PID_FILE: ${JSON.stringify(pidFile)} });
  await child.ready('up');
});
`,
  );
  // NODE_TEST_CONTEXT is set inside this run; removed, the fixture's runner behaves as a top-level one.
  const run = spawnNode(['--test', file], dir, { NODE_TEST_CONTEXT: undefined });
  await waitUntil(() => existsSync(pidFile), 'the fixture to start its child', 15000);
  const pid = Number(await readFile(pidFile, 'utf8'));
  try {
    await waitUntil(() => !isAlive(pid), 'the fixture test to kill the child it started', 10000);
  } finally {
    if (isAlive(pid)) process.kill(pid, 'SIGKILL');
  }
  return run;
}

test('KBOX-35 a started process is killed even when another end-of-test hook fails first', async (t) => {
  const run = await runFixture(t, `t.after(() => { throw new Error('an earlier hook fails'); });`);
  assert.notEqual(run.status, 0, 'the failing hook must still fail the test');
  assert.match(run.stdout + run.stderr, /an earlier hook fails/);
});

test('KBOX-35 a cleanup step that fails is reported, and the process is still killed', async (t) => {
  const run = await runFixture(t, `onTestEnd(t, 'process', () => { throw new Error('a cleanup step fails'); });`);
  assert.notEqual(run.status, 0, 'the failing step must still fail the test');
  assert.match(run.stdout + run.stderr, /a cleanup step fails/);
});
