// The kit's per-test cleanup: a started process is always killed, whatever else fails at the end of the test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnNode, startNode, tempDir, waitUntil } from './kit/index.ts';
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

test('KBOX-35 ready waits for a ready line that a slow, loaded core prints after more than the old 5 s', async (t) => {
  const child = startNode(t, ['-e', 'setTimeout(() => console.log("late ready line"), 6000)'], process.cwd(), {});
  await child.ready('late ready line');
  assert.match(child.stdout(), /late ready line/);
});

test('KBOX-35 ready rejects at once, naming the stderr, when the process exits without printing the line', async (t) => {
  const child = startNode(t, ['-e', 'console.error("it broke"); process.exit(3)'], process.cwd(), {});
  const started = performance.now();
  await assert.rejects(child.ready('never printed'), /exited before printing "never printed": it broke/);
  assert.ok(performance.now() - started < 3000, 'the rejection must not wait for the deadline');
});

test('KBOX-35 ready resolves at once when the line is already there', async (t) => {
  const child = startNode(t, ['-e', 'console.log("hello"); setInterval(() => {}, 1000)'], process.cwd(), {});
  await child.ready('hello');
  await child.ready('hello');
});
