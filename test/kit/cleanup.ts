import type { TestContext } from 'node:test';

/** Processes go first, so nothing is still writing when a directory is removed. */
export type CleanupPhase = 'process' | 'directory';

const phases: readonly CleanupPhase[] = ['process', 'directory'];

interface Step {
  readonly phase: CleanupPhase;
  readonly run: () => unknown;
}

const registries = new WeakMap<TestContext, Step[]>();

/** Runs every step, phase by phase; a failing step never stops the others, and the failures are thrown together afterwards. */
async function runAll(steps: readonly Step[]): Promise<void> {
  const failures: unknown[] = [];
  for (const phase of phases) {
    const settled = await Promise.allSettled(steps.filter((s) => s.phase === phase).map(async (s) => s.run()));
    for (const r of settled) if (r.status === 'rejected') failures.push(r.reason);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, `${failures.length} cleanup steps failed`);
}

/**
 * Adds `run` to what happens when test `t` ends. One `after` hook per test runs all of its steps, so the order in which a test asks for a
 * directory or a process does not matter, and a step that throws cannot stop the others (node:test skips the rest of a test's hooks after
 * the first one that throws). A step's failure still fails the test.
 */
export function onTestEnd(t: TestContext, phase: CleanupPhase, run: () => unknown): void {
  const existing = registries.get(t);
  if (existing !== undefined) {
    existing.push({ phase, run });
    return;
  }
  const steps: Step[] = [{ phase, run }];
  registries.set(t, steps);
  t.after(() => runAll(steps));
}
