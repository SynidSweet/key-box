import { spawnSync } from 'node:child_process';

export interface NodeRun {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** Runs this Node with `args` in `cwd` and waits; a failure to start is thrown, never reported as an exit code. */
export function runNode(args: readonly string[], cwd: string): NodeRun {
  const result = spawnSync(process.execPath, [...args], { cwd, encoding: 'utf8' });
  if (result.error !== undefined) throw result.error;
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
