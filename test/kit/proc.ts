import { spawn, spawnSync } from 'node:child_process';

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

/** Starts this Node with `args` in `cwd` and resolves when it exits, so two of them can run at once. A failure to start rejects. */
export function spawnNode(args: readonly string[], cwd: string): Promise<NodeRun> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...args], { cwd });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => out.push(c));
    child.stderr.on('data', (c: Buffer) => err.push(c));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}
