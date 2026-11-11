import { spawn, spawnSync } from 'node:child_process';
import type { TestContext } from 'node:test';
import { waitUntil } from './settle.ts';

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

export interface LiveNode {
  stdout(): string;
  stderr(): string;
  /** Resolves when `text` has appeared on stdout; rejects if the process exits first. */
  ready(text: string): Promise<void>;
  /** Sends SIGTERM and resolves with the exit. */
  stop(): Promise<NodeRun>;
}

/** Starts this Node on `args` and keeps it running; it is killed when the test ends if still alive. */
export function startNode(t: TestContext, args: readonly string[], cwd: string, env: Readonly<Record<string, string>>): LiveNode {
  const child = spawn(process.execPath, [...args], { cwd, env: { ...process.env, ...env } });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on('data', (c: Buffer) => out.push(c));
  child.stderr.on('data', (c: Buffer) => err.push(c));
  const text = (parts: Buffer[]): string => Buffer.concat(parts).toString('utf8');
  const exited = new Promise<NodeRun>((resolve) => {
    child.on('close', (status) => resolve({ status, stdout: text(out), stderr: text(err) }));
  });
  t.after(() => {
    child.kill('SIGKILL');
  });
  return {
    stdout: () => text(out),
    stderr: () => text(err),
    ready: async (wanted) => {
      let done = false;
      void exited.then(() => (done = true));
      await waitUntil(() => text(out).includes(wanted) || done, `"${wanted}" on stdout`);
      if (!text(out).includes(wanted)) throw new Error(`the process exited before printing "${wanted}": ${text(err)}`);
    },
    stop: () => {
      child.kill('SIGTERM');
      return exited;
    },
  };
}
