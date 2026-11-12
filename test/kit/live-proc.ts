import { spawn } from 'node:child_process';
import type { TestContext } from 'node:test';
import type { NodeRun } from './proc.ts';
import { onTestEnd } from './cleanup.ts';

/** Starts this Node with `args` in `cwd` (with `env` applied over ours; an `undefined` value removes the variable) and resolves when it exits, so two of them can run at once. A failure to start rejects. */
export function spawnNode(args: readonly string[], cwd: string, env: Readonly<Record<string, string | undefined>> = {}): Promise<NodeRun> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...args], { cwd, env: { ...process.env, ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => out.push(c));
    child.stderr.on('data', (c: Buffer) => err.push(c));
    child.on('error', reject);
    child.on('close', (status, signal) => resolve({ status, signal, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}

/** How long `ready` waits for a started process to print its line. The spec's own update health check allows a restarted core 60 s (docs/spec.md, "within 60 seconds of restart"), so a core on a loaded machine may take that long. */
const READY_TIMEOUT_MS = 60_000;

export interface LiveNode {
  stdout(): string;
  stderr(): string;
  /** Resolves when `text` has appeared on stdout; rejects at once if the process exits first, and after 60 s. */
  ready(text: string): Promise<void>;
  /** Sends SIGTERM and resolves with the exit. */
  stop(): Promise<NodeRun>;
}

/** Starts this Node on `args` (as another user when `as` is given, which needs root) and keeps it running; it is killed when the test ends if still alive. */
export function startNode(t: TestContext, args: readonly string[], cwd: string, env: Readonly<Record<string, string>>, as?: { readonly uid: number; readonly gid: number }): LiveNode {
  const child = spawn(process.execPath, [...args], { cwd, env: { ...process.env, ...env }, ...(as === undefined ? {} : { uid: as.uid, gid: as.gid }) });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on('data', (c: Buffer) => out.push(c));
  child.stderr.on('data', (c: Buffer) => err.push(c));
  const text = (parts: Buffer[]): string => Buffer.concat(parts).toString('utf8');
  let closed = false;
  const exited = new Promise<NodeRun>((resolve) => {
    child.on('close', (status, signal) => {
      closed = true;
      resolve({ status, signal, stdout: text(out), stderr: text(err) });
    });
  });
  onTestEnd(t, 'process', async () => {
    child.kill('SIGKILL');
    await exited;
  });
  return {
    stdout: () => text(out),
    stderr: () => text(err),
    ready: (wanted) =>
      new Promise<void>((resolve, reject) => {
        const printed = (): boolean => text(out).includes(wanted);
        const exitedWithout = (): Error => new Error(`the process exited before printing "${wanted}": ${text(err)}`);
        if (printed()) return resolve();
        if (closed) return reject(exitedWithout());
        const settle = (finish: () => void): void => {
          clearTimeout(timer);
          child.stdout.off('data', onData);
          child.off('close', onClose);
          finish();
        };
        const onData = (): void => {
          if (printed()) settle(resolve);
        };
        const onClose = (): void => settle(printed() ? resolve : () => reject(exitedWithout()));
        const timer = setTimeout(() => settle(() => reject(new Error(`timed out after ${READY_TIMEOUT_MS} ms waiting for "${wanted}" on stdout: ${text(err)}`))), READY_TIMEOUT_MS);
        child.stdout.on('data', onData);
        child.on('close', onClose);
      }),
    stop: () => {
      child.kill('SIGTERM');
      return exited;
    },
  };
}
