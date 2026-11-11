// A minimal Chrome DevTools Protocol client over Node's built-in WebSocket, and the launch of a headless Chromium for it. No dependency.
// Chromium is started with a SHORT TMPDIR of its own (a long one has crashed it with core dumps on this machine) and no memory limit.
// Run directly, this file does nothing.
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

export const CHROMIUM = '/home/petter/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome';

export interface CdpEvent {
  readonly method: string;
  readonly params: unknown;
  readonly sessionId: string | undefined;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;
const nap = (ms: number): Promise<void> => new Promise((resolve) => void setTimeout(resolve, ms));

export class Cdp {
  readonly #socket: WebSocket;
  readonly #pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void }>();
  readonly #listeners: ((event: CdpEvent) => void)[] = [];
  #next = 1;

  private constructor(socket: WebSocket) {
    this.#socket = socket;
    socket.addEventListener('message', (message) => {
      const frame: unknown = JSON.parse(String(message.data));
      if (!isRecord(frame)) return;
      const id = frame['id'];
      if (typeof id === 'number') {
        const waiting = this.#pending.get(id);
        this.#pending.delete(id);
        const failure = frame['error'];
        if (isRecord(failure)) waiting?.reject(new Error(`${String(failure['message'])} (${String(failure['code'])})`));
        else waiting?.resolve(frame['result']);
      } else if (typeof frame['method'] === 'string') {
        const sessionId = typeof frame['sessionId'] === 'string' ? frame['sessionId'] : undefined;
        for (const listener of this.#listeners) listener({ method: frame['method'], params: frame['params'], sessionId });
      }
    });
    socket.addEventListener('close', () => {
      for (const waiting of this.#pending.values()) waiting.reject(new Error('the DevTools connection closed'));
      this.#pending.clear();
    });
  }

  static connect(url: string): Promise<Cdp> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      socket.addEventListener('open', () => resolve(new Cdp(socket)));
      socket.addEventListener('error', () => reject(new Error(`could not connect to ${url}`)));
    });
  }

  send(method: string, params: object = {}, sessionId?: string): Promise<unknown> {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params, ...(sessionId === undefined ? {} : { sessionId }) }));
    });
  }

  on(listener: (event: CdpEvent) => void): void {
    this.#listeners.push(listener);
  }

  close(): void {
    this.#socket.close();
  }
}

export interface Chromium {
  readonly cdp: Cdp;
  /** Kills the browser and removes its directory. */
  stop(): Promise<void>;
}

/** Starts headless Chromium with every address of `mapped` sent to 127.0.0.1:`port` and the self-signed certificate accepted. */
export async function launchChromium(mapped: string, port: number): Promise<Chromium> {
  const root = join('/home/petter/.cache', `kb-chr-${process.pid}`);
  mkdirSync(root, { recursive: true });
  const profile = join(root, 'p');
  const args = [
    '--headless',
    '--disable-gpu',
    '--no-first-run',
    '--disable-dev-shm-usage',
    `--user-data-dir=${profile}`,
    '--remote-debugging-port=0',
    `--host-resolver-rules=MAP ${mapped} 127.0.0.1:${port}`,
    '--ignore-certificate-errors',
    'about:blank',
  ];
  const child: ChildProcess = spawn(CHROMIUM, args, { env: { ...process.env, TMPDIR: root }, stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
  let log = '';
  child.stderr?.on('data', (c: Buffer) => (log += c.toString('utf8')));
  const stop = async (): Promise<void> => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    rmSync(root, { recursive: true, force: true });
  };
  try {
    const advertised = join(profile, 'DevToolsActivePort');
    for (let waited = 0; !existsSync(advertised); waited += 50) {
      if (child.exitCode !== null) throw new Error(`Chromium exited at start: ${log}`);
      if (waited > 20_000) throw new Error(`Chromium did not open DevTools: ${log}`);
      await nap(50);
    }
    const [debugPort, path] = readFileSync(advertised, 'utf8').split('\n');
    return { cdp: await Cdp.connect(`ws://127.0.0.1:${debugPort}${path}`), stop };
  } catch (error) {
    await stop();
    throw error;
  }
}
