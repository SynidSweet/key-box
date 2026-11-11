// A real HTTP server on a loopback port that plays one platform's API and fails in its real ways.
import { createServer } from 'node:http';
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { TestContext } from 'node:test';

export type PlatformMode = 'ok' | '500' | '401-echo' | 'malformed-json' | 'partial-body' | 'redirect' | 'hang' | 'refuse';

export interface RecordedRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: IncomingHttpHeaders;
}

export interface FakePlatform {
  readonly url: string;
  readonly requests: readonly RecordedRequest[];
  /** 'refuse' stops listening so the next connection is really refused; any other mode listens again. */
  setMode(mode: PlatformMode): Promise<void>;
  /** Resolves with the first request that arrives after this call. */
  nextRequest(): Promise<RecordedRequest>;
}

export interface FakePlatformOptions {
  /** The body of an 'ok' answer. */
  readonly okBody?: unknown;
}

function answer(mode: PlatformMode, req: IncomingMessage, res: ServerResponse, port: number, okBody: unknown): void {
  switch (mode) {
    case 'ok':
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(okBody));
      return;
    case '500':
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal' }));
      return;
    case '401-echo': {
      const presented = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${presented}` } }));
      return;
    }
    case 'malformed-json':
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":tru');
      return;
    case 'partial-body':
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' });
      res.write('{"ok":', () => req.socket.destroy());
      return;
    case 'redirect':
      res.writeHead(302, { location: `http://localhost:${port}/elsewhere` });
      res.end();
      return;
    case 'hang':
    case 'refuse':
      return;
  }
}

const listen = (server: Server, port: number): Promise<void> =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

const stop = (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.closeAllConnections();
    server.close((err) => (err === undefined ? resolve() : reject(err)));
  });

export async function fakePlatform(t: TestContext, options: FakePlatformOptions = {}): Promise<FakePlatform> {
  const requests: RecordedRequest[] = [];
  const waiting: ((r: RecordedRequest) => void)[] = [];
  let mode: PlatformMode = 'ok';
  let listening = false;
  let port = 0;
  const server = createServer((req, res) => {
    const recorded: RecordedRequest = { method: req.method ?? '', url: req.url ?? '', headers: req.headers };
    requests.push(recorded);
    for (const wake of waiting.splice(0)) wake(recorded);
    req.resume();
    answer(mode, req, res, port, options.okBody ?? { ok: true });
  });
  await listen(server, 0);
  listening = true;
  port = (server.address() as AddressInfo).port;
  t.after(async () => {
    if (listening) await stop(server);
  });
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    async setMode(next) {
      if (next === 'refuse' && listening) {
        await stop(server);
        listening = false;
      } else if (next !== 'refuse' && !listening) {
        await listen(server, port);
        listening = true;
      }
      mode = next;
    },
    nextRequest: () => new Promise((resolve) => waiting.push(resolve)),
  };
}
