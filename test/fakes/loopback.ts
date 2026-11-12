// A loopback HTTP server a platform fake runs on: one handler, and a switch that makes the platform unreachable (the connection is cut).
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';


/** Where a fake's server is closed: a test context, or the file-level `after` of node:test. */
export interface Teardown {
  after(fn: () => unknown): unknown;
}

export interface Loopback {
  readonly url: string;
  down: boolean;
}

export type Handler = (req: IncomingMessage, body: string, res: ServerResponse) => void;

export async function loopback(t: Teardown, handler: Handler): Promise<Loopback> {
  const state = { down: false };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => void chunks.push(c));
    req.on('end', () => {
      if (state.down) {
        req.socket.destroy();
        return;
      }
      handler(req, Buffer.concat(chunks).toString('utf8'), res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  }));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get down() {
      return state.down;
    },
    set down(value: boolean) {
      state.down = value;
    },
  };
}

export const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};
