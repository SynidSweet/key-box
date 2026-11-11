// The relay in-process on its unix socket, over core's real lend handler (lend-world.ts), an upstream stand-in on a loopback
// port and the egress gate's test connector: the gate runs for real (host lists, one lookup, address check), and only the
// final connect goes to loopback instead of the resolved public address.
import { request } from 'node:http';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import type { PlatformEntry } from '../../src/ports/platform.ts';
import { createEgress } from '../../src/shell/egress.ts';
import { createLendClient } from '../../src/shell/lend-socket.ts';
import { loopbackConnector } from './loopback-connector.ts';
import { adapterHostsOf, createRelayServer } from '../../src/shell/relay-http.ts';
import { canary } from '../kit/index.ts';
import type { Canary } from '../kit/index.ts';
import { TEST_REGISTRY } from '../fixtures/profiles.ts';
import { lendWorld } from './lend-world.ts';
import type { LendWorld } from './lend-world.ts';

export interface UpstreamRequest {
  readonly method: string;
  readonly url: string;
  readonly httpVersion: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Buffer;
  readonly trailers: Readonly<Record<string, string | undefined>>;
}

export type Responder = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

export interface Upstream {
  readonly port: number;
  readonly requests: readonly UpstreamRequest[];
  /** How the next requests are answered; the default is 200 `{"ok":true}`. */
  respond(responder: Responder): void;
  /** Resolves when the upstream's side of the last connection has closed. */
  lastClosed(): Promise<void>;
}

/** A scripted upstream platform on a loopback port; it records every request it is sent. */
export async function startUpstream(t: TestContext): Promise<Upstream> {
  const requests: UpstreamRequest[] = [];
  let responder: Responder = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  };
  let closed: Promise<void> = Promise.resolve();
  const server = createServer((req, res) => {
    const socket: Socket = req.socket;
    closed = new Promise((resolve) => socket.once('close', () => resolve()));
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method ?? '', url: req.url ?? '', httpVersion: req.httpVersion, headers: req.headers, body: Buffer.concat(chunks), trailers: req.trailers });
      void Promise.resolve(responder(req, res)).then(
        () => 'answered',
        (error: unknown) => {
          res.destroy();
          throw error;
        },
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  return {
    port: (server.address() as AddressInfo).port,
    requests,
    respond: (next) => void (responder = next),
    lastClosed: () => closed,
  };
}

export interface RelayReply {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Buffer;
  /** False when the relay cut the stream (the body ended without its framing end). */
  readonly complete: boolean;
  /** Response trailers as the caller received them. */
  readonly trailers: Readonly<Record<string, string | undefined>>;
}

export interface CallOptions {
  readonly method?: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** Sent as `Authorization: Bearer <pass>` unless `headers` carries the pass itself. */
  readonly pass?: string | null;
  /** X-KB-Client-Ip; null sends none. */
  readonly ip?: string | null;
  readonly body?: Uint8Array;
  /** Request trailers (the body is sent chunked). */
  readonly trailers?: Readonly<Record<string, string>>;
  /** Called with the running count of body bytes received, after each piece. */
  readonly onBody?: (received: number) => void;
}

export interface RelayWorld {
  readonly lend: LendWorld;
  readonly upstream: Upstream;
  readonly socket: string;
  readonly journal: readonly string[];
  /** The planted key value of `adminkey1` and `hostkey001`. */
  readonly value: Uint8Array;
  readonly canary: Canary;
  /** The pass of machine `laptop`, which holds grants on `adminkey1` (pathplat) and `hostkey001` (hostplat). */
  readonly pass: string;
  /** Upstream hosts whose connect never finishes. */
  readonly hung: Set<string>;
  /** Stops the relay now (it waits for every request in flight to finish its audit); the world's cleanup calls it again harmlessly. */
  stop(): Promise<void>;
  call(path: string, options?: CallOptions): Promise<RelayReply>;
}

export interface RelayWorldOptions {
  readonly registry?: readonly PlatformEntry[];
}

export async function relayWorld(t: TestContext, options: RelayWorldOptions = {}): Promise<RelayWorld> {
  const registry = options.registry ?? TEST_REGISTRY;
  const lend = await lendWorld(t, registry);
  const up = await startUpstream(t);
  const c = canary();
  const value = Buffer.from(Buffer.from(c.bytes).toString('hex'));
  const pass = lend.enrol('laptop');
  lend.addKey({ keyref: 'adminkey1', value, grants: ['laptop'] });
  lend.addKey({ keyref: 'hostkey001', value, platform: 'hostplat', grants: ['laptop'] });
  const hung = new Set<string>();
  const connector = loopbackConnector(up.port, hung);
  const egress = createEgress({ adapterHosts: adapterHostsOf(registry), listed: [], resolver: { resolve: () => Promise.resolve(['203.0.113.10']) }, connector, scheduler: lend.clock });
  const journal: string[] = [];
  const server = createRelayServer({ registry, lend: createLendClient(lend.socket), egress, domain: 'box.example', journal: (code) => void journal.push(code) });
  const socket = join(lend.dir, 'relay.sock');
  await server.listen(socket);
  t.after(() => server.stop());

  const call = (path: string, call: CallOptions = {}): Promise<RelayReply> =>
    new Promise((resolve, reject) => {
      const headers: Record<string, string> = { ...call.headers };
      if (call.pass !== null) headers['authorization'] ??= `Bearer ${call.pass ?? pass}`;
      if (call.ip !== null) headers['x-kb-client-ip'] = call.ip ?? '203.0.113.9';
      if (call.trailers !== undefined) headers['transfer-encoding'] = 'chunked';
      const req = request({ socketPath: socket, method: call.method ?? 'GET', path, headers }, (res) => {
        const chunks: Buffer[] = [];
        let finished = false;
        let received = 0;
        res.on('data', (d: Buffer) => {
          chunks.push(d);
          received += d.length;
          call.onBody?.(received);
        });
        res.on('end', () => (finished = res.complete));
        res.on('error', () => void (finished = false));
        res.on('close', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), complete: finished, trailers: res.trailers }));
      });
      req.on('error', reject);
      if (call.body !== undefined) req.write(call.body);
      if (call.trailers !== undefined) req.addTrailers(call.trailers);
      req.end();
    });

  return { lend, upstream: up, socket, journal, value, canary: c, pass, hung, call, stop: () => server.stop() };
}
