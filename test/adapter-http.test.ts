// KBOX-23, KBOX-47, KBOX-14: how an adapter reaches its platform. The real client runs over the real egress gate (caller `adapter`) and
// the real TLS connector against a local TLS server whose certificate is the test's CA; only the resolver and the address are stood in.
// The registry's `hosts` and the kit's `AdapterHttp` are tested here too.
import assert from 'node:assert/strict';
import { createServer as createPlainServer } from 'node:http';
import { createServer } from 'node:https';
import { Duplex } from 'node:stream';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { inspect } from 'node:util';
import { HTTP_BODY_CAP_BYTES, HTTP_TIMEOUT_MS, HttpTransportError, refusingAdapterHttp } from '../src/ports/http.ts';
import type { AdapterHttp, HttpFailureCode, HttpRequest, HttpResponse } from '../src/ports/http.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import { createRegistry, createRelayRegistry } from '../src/platforms/registry.ts';
import { hostVerdict } from '../src/pure/egress-policy.ts';
import { RegistryRefused, assertRegistry, checkRegistry } from '../src/pure/profile.ts';
import { createAdapterHttp } from '../src/shell/adapter-http.ts';
import { EgressRefused, createEgress, createTlsConnector } from '../src/shell/egress.ts';
import type { Connector, Egress, Resolver } from '../src/shell/egress.ts';
import { NO_ISSUER_SHAPE } from './fixtures/profiles.ts';
import { TimedClock, adapterHttpTo, canary, fakePlatform, waitUntil } from './kit/index.ts';
import { selfSignedCertificate } from './kit/tls.ts';

const HOST = 'api.vendor.example';
/** A public address for the fake resolver of the tests written for the deadline and abort rules. */
const PUBLIC_ADDRESS = '8.8.8.8';
const URL_OK = `https://${HOST}/v1/keys?limit=2&a=b%20c`;

interface Seen {
  readonly method: string;
  readonly url: string;
  readonly headers: IncomingMessage['headers'];
  readonly body: Buffer;
}

type Responder = (req: IncomingMessage, res: ServerResponse) => void;

interface World {
  readonly http: AdapterHttp;
  readonly clock: TimedClock;
  readonly seen: Seen[];
  readonly egress: Egress;
  respond(responder: Responder): void;
}

interface WorldOptions {
  readonly bodyCapBytes?: number;
  readonly hosts?: readonly string[];
  readonly connector?: Connector;
  readonly resolver?: Resolver;
  readonly clock?: TimedClock;
}

async function world(t: TestContext, options: WorldOptions = {}): Promise<World> {
  const cert = await selfSignedCertificate(t, HOST);
  const seen: Seen[] = [];
  let responder: Responder = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  };
  const server = createServer(cert, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => void chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks) });
      responder(req, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const port = (server.address() as AddressInfo).port;
  const tls = createTlsConnector({ ca: cert.cert });
  const clock = options.clock ?? new TimedClock(0);
  const egress = createEgress({
    adapterHosts: [],
    registryHosts: options.hosts ?? [HOST],
    listed: [],
    resolver: options.resolver ?? { resolve: () => Promise.resolve(['203.0.113.10']) },
    connector: options.connector ?? { connect: (target, signal) => tls.connect({ ...target, address: '127.0.0.1', port }, signal) },
    scheduler: clock,
  });
  const http = createAdapterHttp({ egress, scheduler: clock, ...(options.bodyCapBytes === undefined ? {} : { bodyCapBytes: options.bodyCapBytes }) });
  return { http, clock, seen, egress, respond: (r) => void (responder = r) };
}

const failure = (call: Promise<HttpResponse>): Promise<HttpFailureCode | 'no failure'> =>
  call.then(
    () => 'no failure',
    (e: unknown) => {
      if (e instanceof HttpTransportError) return e.code;
      throw e;
    },
  );

const get = (url = URL_OK, extra: Partial<HttpRequest> = {}): HttpRequest => ({ method: 'GET', url, ...extra });

test('KBOX-23 a 200 answer comes back whole, and the request reaches the server with method, path, query, headers, body and Host intact', async (t) => {
  const w = await world(t);
  const body = new TextEncoder().encode('{"name":"k ü 日本"}');
  const answer = await w.http.request({ method: 'POST', url: URL_OK, headers: { Authorization: 'Bearer abc', 'Content-Type': 'application/json' }, body });
  assert.equal(answer.status, 200);
  assert.equal(answer.headers['content-type'], 'application/json');
  assert.equal(Buffer.from(answer.body).toString('utf8'), '{"ok":true}');
  const [only] = w.seen;
  assert.equal(w.seen.length, 1);
  assert.equal(only?.method, 'POST');
  assert.equal(only?.url, '/v1/keys?limit=2&a=b%20c');
  assert.equal(only?.headers['authorization'], 'Bearer abc');
  assert.equal(only?.headers['content-type'], 'application/json');
  assert.equal(only?.headers['host'], HOST);
  assert.equal(only?.headers['content-length'], String(body.length));
  assert.deepEqual(only?.body, Buffer.from(body));
});

test('KBOX-23 an empty body and no body both answer, and a repeated response header is joined', async (t) => {
  const w = await world(t);
  w.respond((_req, res) => {
    res.writeHead(204, [['set-cookie', 'a=1'], ['set-cookie', 'b=2']]);
    res.end();
  });
  const answer = await w.http.request(get());
  assert.equal(answer.status, 204);
  assert.equal(answer.body.length, 0);
  assert.equal(answer.headers['set-cookie'], 'a=1, b=2');
});

test('KBOX-23 a 401 and a 500 are answers returned as a status, not thrown', async (t) => {
  const w = await world(t);
  for (const status of [401, 403, 404, 500]) {
    w.respond((_req, res) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end('{"error":"no"}');
    });
    assert.equal((await w.http.request(get())).status, status);
  }
});

test('KBOX-23 a 302 is returned as a status and its Location is not followed', async (t) => {
  const w = await world(t);
  w.respond((_req, res) => {
    res.writeHead(302, { location: `https://${HOST}/elsewhere` });
    res.end();
  });
  const answer = await w.http.request(get());
  assert.equal(answer.status, 302);
  assert.equal(answer.headers['location'], `https://${HOST}/elsewhere`);
  assert.equal(w.seen.length, 1);
});

test('KBOX-23 a body at the cap passes and one byte over is too_large', async (t) => {
  const w = await world(t, { bodyCapBytes: 1000 });
  w.respond((_req, res) => void res.end(Buffer.alloc(1000, 0x61)));
  assert.equal((await w.http.request(get())).body.length, 1000);
  w.respond((_req, res) => void res.end(Buffer.alloc(1001, 0x61)));
  assert.equal(await failure(w.http.request(get())), 'too_large');
});

test('KBOX-23 the default cap is 8 MiB and a body over it is too_large', async (t) => {
  assert.equal(HTTP_BODY_CAP_BYTES, 8 * 1024 * 1024);
  const w = await world(t);
  w.respond((_req, res) => void res.end(Buffer.alloc(HTTP_BODY_CAP_BYTES + 1, 0x61)));
  assert.equal(await failure(w.http.request(get())), 'too_large');
});

test('KBOX-23 a server that never answers is the timeout failure once the deadline passes, and the timer is gone after', async (t) => {
  const w = await world(t);
  w.respond(() => undefined);
  const call = failure(w.http.request(get(URL_OK, { timeoutMs: 5000 })));
  await waitUntil(() => w.seen.length === 1, 'the request to reach the server');
  w.clock.advance(4999);
  await waitUntil(() => w.clock.pendingTimers === 1, 'the deadline timer to stay set');
  w.clock.advance(1);
  assert.equal(await call, 'timeout');
  assert.equal(w.clock.pendingTimers, 0);
  assert.equal(HTTP_TIMEOUT_MS, 30_000);
});

test('KBOX-23 a connection that cannot be made is unreachable and one that never finishes connecting is a timeout', async (t) => {
  const refused = await world(t, { connector: { connect: () => Promise.reject(new Error('ECONNREFUSED')) } });
  assert.equal(await failure(refused.http.request(get())), 'unreachable');
  const hung = await world(t, { connector: { connect: (_target, signal) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })) } });
  const call = failure(hung.http.request(get(URL_OK, { timeoutMs: 2000 })));
  await waitUntil(() => hung.clock.pendingTimers === 2, 'the connect and call timers');
  hung.clock.advance(2000);
  assert.equal(await call, 'timeout');
});

test('KBOX-23 a cut body and a non-HTTP answer are malformed', async (t) => {
  const w = await world(t);
  w.respond((req, res) => {
    res.writeHead(200, { 'content-length': '100' });
    res.write('{"ok":', () => req.socket.destroy());
  });
  assert.equal(await failure(w.http.request(get())), 'malformed');
  const garbage: Connector = {
    connect: () =>
      Promise.resolve(
        new Duplex({
          read() {
            this.push('NOT HTTP AT ALL\r\n\r\n');
            this.push(null);
          },
          write(_chunk, _encoding, done) {
            done();
          },
        }),
      ),
  };
  const g = await world(t, { connector: garbage });
  assert.equal(await failure(g.http.request(get())), 'malformed');
});

test('KBOX-47 a host outside every list, a bad URL and a non-https URL are refused, and nothing is connected', async (t) => {
  let connects = 0;
  const w = await world(t, { connector: { connect: () => Promise.reject(new Error(`connect ${(connects += 1)}`)) } });
  for (const url of ['https://evil.example/x', 'http://api.vendor.example/x', 'https://api.vendor.example:8443/x', 'not a url', 'https://u:p@api.vendor.example/x']) {
    assert.equal(await failure(w.http.request(get(url))), 'refused', url);
  }
  assert.equal(connects, 0);
});

test('KBOX-47 the gate serves a registry host to caller adapter and refuses it to caller relay; a relay-profile host serves both', async (t) => {
  const w = await world(t);
  const refusedFor = async (caller: 'relay' | 'adapter', url: string): Promise<string> =>
    w.egress.open(caller, new URL(url), new AbortController().signal).then(
      (socket) => {
        socket.destroy();
        return 'opened';
      },
      (e: unknown) => (e instanceof EgressRefused ? e.code : 'other'),
    );
  assert.equal(await refusedFor('adapter', `https://${HOST}/x`), 'opened');
  assert.equal(await refusedFor('relay', `https://${HOST}/x`), 'wrong_caller');
  assert.equal(await refusedFor('adapter', 'https://other.vendor.example/x'), 'undeclared_host');
  assert.equal(hostVerdict('relay', 'relay.example.com', ['relay.example.com'], [], [HOST]), 'allowed');
  assert.equal(hostVerdict('adapter', 'relay.example.com', ['relay.example.com'], [], [HOST]), 'allowed');
  assert.equal(hostVerdict('push', HOST, [], [], [HOST]), 'wrong_caller');
});

test('KBOX-14 a canary in a request header and in the response body is in no error message, stack or cause, on every failure kind', async (t) => {
  const c = canary();
  const secret = Buffer.from(c.bytes).toString('hex');
  const errors: unknown[] = [];
  const attempt = async (call: Promise<HttpResponse>): Promise<void> => {
    await call.then(
      () => assert.fail('a failure was expected'),
      (e: unknown) => void errors.push(e),
    );
  };
  const w = await world(t, { bodyCapBytes: 50 });
  w.respond((_req, res) => void res.end(`${secret}${'x'.repeat(100)}`));
  await attempt(w.http.request(get(URL_OK, { headers: { authorization: `Bearer ${secret}` } })));
  w.respond((req, res) => {
    res.writeHead(200, { 'content-length': '500' });
    res.write(secret, () => req.socket.destroy());
  });
  await attempt(w.http.request(get(URL_OK, { headers: { authorization: `Bearer ${secret}` } })));
  await attempt(w.http.request(get('https://evil.example/x', { headers: { authorization: `Bearer ${secret}` } })));
  const down = await world(t, { connector: { connect: () => Promise.reject(new Error(`could not connect with ${secret}`)) } });
  await attempt(down.http.request(get(URL_OK, { headers: { authorization: `Bearer ${secret}` } })));
  await attempt(refusingAdapterHttp.request(get(URL_OK, { headers: { authorization: `Bearer ${secret}` } })));
  assert.equal(errors.length, 5);
  for (const e of errors) {
    assert.ok(e instanceof HttpTransportError);
    c.assertAbsent({ message: e.message, inspected: inspect(e, { depth: 10 }), json: JSON.stringify(e), cause: String(e.cause ?? '') });
  }
});

test('KBOX-23 the refusing client refuses every call', async () => {
  assert.equal(await failure(refusingAdapterHttp.request(get())), 'refused');
});

const entryWith = (hosts: readonly string[]): PlatformEntry => ({ id: 'hostful', shape: NO_ISSUER_SHAPE, unverified: [], hosts });

test('KBOX-23 a registry entry host is an exact lower-case DNS name; a wildcard, port, path, upper case or address is refused naming the platform', () => {
  assert.equal(checkRegistry([entryWith(['api.vercel.com', 'sts.googleapis.com'])]).ok, true);
  assert.equal(checkRegistry([entryWith([])]).ok, true);
  for (const host of ['*.vercel.com', 'api.vercel.com:443', 'api.vercel.com/v1', 'API.vercel.com', 'localhost', '203.0.113.10', '', 'a..com', ' api.vercel.com', 'https://api.vercel.com']) {
    assert.deepEqual(checkRegistry([entryWith(['api.vercel.com', host])]), { ok: false, code: 'bad_host', platform: 'hostful' }, JSON.stringify(host));
  }
  assert.throws(() => assertRegistry([entryWith(['*.x.com'])]), (e: unknown) => e instanceof RegistryRefused && e.code === 'bad_host');
});

test('KBOX-23 createRegistry builds the list from the client and the clock, and the built list passes the registry checks', () => {
  const built = createRegistry({ http: refusingAdapterHttp, clock: { now: () => 0 } });
  assert.doesNotThrow(() => assertRegistry(built));
});

test('KBOX-35 the kit AdapterHttp sends a request to the fake in place of the origin, keeping method, path, query and headers, and records the host', async (t) => {
  const platform = await fakePlatform(t, { okBody: { fine: 1 } });
  const http = adapterHttpTo(platform);
  const answer = await http.request({ method: 'DELETE', url: 'https://api.vercel.com/v9/keys/k1?team=t%201&x=', headers: { Authorization: 'Bearer z', 'X-Odd': 'a b' } });
  assert.equal(answer.status, 200);
  assert.equal(Buffer.from(answer.body).toString('utf8'), '{"fine":1}');
  const [got] = platform.requests;
  assert.equal(got?.method, 'DELETE');
  assert.equal(got?.url, '/v9/keys/k1?team=t%201&x=');
  assert.equal(got?.headers['authorization'], 'Bearer z');
  assert.equal(got?.headers['x-odd'], 'a b');
  assert.equal(http.sent[0]?.originalHost, 'api.vercel.com');
});

test('KBOX-35 the kit AdapterHttp delivers a body whole to the server, returns a failing status as a status, and a refused connection as unreachable', async () => {
  const received: Buffer[] = [];
  const server = createPlainServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => void chunks.push(c));
    req.on('end', () => {
      received.push(Buffer.concat(chunks));
      res.writeHead(req.url === '/deny' ? 401 : 200);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const http = adapterHttpTo({ url: `http://127.0.0.1:${port}` });
  const body = new TextEncoder().encode('{"v":"ü 日本 \\n"}');
  assert.equal((await http.request({ method: 'PUT', url: 'https://api.x.example/p', body })).status, 200);
  assert.deepEqual(received[0], Buffer.from(body));
  assert.equal((await http.request({ method: 'GET', url: 'https://api.x.example/deny' })).status, 401);
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
  assert.equal(await failure(http.request({ method: 'GET', url: 'https://api.x.example/p' })), 'unreachable');
});

test('KBOX-47 KBOX-23 the call deadline bounds name resolution: a lookup that outlasts timeoutMs ends the call as timeout at the deadline, not when the lookup ends', async (t) => {
  const clock = new TimedClock(0);
  let lookups = 0;
  const w = await world(t, {
    clock,
    resolver: {
      resolve: () =>
        new Promise((resolve) => {
          lookups += 1;
          clock.after(3000, () => resolve([PUBLIC_ADDRESS]));
        }),
    },
  });
  let ended: HttpFailureCode | 'no failure' | undefined;
  const call = failure(w.http.request(get(URL_OK, { timeoutMs: 300 }))).then((code) => void (ended = code));
  await waitUntil(() => lookups === 1, 'the lookup to start');
  clock.advance(300);
  await waitUntil(() => ended !== undefined, 'the call to end at its deadline, before the lookup ends');
  await call;
  assert.equal(ended, 'timeout');
  assert.equal(w.seen.length, 0, 'nothing was sent');
});

test('KBOX-47 an already-aborted signal stops the gate before it resolves or connects', async () => {
  let resolves = 0;
  let connects = 0;
  const egress = createEgress({
    adapterHosts: [],
    registryHosts: [HOST],
    listed: [],
    resolver: {
      resolve: () => {
        resolves += 1;
        return Promise.resolve([PUBLIC_ADDRESS]);
      },
    },
    connector: {
      connect: () => {
        connects += 1;
        return Promise.reject(new Error('must not connect'));
      },
    },
    scheduler: new TimedClock(0),
  });
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(egress.open('adapter', new URL(URL_OK), aborted.signal), (e: unknown) => e instanceof EgressRefused);
  assert.equal(connects, 0);
  assert.equal(resolves, 0);
});

test('KBOX-47 a signal aborted while the lookup runs never reaches the connector', async () => {
  let connects = 0;
  const abort = new AbortController();
  const egress = createEgress({
    adapterHosts: [],
    registryHosts: [HOST],
    listed: [],
    resolver: {
      resolve: () => {
        abort.abort();
        return Promise.resolve([PUBLIC_ADDRESS]);
      },
    },
    connector: {
      connect: () => {
        connects += 1;
        return Promise.reject(new Error('must not connect'));
      },
    },
    scheduler: new TimedClock(0),
  });
  await assert.rejects(egress.open('adapter', new URL(URL_OK), abort.signal), (e: unknown) => e instanceof EgressRefused);
  assert.equal(connects, 0);
});

test('KBOX-23 a request the client cannot send (a header value with a line break, a bad header name, a bad method) rejects as HttpTransportError invalid_request, with no value in the error', async (t) => {
  const c = canary();
  const secret = Buffer.from(c.bytes).toString('hex');
  const w = await world(t);
  const bad: HttpRequest[] = [
    get(URL_OK, { headers: { 'x-k': `${secret}\r\nzz` } }),
    get(URL_OK, { headers: { [`bad name ${secret}`]: 'v' } }),
    { method: `BAD METHOD ${secret}`, url: URL_OK },
  ];
  for (const req of bad) {
    const error = await w.http.request(req).then(
      () => assert.fail('a failure was expected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof HttpTransportError, String(error));
    assert.equal(error.code, 'invalid_request');
    c.assertAbsent({ message: error.message, inspected: inspect(error, { depth: 10 }), json: JSON.stringify(error) });
  }
  assert.equal(w.seen.length, 0);
});

test('KBOX-23 a gate failure that is not a refusal (a resolver that throws) still rejects as HttpTransportError', async (t) => {
  const w = await world(t, {
    resolver: {
      resolve: () => {
        throw new TypeError('a resolver that throws instead of rejecting');
      },
    },
  });
  assert.equal(await failure(w.http.request(get())), 'unreachable');
});

test('KBOX-47 the main-relay registry is built with the refusing client: every adapter call the relay process could make is refused', async () => {
  const given: AdapterHttp[] = [];
  const registry = createRelayRegistry({ now: () => 0 }, (deps) => {
    given.push(deps.http);
    return [];
  });
  assert.deepEqual(registry, []);
  assert.equal(given.length, 1);
  assert.equal(given[0], refusingAdapterHttp);
  assert.equal(await failure(given[0]?.request(get()) ?? Promise.reject(new Error('no client'))), 'refused');
});

test('KBOX-23 KBOX-14 a body that drips past the deadline ends as timeout and never returns the partial body as an answer', async (t) => {
  const w = await world(t);
  let held: ServerResponse | undefined;
  w.respond((_req, res) => {
    res.writeHead(200, { 'content-length': '1000' });
    held = res;
  });
  let outcome: HttpFailureCode | 'answered' | undefined;
  const call = w.http
    .request(get(URL_OK, { timeoutMs: 5000 }))
    .then(
      () => 'answered' as const,
      (e: unknown) => (e instanceof HttpTransportError ? e.code : undefined),
    )
    .then((code) => void (outcome = code));
  await waitUntil(() => held !== undefined, 'the server to hold the response');
  for (let i = 0; i < 3; i += 1) {
    await new Promise<void>((resolve) => void held?.write('a', () => resolve()));
    w.clock.advance(1000);
  }
  assert.equal(outcome, undefined, 'still waiting before the deadline');
  w.clock.advance(2000);
  await waitUntil(() => outcome !== undefined, 'the call to end');
  await call;
  assert.equal(outcome, 'timeout');
});
