// KBOX-47: every outbound request of core and relay goes through one gate. It refuses hosts no adapter declares and the
// closed list does not name for that caller, and every private, link-local or loopback address; it resolves once and
// connects to that address. The resolver and connector are ports: these tests use fakes, plus the production wiring against
// literal addresses (refused before any socket) and the real TLS connector against a local server.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:tls';
import type { AddressInfo } from 'node:net';
import { Duplex } from 'node:stream';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { addressRefused, parseEgressHosts } from '../src/pure/egress-policy.ts';
import type { EgressHost } from '../src/pure/egress-policy.ts';
import { EgressRefused, createEgress, createTlsConnector, systemResolver } from '../src/shell/egress.ts';
import type { Caller, Connector, ConnectTarget, Egress, Resolver } from '../src/shell/egress.ts';
import { TimedClock, settle } from './kit/index.ts';
import { selfSignedCertificate } from './kit/tls.ts';

const PUBLIC = '203.0.113.10';
const LISTED: readonly EgressHost[] = [
  { host: 'fcm.googleapis.com', purpose: 'web push', caller: 'push' },
  { host: '*.notify.windows.com', purpose: 'web push', caller: 'push' },
  { host: 'nodejs.org', purpose: 'runtime download', caller: 'update' },
];

interface World {
  readonly egress: Egress;
  readonly clock: TimedClock;
  readonly connects: ConnectTarget[];
  readonly lookups: string[];
}

function world(options: { readonly answers?: (host: string, n: number) => readonly string[]; readonly connector?: Connector } = {}): World {
  const clock = new TimedClock(0);
  const connects: ConnectTarget[] = [];
  const lookups: string[] = [];
  const resolver: Resolver = {
    resolve: (host) => {
      lookups.push(host);
      return Promise.resolve(options.answers?.(host, lookups.length) ?? [PUBLIC]);
    },
  };
  const connector: Connector = options.connector ?? {
    connect: (target) => {
      connects.push(target);
      return Promise.resolve(new Duplex({ read() {}, write(_c, _e, done) { done(); } }));
    },
  };
  const egress = createEgress({ adapterHosts: ['api.pathplat.example', 'iam.hostplat.example'], listed: LISTED, resolver, connector, scheduler: clock });
  return { egress, clock, connects, lookups };
}

const refusal = async (w: World, caller: Caller, url: string): Promise<string> =>
  w.egress.open(caller, new URL(url), new AbortController().signal).then(
    (socket) => {
      socket.destroy();
      return 'opened';
    },
    (e: unknown) => (e instanceof EgressRefused ? e.code : `other: ${String(e)}`),
  );

test('KBOX-47 an undeclared host is refused before any lookup or connect', async () => {
  const w = world();
  assert.equal(await refusal(w, 'relay', 'https://evil.example/x'), 'undeclared_host');
  assert.equal(await refusal(w, 'relay', 'https://api.pathplat.example.evil.example/x'), 'undeclared_host');
  assert.deepEqual([w.lookups, w.connects], [[], []]);
});

test('KBOX-47 a listed non-adapter host used by the wrong caller is refused; adapter hosts are for relay and adapter calls only', async () => {
  const w = world();
  assert.equal(await refusal(w, 'relay', 'https://fcm.googleapis.com/send/x'), 'wrong_caller');
  assert.equal(await refusal(w, 'update', 'https://fcm.googleapis.com/send/x'), 'wrong_caller');
  assert.equal(await refusal(w, 'push', 'https://nodejs.org/dist/x'), 'wrong_caller');
  assert.equal(await refusal(w, 'push', 'https://api.pathplat.example/v1'), 'wrong_caller');
  assert.deepEqual(w.connects, []);
});

test('KBOX-47 a Web Push call to a listed push host passes, a wildcard entry takes a sub-domain only, and the connect goes to the resolved address', async () => {
  const w = world();
  assert.equal(await refusal(w, 'push', 'https://fcm.googleapis.com/fcm/send/abc'), 'opened');
  assert.equal(await refusal(w, 'push', 'https://db5p.notify.windows.com/w/?token=x'), 'opened');
  assert.equal(await refusal(w, 'push', 'https://notify.windows.com/w'), 'undeclared_host');
  assert.equal(await refusal(w, 'adapter', 'https://iam.hostplat.example/v1'), 'opened');
  assert.deepEqual(w.connects, [
    { address: PUBLIC, port: 443, servername: 'fcm.googleapis.com' },
    { address: PUBLIC, port: 443, servername: 'db5p.notify.windows.com' },
    { address: PUBLIC, port: 443, servername: 'iam.hostplat.example' },
  ]);
});

test('KBOX-47 every private, loopback, link-local and metadata address is refused, IPv4-mapped IPv6 included', () => {
  for (const address of [
    '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '127.8.8.8', '169.254.169.254', '169.254.0.1', '0.0.0.0', '100.64.0.1',
    '224.0.0.1', '255.255.255.255', '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:a00:1', '::ffff:169.254.169.254',
    '::ffff:127.0.0.1', '64:ff9b::a9fe:a9fe', '::127.0.0.1', 'not an address',
  ]) {
    assert.equal(addressRefused(address), true, address);
  }
  for (const address of ['203.0.113.10', '8.8.8.8', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '2001:db8::1', '2606:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(addressRefused(address), false, address);
  }
});

test('KBOX-47 a declared host that resolves to a private or metadata address is refused before connect', async () => {
  for (const answer of [['10.0.0.5'], ['169.254.169.254'], ['::ffff:127.0.0.1'], [PUBLIC, '192.168.0.1'], []]) {
    const w = world({ answers: () => answer });
    assert.equal(await refusal(w, 'relay', 'https://api.pathplat.example/v1'), answer.length === 0 ? 'resolve_failed' : 'private_address', answer.join(','));
    assert.deepEqual(w.connects, []);
  }
});

test('KBOX-47 a name that resolves first to a public and then to a private address is looked up once per call and pinned to the first answer', async () => {
  const w = world({ answers: (_host, n) => (n === 1 ? [PUBLIC] : ['10.0.0.9']) });
  assert.equal(await refusal(w, 'relay', 'https://api.pathplat.example/v1'), 'opened');
  assert.deepEqual(w.lookups, ['api.pathplat.example']);
  assert.deepEqual(w.connects.map((c) => c.address), [PUBLIC]);
  assert.equal(await refusal(w, 'relay', 'https://api.pathplat.example/v1'), 'private_address');
  assert.deepEqual(w.connects.map((c) => c.address), [PUBLIC]);
});

test('KBOX-47 a redirect target outside the list is refused', async () => {
  const w = world();
  const location = new URL('https://attacker.example/steal', 'https://api.pathplat.example/v1/x');
  assert.equal(await refusal(w, 'relay', location.href), 'undeclared_host');
});

test('KBOX-47 only https on the default port, with no user info, goes out', async () => {
  const w = world();
  for (const url of ['http://api.pathplat.example/v1', 'https://api.pathplat.example:8443/v1', 'https://u:p@api.pathplat.example/v1', 'ftp://api.pathplat.example/']) {
    assert.equal(await refusal(w, 'relay', url), 'bad_url', url);
  }
  assert.deepEqual(w.lookups, []);
});

test('KBOX-47 a connect that does not finish in 10 s is connect_timeout and is aborted; a refused connect is connect_failed', async () => {
  let aborted = false;
  const hung = world({
    connector: {
      connect: (_target, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            aborted = true;
            reject(new Error('aborted'));
          });
        }),
    },
  });
  const pending = refusal(hung, 'relay', 'https://api.pathplat.example/v1');
  await settle();
  hung.clock.advance(9_999);
  await settle();
  assert.equal(aborted, false);
  hung.clock.advance(1);
  assert.equal(await pending, 'connect_timeout');
  assert.equal(aborted, true);
  const refused = world({ connector: { connect: () => Promise.reject(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })) } });
  assert.equal(await refusal(refused, 'relay', 'https://api.pathplat.example/v1'), 'connect_failed');
});

test('KBOX-47 the production wiring refuses literal private addresses before it opens any socket', async () => {
  let sockets = 0;
  const tls = createTlsConnector();
  const counting: Connector = {
    connect: (target, signal) => {
      sockets += 1;
      return tls.connect(target, signal);
    },
  };
  const egress = createEgress({ adapterHosts: ['169.254.169.254', '10.1.2.3', '127.0.0.1'], listed: LISTED, resolver: systemResolver, connector: counting, scheduler: new TimedClock(0) });
  const open = (url: string): Promise<string> =>
    egress.open('relay', new URL(url), new AbortController().signal).then(
      () => 'opened',
      (e: unknown) => (e instanceof EgressRefused ? e.code : 'other'),
    );
  assert.equal(await open('https://169.254.169.254/latest/meta-data/'), 'private_address');
  assert.equal(await open('https://10.1.2.3/'), 'private_address');
  assert.equal(await open('https://127.0.0.1/'), 'private_address');
  assert.equal(await open('https://[::ffff:127.0.0.1]/'), 'undeclared_host');
  assert.equal(await open('https://8.8.8.8/'), 'undeclared_host');
  assert.equal(sockets, 0);
});

async function tlsServer(t: TestContext, name: string, alpn: readonly string[]): Promise<{ readonly port: number; readonly ca: string }> {
  const { key, cert } = await selfSignedCertificate(t, name);
  const server = createServer({ key, cert, ALPNProtocols: [...alpn] }, (socket) => socket.end());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  return { port: (server.address() as AddressInfo).port, ca: cert };
}

test('KBOX-13 the upstream TLS connection offers only http/1.1, so a server that prefers h2 negotiates no h2', async (t) => {
  const { port, ca } = await tlsServer(t, 'api.pathplat.example', ['h2', 'http/1.1']);
  const socket = await createTlsConnector({ ca }).connect({ address: '127.0.0.1', port, servername: 'api.pathplat.example' }, new AbortController().signal);
  t.after(() => socket.destroy());
  assert.equal((socket as unknown as { alpnProtocol: string | false }).alpnProtocol, 'http/1.1');
});

test('KBOX-47 the TLS connector checks the certificate against the host name', async (t) => {
  const { port, ca } = await tlsServer(t, 'other.example', ['http/1.1']);
  await assert.rejects(createTlsConnector({ ca }).connect({ address: '127.0.0.1', port, servername: 'api.pathplat.example' }, new AbortController().signal));
});

test('KBOX-47 deploy/egress-hosts.json names every push host for core push only and every runtime.lock download host for the update intake only', () => {
  const parsed = parseEgressHosts(JSON.parse(readFileSync(new URL('../deploy/egress-hosts.json', import.meta.url), 'utf8')) as unknown);
  assert.ok(parsed.ok);
  const push = JSON.parse(readFileSync(new URL('../src/data/push-hosts.json', import.meta.url), 'utf8')) as string[];
  assert.deepEqual(parsed.value.filter((h) => h.caller === 'push').map((h) => h.host).sort(), [...push].sort());
  const lock = readFileSync(new URL('../runtime.lock', import.meta.url), 'utf8');
  const downloads = [...lock.matchAll(/^[^#\s].*\s(https:\/\/\S+)$/gm)].map((m) => new URL(m[1] ?? '').hostname);
  assert.deepEqual(parsed.value.filter((h) => h.caller === 'update').map((h) => h.host).sort(), [...new Set(downloads)].sort());
  assert.ok(parsed.value.every((h) => h.purpose.length > 0));
});

test('KBOX-47 the hosts file is closed: an unknown member, an unknown caller or a malformed host is refused', () => {
  for (const raw of [
    { hosts: [{ host: 'a.example', purpose: 'p', caller: 'relay' }] },
    { hosts: [{ host: 'a.example', purpose: 'p', caller: 'push', extra: 1 }] },
    { hosts: [{ host: 'A.example', purpose: 'p', caller: 'push' }] },
    { hosts: [{ host: '10.0.0.1', purpose: 'p', caller: 'push' }] },
    { hosts: [{ host: 'a.example', purpose: '', caller: 'push' }] },
    { hosts: [], other: true },
    [],
  ]) {
    assert.equal(parseEgressHosts(raw).ok, false, JSON.stringify(raw));
  }
});
