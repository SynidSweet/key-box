// A demo of the phone pages: the real core parts (openCore, openApproveCore, openRotation, the updater, the real routes) over a fresh temp state
// directory, served as keys.localhost over TLS on 127.0.0.1 the way Caddy serves keys.<domain> (X-KB-Client-Ip set from the connection, no
// forwarding headers). The only fakes are the ones the tests use: root's trust copy (it checks the real setup code store and the real proofs),
// a push recorder and one paste platform. State is seeded through the box's own routes: a rotation of an admin key, an update, a paste
// task, and, once the owner has set up, a phone that registered through /recover/register and waits for approval.
// Run `node test/support/demo-pages.ts [--port N] [--dir D]`: it prints one line per page and serves until SIGINT or SIGTERM, then removes
// its temp directory. Under `node --test` this file does nothing.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import type { Server } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { KeyRow } from '../../src/ports/meta.ts';
import type { Issuer, IssuerCapabilities, Verifier } from '../../src/ports/issuer.ts';
import type { KeyClass, Scope } from '../../src/ports/types.ts';
import { fileSha256, releaseHash } from '../../src/pure/release-hash.ts';
import { parseWordlist } from '../../src/pure/codes.ts';
import { hashToken, newToken } from '../../src/pure/tokens.ts';
import { openApproveCore } from '../../src/shell/approve-core.ts';
import type { Executor } from '../../src/shell/approvals.ts';
import { systemClock, systemScheduler } from '../../src/shell/clock.ts';
import { createCodeRoot } from '../../src/shell/console.ts';
import { openCore } from '../../src/shell/core.ts';
import { createApiServer } from '../../src/shell/http.ts';
import { openPrivateDatabase } from '../../src/shell/private-db.ts';
import { systemRandom } from '../../src/shell/random.ts';
import { openRotation } from '../../src/shell/rotation.ts';
import type { Rotation } from '../../src/shell/rotation.ts';
import type { PlatformSource } from '../../src/shell/rotation-ports.ts';
import { createUpdater } from '../../src/shell/updater.ts';
import { FakePush } from '../fakes/push.ts';
import { FakeTrust } from '../fakes/trust.ts';
import { makeCertificate } from '../kit/cert.ts';
import { drive, lent } from '../kit/index.ts';
import type { Driver } from '../kit/index.ts';
import { softApprover } from '../kit/approver.ts';
import { challenges, newApproverBody, wire } from './approve-world.ts';
import { tarOf } from './tar.ts';

const DOMAIN = 'localhost';
const HOST = `keys.${DOMAIN}`;
const RP = { rpId: HOST, origin: `https://${HOST}` } as const;
const BOOT = 'de300000-0000-4000-8000-000000000001';
const PLATFORM = 'anthropic';
const ADMIN_KEYREF = `${PLATFORM}/shop/ANTHROPIC_ADMIN_KEY`;
const COMMIT = 'd3adbeef'.padEnd(40, '0');
const POLL_MS = 200;

/** A value the demo's paste platform accepts: `pk-` and 32 hex characters. */
export const DEMO_PASTE_VALUE = `pk-${'0123456789abcdef'.repeat(2)}`;

export interface DemoPage {
  /** What the page is, in words. */
  readonly name: string;
  /** The address the box expects the phone to use (its WebAuthn origin has no port). */
  readonly url: string;
}

export interface DemoOptions {
  /** The directory the demo makes its own temp directory in; the system temp directory when absent. */
  readonly dir?: string;
  /** The TCP port on 127.0.0.1; any free port when absent. */
  readonly port?: number;
}

export interface Demo {
  readonly port: number;
  /** The self-signed certificate (PEM) the pages are served with, for a client that trusts it. */
  readonly certificatePath: string;
  /** What the box's console would show: the setup code and the recovery code of this boot. */
  readonly setupCode: string;
  readonly recoveryCode: string;
  readonly pages: readonly DemoPage[];
  /** Resolves once the owner has set up and the box holds the pending phone's approval; rejects if that seeding failed. */
  readonly pendingPhone: Promise<void>;
  /** Closes the server and every store, then removes the temp directory. */
  stop(): Promise<void>;
}

const keyRow = (keyref: string): KeyRow => ({
  keyref,
  platform: PLATFORM,
  name: 'ANTHROPIC_ADMIN_KEY',
  projects: ['shop'],
  class: 'admin',
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

const classify = (scope: Scope): KeyClass => {
  const items = scope['items'];
  return Array.isArray(items) && items.includes('admin') ? 'admin' : 'ordinary';
};

/** One paste platform whose keys are made on the phone: `pk-` and 32 hex characters, accepted by its verifier. */
function pasteSource(): PlatformSource {
  const issuer: Issuer = {
    platform: PLATFORM,
    capabilities: (): IssuerCapabilities => ({
      create: 'paste',
      revoke: 'paste',
      selfRotate: false,
      overlap: true,
      set: 'none',
      revealOnce: false,
      scopeSchema: { fields: ['items'] },
      shape: { prefix: 'pk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true },
      classify,
    }),
    issue: () => Promise.reject(new Error('a paste platform cannot issue')),
    revoke: () => Promise.resolve('absent'),
  };
  const verifier: Verifier = { verify: () => Promise.resolve('ok') };
  return {
    platform: (id) => (id === PLATFORM ? { issuer, verifier, keyPageUrl: 'https://platform.example/keys' } : undefined),
    destination: () => undefined,
    // The paste platform issues nothing, but a run reads its master before it pushes: the demo hands it a stand-in.
    master: () => lent(Buffer.from('demo master key, never sent anywhere'), 'demo-master'),
  };
}

/** The release the box says it runs, on disk the way the updater reads it: `releases/<H0>` behind a `current` link. */
function writeRunningRelease(dir: string): string {
  const files = { 'README.md': 'version one\n', 'src/main-core.ts': 'the old core\n' };
  const h0 = releaseHash(Object.entries(files).map(([path, body]) => ({ path, executable: false, sha256: fileSha256(Buffer.from(body)) })));
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(dir, 'releases', h0, path, '..'), { recursive: true });
    writeFileSync(join(dir, 'releases', h0, path), body);
  }
  symlinkSync(join(dir, 'releases', h0), join(dir, 'current'));
  return h0;
}

/** Caddy's part: TLS on 127.0.0.1, the connection's address in X-KB-Client-Ip, every forwarding header dropped, one unix socket behind. */
function frontDoor(tls: { readonly key: string; readonly cert: string }, socket: string): Server {
  return createTlsServer(tls, (req, res) => {
    const headers: Record<string, string | string[] | undefined> = { ...req.headers, 'x-kb-client-ip': req.socket.remoteAddress };
    for (const name of ['x-forwarded-for', 'x-real-ip', 'forwarded', 'x-forwarded-proto', 'x-forwarded-host']) delete headers[name];
    const upstream = httpRequest({ socketPath: socket, method: req.method, path: req.url, headers }, (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers);
      answer.pipe(res);
    });
    upstream.on('error', () => {
      res.writeHead(502).end();
    });
    req.pipe(upstream);
  });
}

const listen = (server: Server, port: number): Promise<number> =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') reject(new Error('the demo server has no port'));
      else resolve(address.port);
    });
  });

const closeServer = (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
    server.closeAllConnections();
  });

const nap = (ms: number): Promise<void> => new Promise((resolve) => void setTimeout(resolve, ms));

async function must(reply: Promise<{ readonly status: number; readonly body: string; json(): unknown }>, expected: number, what: string): Promise<unknown> {
  const answer = await reply;
  if (answer.status !== expected) throw new Error(`${what}: ${answer.status} ${answer.body}`);
  return answer.json();
}

export async function startDemo(options: DemoOptions = {}): Promise<Demo> {
  const dir = mkdtempSync(join(options.dir ?? tmpdir(), 'kb-demo-'));
  const closers: (() => void | Promise<void>)[] = [() => rmSync(dir, { recursive: true, force: true })];
  const stop = async (): Promise<void> => {
    for (const close of closers.splice(0).reverse()) await close();
  };
  try {
    const clock = systemClock;
    const random = systemRandom;
    const stateDir = join(dir, 'state');
    const parts = openCore({ stateDir, clock, scheduler: systemScheduler, random });
    const priv = openPrivateDatabase(join(stateDir, 'private.db'));
    closers.push(() => priv.close(), () => parts.close());
    const push = new FakePush();
    const consoleLines: string[] = [];
    const wordlist = parseWordlist(readFileSync(new URL('../../src/data/wordlist.txt', import.meta.url), 'utf8'));
    const codes = createCodeRoot({ dir: join(dir, 'codes'), sink: (line) => void consoleLines.push(line), random, clock, wordlist });
    const trust = new FakeTrust(codes, () => BOOT);
    const h0 = writeRunningRelease(dir);
    const updater = createUpdater({
      stagingDir: join(dir, 'staging'),
      resultsDir: join(dir, 'results'),
      currentLink: join(dir, 'current'),
      propose: (input) => approve.approvals.propose(input),
      approvals: () => approve.approvals,
      events: { append: (kind, data) => parts.events.append(kind, data) },
    });
    mkdirSync(join(dir, 'staging'), { recursive: true });
    mkdirSync(join(dir, 'results'), { recursive: true });
    let rotation: Rotation | undefined;
    const viaRotation = (kind: 'rotate_key' | 'add_key'): Executor => (approval) => {
      const executor = rotation?.executors[kind];
      if (executor === undefined) throw new RangeError('rotation is not open');
      return executor(approval);
    };
    const approve = openApproveCore({
      parts,
      approverStore: priv,
      trust,
      push,
      clock,
      random,
      domain: DOMAIN,
      wordlist,
      vet: () => 'ok',
      executors: { install_update: updater.executor, rotate_key: viaRotation('rotate_key'), add_key: viaRotation('add_key') },
      updateChanges: (action) => updater.changes(action),
    });
    rotation = openRotation({ parts, approvals: approve.approvals, approvers: approve.approvers, push, clock, scheduler: systemScheduler, random, audit: parts.audit, source: pasteSource() });
    const rotationOpen = rotation;
    // As the service does, once the server listens: resume, reconcile and the schedule; the stop cancels the timers, then idle waits for work in flight.
    closers.push(() => rotationOpen.idle());
    const server = createApiServer({ routes: [...parts.routes, ...approve.routes, ...updater.routes, ...rotation.routes], tokens: approve.tokens.tokenStore, audit: parts.audit, random, clock, journal: () => undefined });
    const socket = join(dir, 'http.sock');
    await server.listen(socket);
    closers.push(() => server.stop());
    closers.push(rotationOpen.run());

    const certDir = join(dir, 'tls');
    mkdirSync(certDir);
    const certificate = makeCertificate(certDir, HOST);
    const front = frontDoor(certificate, socket);
    const port = await listen(front, options.port ?? 0);
    closers.push(() => closeServer(front));

    // The owner's phone has not set up: the console shows the setup code, and kb-code has written this boot's recovery code.
    codes.writeSetupCode(false);
    const setupCode = codeOf(consoleLines);
    codes.writeRecoveryCode(BOOT);
    const recoveryCode = codeOf(consoleLines);

    const driver = drive(socket);
    const control = newToken(random);
    parts.meta.addMachine({ label: 'mission-control', scope: 'control', tokenSha256: hashToken(control), enrolledAt: clock.now() });
    parts.meta.putKey(keyRow(ADMIN_KEYREF));
    const api = (path: string, body?: string | Uint8Array, contentType = 'application/json') =>
      driver.request({ path, method: body === undefined ? 'GET' : 'POST', headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${control}`, 'content-type': contentType }, ...(body === undefined ? {} : { body }) });

    await must(api('/api/proposals', JSON.stringify({ action: { kind: 'rotate_key', keyref: ADMIN_KEYREF }, reason: { agent: 'rotation-bot', text: 'The thirty days of this admin key are up.' } })), 201, 'the rotation proposal');
    const tar = tarOf([{ name: 'README.md', body: 'version two\n' }, { name: 'src/', type: '5' }, { name: 'src/main-core.ts', body: 'the new core\n' }, { name: 'src/extra.ts', body: 'one more file\n' }]);
    await must(api(`/api/updates?commit=${COMMIT}`, tar, 'application/x-tar'), 201, `the update over ${h0}`);
    const task = await must(api('/api/keys', JSON.stringify({ platform: PLATFORM, name: 'ANTHROPIC_KEY', projects: ['shop'], scope: { items: ['admin'] }, destinations: [] })), 202, 'the paste task');
    const pasteId = (task as { paste_task_id?: unknown }).paste_task_id;
    if (typeof pasteId !== 'string') throw new Error('the box opened no paste task');

    const pages: readonly DemoPage[] = [
      { name: 'setup (before the owner sets up)', url: `https://${HOST}/setup` },
      { name: 'recovery or add a phone', url: `https://${HOST}/recover` },
      { name: 'the app: queue of approvals', url: `https://${HOST}/` },
      { name: 'paste a key', url: `https://${HOST}/paste.html#${pasteId}` },
    ];
    const pendingPhone = seedPendingPhone(driver, approve.approvers, closers);
    // A seeding that fails is reported to whoever awaits it; an unawaited one must not end the process.
    pendingPhone.catch(() => undefined);
    return { port, certificatePath: join(certDir, 'cert.pem'), setupCode, recoveryCode, pages, pendingPhone, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}

/** The last twelve words the console wrote. */
const codeOf = (lines: readonly string[]): string => /([a-z]+(?: [a-z]+){11})/.exec(lines.at(-1) ?? '')?.[1] ?? '';

/**
 * Once an owner has set up: an approving phone asks for a registration code, a second phone registers with it at /recover/register (the box holds it
 * pending and opens the approver_add with its fingerprint). Stops looking when the demo stops.
 */
async function seedPendingPhone(driver: Driver, approvers: { count(): number; ids(): readonly string[]; startAdd(issuerId: string): string }, closers: (() => void | Promise<void>)[]): Promise<void> {
  let stopped = false;
  closers.push(() => void (stopped = true));
  while (approvers.count() === 0) {
    if (stopped) return;
    await nap(POLL_MS);
  }
  const owner = approvers.ids()[0];
  if (owner === undefined) throw new Error('the box has an approver and names none');
  const code = approvers.startAdd(owner);
  const second = softApprover();
  const nonce = await must(driver.request({ path: '/app/nonce?purpose=register', headers: { 'x-kb-client-ip': '203.0.113.10' } }), 200, 'the registration nonce');
  const bytes = Uint8Array.from(Buffer.from((nonce as { nonce_b64: string }).nonce_b64, 'base64url'));
  const body = { code, approver: newApproverBody(second), proof: wire(bytes, second.prove(challenges.register(bytes), RP)), phrase: 'green lantern' };
  await must(driver.request({ path: '/recover/register', method: 'POST', headers: { 'x-kb-client-ip': '203.0.113.10', 'content-type': 'application/json' }, body: JSON.stringify(body) }), 201, 'the second phone');
}

function argOf(argv: readonly string[], name: string): string | undefined {
  const at = argv.indexOf(name);
  return at < 0 ? undefined : argv[at + 1];
}

async function main(argv: readonly string[]): Promise<void> {
  const port = argOf(argv, '--port');
  const dir = argOf(argv, '--dir');
  const demo = await startDemo({ ...(port === undefined ? {} : { port: Number(port) }), ...(dir === undefined ? {} : { dir }) });
  const out = [
    `demo serving on 127.0.0.1:${demo.port} (TLS, certificate ${demo.certificatePath})`,
    `browse with: --host-resolver-rules="MAP ${HOST} 127.0.0.1:${demo.port}" --ignore-certificate-errors (the passkey origin is https://${HOST})`,
    `setup code: ${demo.setupCode}`,
    `recovery code: ${demo.recoveryCode}`,
    `paste value: ${DEMO_PASTE_VALUE}`,
    ...demo.pages.map((p) => `page\t${p.name}\t${p.url}`),
    'ready',
  ];
  process.stdout.write(`${out.join('\n')}\n`);
  void demo.pendingPhone.then(
    () => process.stdout.write('pending phone seeded: the queue holds an approver_add with its fingerprint\n'),
    (error: unknown) => process.stderr.write(`pending phone not seeded: ${error instanceof Error ? error.message : 'failed'}\n`),
  );
  await new Promise<void>((resolve) => {
    process.once('SIGINT', resolve);
    process.once('SIGTERM', resolve);
  });
  await demo.stop();
}

if (import.meta.main && !process.env['NODE_TEST_CONTEXT']) await main(process.argv.slice(2));
