// The core process: opens the state directory, serves the machine API and, once the box's domain is configured, the phone
// app and its approvals on one unix socket; stops on SIGTERM. Later units add their routes, ports and executors here. This is
// the only file besides the private-db adapter that names private.db.
import { mkdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import type { AuditEvent } from './ports/audit.ts';
import type { Clock, Scheduler } from './ports/clock.ts';
import type { PlatformEntry } from './ports/platform.ts';
import type { Random } from './ports/random.ts';
import { DOMAIN_NAME } from './pure/actions.ts';
import type { Action, ActionKind } from './pure/actions.ts';
import { parseWordlist } from './pure/codes.ts';
import { RegistryRefused, assertRegistry } from './pure/profile.ts';
import { shapeOfPlatform } from './pure/platform-shape.ts';
import { vetAction } from './pure/proposal-vet.ts';
import { osErrorCode } from './pure/errors.ts';
import { decodeJsonBody } from './pure/schemas.ts';
import { openApproveCore } from './shell/approve-core.ts';
import { systemClock, systemScheduler } from './shell/clock.ts';
import { openCore } from './shell/core.ts';
import { createApiServer } from './shell/http.ts';
import { createLendHandler, loadCredentialShapes } from './shell/lend-core.ts';
import { createLendServer } from './shell/lend-socket.ts';
import { createMintedValues } from './shell/minted-values.ts';
import type { Route } from './shell/http.ts';
import { createIdleWatch } from './shell/idle-watch.ts';
import type { IdleWatch } from './shell/idle-watch.ts';
import { createShareWriter, shareRoute } from './shell/share-writer.ts';
import { createMetaShareSource } from './shell/share-source.ts';
import { createPush } from './shell/push.ts';
import { createLazyEgress, loadEgressHosts } from './shell/egress-system.ts';
import { createHttpPushTransport } from './shell/push-transport.ts';
import { openPrivateDatabase } from './shell/private-db.ts';
import { systemRandom } from './shell/random.ts';
import { createRegistry } from './platforms/registry.ts';
import { createAdapterHttp } from './shell/adapter-http.ts';
import { createTrustInstaller } from './shell/trust-installer.ts';
import { createUpdater } from './shell/updater.ts';
import type { Executor } from './shell/approvals.ts';
import { createPlatformSource } from './shell/platform-source.ts';
import { openRotation } from './shell/rotation.ts';
import type { Rotation } from './shell/rotation.ts';
import type { PlatformSource } from './shell/rotation-ports.ts';

interface Config {
  readonly stateDir: string;
  readonly socket: string;
  /** Where kb-relay asks core for passes, grants, lent values, scans and audit rows (KBOX-3). Absent: no relay call is served. */
  readonly lendSocket: string | undefined;
  /** The box's domain; the phone app lives on `keys.<domain>`. Absent until the bootstrap configures it. */
  readonly domain: string | undefined;
  /** Core's staging directory, root's results directory and the running release's link (KBOX-6). */
  readonly staging: string;
  readonly installResults: string;
  readonly current: string;
}

/** The environment is parsed once, here; the rest of the process takes the typed value. */
function readConfig(env: NodeJS.ProcessEnv): Config {
  const stateDir = env['KB_STATE_DIR'] ?? '/var/lib/keybox';
  const socket = env['KB_SOCKET'] ?? '/run/keybox/http.sock';
  const lendSocket = env['KB_LEND_SOCKET'];
  const domain = env['KB_DOMAIN'];
  const staging = join(stateDir, 'staging');
  const installResults = env['KB_INSTALL_RESULTS'] ?? '/var/lib/keybox-install';
  const current = env['KB_CURRENT'] ?? '/opt/keybox/current';
  if (![stateDir, socket, installResults, current].every((p) => isAbsolute(p)) || (lendSocket !== undefined && !isAbsolute(lendSocket))) {
    throw new RangeError('KB_STATE_DIR, KB_SOCKET, KB_LEND_SOCKET, KB_INSTALL_RESULTS and KB_CURRENT are absolute paths');
  }
  if (domain !== undefined && !DOMAIN_NAME.test(domain)) throw new RangeError('KB_DOMAIN is a lower-case domain name');
  return { stateDir, socket, lendSocket, domain, staging, installResults, current };
}

const SWEEP_EVERY_MS = 60 * 60_000;
/** How often core looks for root's answer to an install it waits for. */
const SETTLE_EVERY_MS = 5_000;
/** How often core samples /proc for the idle watch (KBOX-21). */
const IDLE_SAMPLE_EVERY_MS = 10 * 60_000;

/** The nominal link speed from deploy/runtime.config.json (KBOX-21); the file is shared, so only this member is read. */
function linkMbps(): number {
  const raw = decodeJsonBody(readFileSync(new URL('../deploy/runtime.config.json', import.meta.url)));
  const value = raw.ok && typeof raw.value === 'object' && raw.value !== null ? (raw.value as Record<string, unknown>)['link_mbps'] : undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) throw new RangeError('runtime.config.json does not name link_mbps');
  return value;
}

/** The route table of core (KBOX-1): the store's control routes, then the phone and approval routes, then the update intake. */
export function coreRoutes(parts: readonly Route[], approve: readonly Route[], update: readonly Route[]): readonly Route[] {
  return [...parts, ...approve, ...update];
}

/** What core takes from the process: the clock, the timers, the randomness and where the journal goes. A test hands in its own. */
export interface CoreRuntime {
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly random: Random;
  readonly journal: (code: string) => void;
  /** The platform adapters rotation is given; production derives them from the registry (a test passes its own). */
  readonly platforms?: PlatformSource;
  /** The platform registry the box runs with; production builds it with `createRegistry`, a test passes its own. */
  readonly registry?: readonly PlatformEntry[];
  /** The egress host list core reads and checks at its start; production reads deploy/egress-hosts.json (a test passes another file). */
  readonly egressHostsFile?: URL;
}

const systemRuntime: CoreRuntime = {
  clock: systemClock,
  scheduler: systemScheduler,
  random: systemRandom,
  journal: (code) => void process.stderr.write(`keybox core: ${code}\n`),
};

export interface StartedCore {
  /** The route table the server answers from. */
  readonly routes: readonly Route[];
  /** The kinds core has an executor for (none without the approval half): a proposal of any other kind is refused up front. */
  readonly executorKinds: ReadonlySet<ActionKind>;
  /**
   * Cancels every timer core set and closes the sockets; resolves then. A rotation run waiting on a platform or destination call is not waited
   * for (review N4): every run is persisted step by step, so the process may end there and the next start resumes it.
   */
  stop(): Promise<void>;
  /** Resolves once a stop has closed the stores, which happens when rotation's work in flight has ended; rejects when closing failed. */
  readonly closed: Promise<void>;
}

/** Opens the state directory, wires every part and starts listening. The environment is read once, here. */
export async function startCore(env: NodeJS.ProcessEnv, runtime: CoreRuntime = systemRuntime): Promise<StartedCore> {
  const { clock, scheduler, random, journal } = runtime;
  const config = readConfig(env);
  // The host list is read here, so a bad one stops the start. The adapters' client holds the gate and the gate reads the registry's hosts: those are bound on first use.
  const egress = createLazyEgress(() => registry, loadEgressHosts(runtime.egressHostsFile));
  const registry = runtime.registry ?? createRegistry({ http: createAdapterHttp({ egress, scheduler }), clock });
  assertRegistry(registry);
  const parts = openCore({ stateDir: config.stateDir, clock, scheduler, random });
  const privateStore = openPrivateDatabase(join(config.stateDir, 'private.db'));
  let approve: ReturnType<typeof openApproveCore> | undefined;
  let idle: IdleWatch | undefined;
  let rotation: Rotation | undefined;
  const wait = (ms: number): Promise<void> => new Promise((resolve) => void scheduler.after(ms, resolve));
  const updater = createUpdater({
    stagingDir: config.staging,
    resultsDir: config.installResults,
    currentLink: config.current,
    propose: (input) => {
      if (approve === undefined) throw new RangeError('updates need the approval half');
      return approve.approvals.propose(input);
    },
    approvals: () => {
      if (approve === undefined) throw new RangeError('updates need the approval half');
      return approve.approvals;
    },
    events: parts.events,
  });
  const running = updater.running();
  if (running === undefined) journal('no_release');
  else parts.meta.setRelease(running);
  mkdirSync(config.staging, { recursive: true, mode: 0o750 });
  if (config.domain === undefined) journal('no_domain');
  else {
    const trust = createTrustInstaller({ stagingDir: config.staging, resultsDir: config.installResults, random, clock, wait });
    const push = createPush({ store: privateStore, transport: createHttpPushTransport(egress), scheduler, clock, random, audit: parts.audit, subject: `https://keys.${config.domain}` });
    const wordlist = parseWordlist(readFileSync(new URL('./data/wordlist.txt', import.meta.url), 'utf8'));
    idle = createIdleWatch({ files: { stat: '/proc/stat', meminfo: '/proc/meminfo', netdev: '/proc/net/dev' }, clock, push, linkMbps: linkMbps(), notifier: { notice: journal } });
    // Rotation needs the approvals and approvers that need its executors: the executors reach it once it is open (an approval is decided long after start).
    const viaRotation = (kind: 'rotate_key' | 'add_key'): Executor => (approval) => {
      const executor = rotation?.executors[kind];
      if (executor === undefined) throw new RangeError('rotation is not open');
      return executor(approval);
    };
    approve = openApproveCore({
      parts,
      approverStore: privateStore,
      trust,
      push,
      clock,
      random,
      domain: config.domain,
      wordlist,
      vet: vetAction(registry),
      refuseUnwired: true,
      executors: { install_update: updater.executor, rotate_key: viaRotation('rotate_key'), add_key: viaRotation('add_key') },
      updateChanges: (action) => updater.changes(action),
    });
    const source = runtime.platforms ?? createPlatformSource({ registry, meta: parts.meta, vault: parts.vault });
    rotation = openRotation({ parts, approvals: approve.approvals, approvers: approve.approvers, push, clock, scheduler, random, audit: parts.audit, source });
  }
  const rotationStore = rotation?.store;
  const shares = createShareWriter({
    dir: join(config.stateDir, 'share'),
    meta: parts.meta,
    signingKey: parts.share.signingKey,
    source: createMetaShareSource({ meta: parts.meta, values: parts.share.values, shapeOf: (platform) => shapeOfPlatform(registry, platform), ...(rotationStore === undefined ? {} : { generations: (keyref: string) => rotationStore.gens(keyref) }) }),
    events: parts.events,
    hub: parts.hub,
    clock,
    scheduler,
    random,
    audit: parts.audit,
  });
  // A first file that cannot be written does not stop the box: the file is served as stale (503) until the next key.changed makes one.
  await shares.start().catch(() => parts.audit.append({ action: 'share.refresh_failed', subject: 'share', at: clock.now(), detail: { code: 'start_failed' } }));
  const routes = [...coreRoutes(parts.routes, approve?.routes ?? [], approve === undefined || running === undefined ? [] : updater.routes), shareRoute(shares), ...(rotation?.routes ?? [])];
  const server = createApiServer({
    routes,
    tokens: approve?.tokens.tokenStore ?? parts.meta,
    audit: parts.audit,
    random,
    clock,
    journal,
  });
  await server.listen(config.socket);
  // Platform adapters register the short-lived values they mint here, so the scanner holds them while they live (KBOX-14).
  const minted = createMintedValues(clock);
  const lend = createLendServer(
    createLendHandler({ meta: parts.meta, tokens: approve?.tokens.tokenStore ?? parts.meta, vault: parts.vault, audit: parts.audit, events: parts.events, registry, shapes: loadCredentialShapes(), clock, minted, journal }),
    journal,
  );
  if (config.lendSocket === undefined) journal('no_lend_socket');
  else await lend.listen(config.lendSocket);
  // A timed job schedules its next run BEFORE it works, so neither the work nor the audit of its failure can stop the schedule. A throw is
  // audited; when the audit itself throws, the journal says so (nothing is swallowed, and nothing escapes the timer: under the real timer an
  // uncaught throw would end core and stop every later run).
  const notifier = { notice: journal };
  const failSafeAudit = {
    append(event: AuditEvent): void {
      try {
        parts.audit.append(event);
      } catch {
        notifier.notice(`audit_failed:${event.action}`);
      }
    },
  };
  let cancelSweep = (): void => undefined;
  const sweep = (): void => {
    cancelSweep = scheduler.after(SWEEP_EVERY_MS, sweep);
    try {
      approve?.approvals.sweep();
    } catch {
      failSafeAudit.append({ action: 'approvals.sweep_failed', subject: 'approvals', at: clock.now(), detail: { code: 'sweep_failed' } });
    }
  };
  let cancelSettle = (): void => undefined;
  const settle = (): void => {
    cancelSettle = scheduler.after(SETTLE_EVERY_MS, settle);
    try {
      updater.settle();
    } catch {
      failSafeAudit.append({ action: 'update.settle_failed', subject: 'updater', at: clock.now(), detail: { code: 'settle_failed' } });
    }
  };
  if (approve !== undefined) settle();
  let cancelIdle = (): void => undefined;
  const sampleIdle = (): void => {
    idle?.sample();
    cancelIdle = scheduler.after(IDLE_SAMPLE_EVERY_MS, sampleIdle);
  };
  if (idle !== undefined) sampleIdle();
  if (approve !== undefined) sweep();
  // Last, once both sockets listen (review N4): resume, reconcile and the first tick run in the background, so a port that hangs holds back
  // neither the start nor the signal handlers main() sets next; the hourly tick and the daily reconcile are armed now.
  const stopRotation = rotation?.run() ?? ((): void => undefined);
  let settleClosed: { resolve(): void; reject(error: unknown): void } | undefined;
  const closed = new Promise<void>((resolve, reject) => {
    settleClosed = { resolve, reject };
  });
  const closeStores = async (): Promise<void> => {
    await rotation?.idle();
    privateStore.close();
    parts.close();
  };
  const shutDown = async (): Promise<void> => {
    cancelSweep();
    cancelSettle();
    cancelIdle();
    idle?.stop();
    shares.stop();
    stopRotation();
    await Promise.all([server.stop(), lend.stop()]);
    // A failure to close is passed on through `closed`, never swallowed.
    void closeStores().then(
      () => settleClosed?.resolve(),
      (error: unknown) => settleClosed?.reject(error),
    );
  };
  let stopping: Promise<void> | undefined;
  return { routes, executorKinds: approve?.executorKinds ?? new Set(), stop: () => (stopping ??= shutDown()), closed };
}

async function main(): Promise<void> {
  const core = await startCore(process.env);
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => void core.stop().then(resolve);
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  });
  process.stdout.write('keybox core listening\n');
  await stopped;
}

if (import.meta.main) process.exitCode = await main().then(
  () => 0,
  (error: unknown) => {
    const why = error instanceof RegistryRefused ? `: ${error.message}` : osErrorCode(error) === undefined ? '' : ` (${osErrorCode(error)})`;
    process.stderr.write(`keybox core failed to start${why}\n`);
    return 1;
  },
);
