// The core process: opens the state directory, serves the machine API and, once the box's domain is configured, the phone
// app and its approvals on one unix socket; stops on SIGTERM. Later units add their routes, ports and executors here. This is
// the only file besides the private-db adapter that names private.db.
import { mkdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import type { AuditEvent } from './ports/audit.ts';
import type { Clock, Scheduler } from './ports/clock.ts';
import type { BoxIdentity, PlatformEntry, RegistryDeps, StoredKey } from './ports/platform.ts';
import type { Random } from './ports/random.ts';
import { DOMAIN_NAME } from './pure/actions.ts';
import type { Action, ActionKind } from './pure/actions.ts';
import { parseWordlist } from './pure/codes.ts';
import { RegistryRefused, assertRegistry } from './pure/profile.ts';
import { shapeOfKey } from './pure/platform-shape.ts';
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
import { readKeyInfo } from './shell/rotation-store.ts';
import { kindOfStored, kitFor } from './shell/rotation-ports.ts';
import type { Rotation } from './shell/rotation.ts';
import type { PlatformSource } from './shell/rotation-ports.ts';
import { createGrantChecks } from './shell/grant-checks.ts';
import type { GrantChecks } from './shell/grant-checks.ts';
import { identityRoutes } from './shell/identity-routes.ts';
import { ensureBoxKeys } from './shell/box-keys.ts';

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
  /**
   * KBOX-41: the audience of the box's own OIDC assertions (for Google, the workload identity provider the owner made in the setup). With
   * the domain it is the box's identity; absent, every mint refuses, so a grant check refuses every grant it applies to (fail closed).
   */
  readonly oidcAudience: string | undefined;
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
  const oidcAudience = env['KB_OIDC_AUDIENCE'];
  if (oidcAudience !== undefined && !/^[\x21-\x7e]{1,255}$/.test(oidcAudience)) throw new RangeError('KB_OIDC_AUDIENCE is printable ASCII without spaces');
  return { stateDir, socket, lendSocket, domain, staging, installResults, current, oidcAudience };
}

const SWEEP_EVERY_MS = 60 * 60_000;
/** How often core looks for root's answer to an install it waits for. */
const SETTLE_EVERY_MS = 5_000;
/** How often core samples /proc for the idle watch (KBOX-21). */
const IDLE_SAMPLE_EVERY_MS = 10 * 60_000;
/** How often granted keys are checked again (KBOX-24: daily). */
const GRANT_CHECK_EVERY_MS = 24 * 3600_000;

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
  /**
   * The platform registry the box runs with; production builds it with `createRegistry` over core's deps (client, clock, identity, minted sink,
   * stored-record reader). A test passes its own list, or a builder that is handed core's deps.
   */
  readonly registry?: readonly PlatformEntry[] | ((deps: RegistryDeps) => readonly PlatformEntry[]);
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
  // Platform adapters register the short-lived values they mint here, so the scanner holds them while they live (KBOX-14).
  const minted = createMintedValues(clock);
  const identity: BoxIdentity | undefined = config.domain === undefined || config.oidcAudience === undefined ? undefined : { issuer: `https://keys.${config.domain}`, audience: config.oidcAudience };
  // The stored-record reader the registry is handed answers nothing until the store is open below, so an early mint fails closed.
  let storedOf: ((keyref: string) => StoredKey | undefined) | undefined;
  const registryDeps: RegistryDeps = { http: createAdapterHttp({ egress, scheduler }), clock, minted, keyInfo: (keyref) => storedOf?.(keyref), ...(identity === undefined ? {} : { identity }) };
  const registry = typeof runtime.registry === 'function' ? runtime.registry(registryDeps) : (runtime.registry ?? createRegistry(registryDeps));
  assertRegistry(registry);
  const parts = openCore({ stateDir: config.stateDir, clock, scheduler, random, journal });
  const storedRecord = (keyref: string): StoredKey | undefined => readKeyInfo(parts.db, keyref);
  storedOf = storedRecord;
  const privateStore = openPrivateDatabase(join(config.stateDir, 'private.db'), journal);
  // The registry's view for each stored key (KBOX-55: the box-made key's kit is its own): the share file reads it; rotation is handed the
  // runtime's source when a test passes one.
  const registrySource = createPlatformSource({ registry, meta: parts.meta, vault: parts.vault, keyInfo: storedRecord });
  let approve: ReturnType<typeof openApproveCore> | undefined;
  let idle: IdleWatch | undefined;
  let rotation: Rotation | undefined;
  let grantChecks: GrantChecks | undefined;
  let identityPages: readonly Route[] = [];
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
    const source = runtime.platforms ?? registrySource;
    const checks = createGrantChecks({ registry, meta: parts.meta, keyInfo: storedRecord, master: (platform, at, items) => source.master(platform, at, items), audit: parts.audit, events: parts.events, clock });
    grantChecks = checks;
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
      precheck: (action) => checks.atProposal(action),
    });
    const opened = openRotation({ parts, approvals: approve.approvals, approvers: approve.approvers, push, clock, scheduler, random, audit: parts.audit, source });
    rotation = opened;
    // KBOX-41, KBOX-55: with the box's identity (domain and audience), its own signing key is made once, before anything is served, and its
    // documents are served; the JWKS reads the key's generations by status. Without it there is no key and nothing to publish.
    if (identity !== undefined) {
      ensureBoxKeys({ registry, meta: parts.meta, vault: parts.vault, store: opened.store, random, clock, audit: parts.audit });
      identityPages = identityRoutes({ registry, source: registrySource, meta: parts.meta, vault: parts.vault, generations: (keyref) => opened.store.gens(keyref), issuer: identity.issuer });
    }
  }
  const rotationStore = rotation?.store;
  const shares = createShareWriter({
    dir: join(config.stateDir, 'share'),
    meta: parts.meta,
    signingKey: parts.share.signingKey,
    source: createMetaShareSource({
      meta: parts.meta,
      values: parts.share.values,
      shapeOf: (platform, keyref) => shapeOfKey(kitFor(registrySource, { platform, keyref }), kindOfStored(readKeyInfo(parts.db, keyref))),
      boxMade: (platform, keyref) => kitFor(registrySource, { platform, keyref })?.boxKey !== undefined,
      ...(rotationStore === undefined ? {} : { generations: (keyref: string) => rotationStore.gens(keyref) }),
    }),
    events: parts.events,
    hub: parts.hub,
    clock,
    scheduler,
    random,
    audit: parts.audit,
  });
  // A first file that cannot be written does not stop the box: the file is served as stale (503) until the next key.changed makes one.
  await shares.start().catch(() => parts.audit.append({ action: 'share.refresh_failed', subject: 'share', at: clock.now(), detail: { code: 'start_failed' } }));
  const routes = [...coreRoutes(parts.routes, approve?.routes ?? [], approve === undefined || running === undefined ? [] : updater.routes), shareRoute(shares), ...(rotation?.routes ?? []), ...identityPages];
  const server = createApiServer({
    routes,
    tokens: approve?.tokens.tokenStore ?? parts.meta,
    audit: parts.audit,
    random,
    clock,
    journal,
  });
  await server.listen(config.socket);
  const lend = createLendServer(
    createLendHandler({ meta: parts.meta, tokens: approve?.tokens.tokenStore ?? parts.meta, vault: parts.vault, audit: parts.audit, events: parts.events, registry, shapes: loadCredentialShapes(), clock, minted, journal, locationOf: (keyref) => readKeyInfo(parts.db, keyref)?.location }),
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
  // KBOX-24: granted keys are checked at start and then daily. Like every timed job the next run is armed before the work, so a run that
  // throws (audited) never stops the schedule; the run in flight is waited for before the stores close.
  let cancelGrantCheck = (): void => undefined;
  let grantRun: Promise<void> = Promise.resolve();
  const checkGrants = (checks: GrantChecks): void => {
    cancelGrantCheck = scheduler.after(GRANT_CHECK_EVERY_MS, () => checkGrants(checks));
    grantRun = checks.daily().catch(() => failSafeAudit.append({ action: 'grants.check_failed', subject: 'grants', at: clock.now(), detail: { code: 'check_failed' } }));
  };
  if (grantChecks !== undefined) checkGrants(grantChecks);
  // Last, once both sockets listen (review N4): resume, reconcile and the first tick run in the background, so a port that hangs holds back
  // neither the start nor the signal handlers main() sets next; the hourly tick and the daily reconcile are armed now.
  const stopRotation = rotation?.run() ?? ((): void => undefined);
  let settleClosed: { resolve(): void; reject(error: unknown): void } | undefined;
  const closed = new Promise<void>((resolve, reject) => {
    settleClosed = { resolve, reject };
  });
  const closeStores = async (): Promise<void> => {
    await rotation?.idle();
    await grantRun;
    privateStore.close();
    parts.close();
  };
  const shutDown = async (): Promise<void> => {
    cancelSweep();
    cancelSettle();
    cancelIdle();
    cancelGrantCheck();
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
