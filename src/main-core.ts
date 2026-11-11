// The core process: opens the state directory, serves the machine API and, once the box's domain is configured, the phone
// app and its approvals on one unix socket; stops on SIGTERM. Later units add their routes, ports and executors here. This is
// the only file besides the private-db adapter that names private.db.
import { mkdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { DOMAIN_NAME } from './pure/actions.ts';
import type { Action } from './pure/actions.ts';
import { parseWordlist } from './pure/codes.ts';
import { osErrorCode } from './pure/errors.ts';
import { decodeJsonBody } from './pure/schemas.ts';
import { openApproveCore } from './shell/approve-core.ts';
import { systemClock, systemScheduler } from './shell/clock.ts';
import { openCore } from './shell/core.ts';
import { createApiServer } from './shell/http.ts';
import type { Route } from './shell/http.ts';
import { createIdleWatch } from './shell/idle-watch.ts';
import type { IdleWatch } from './shell/idle-watch.ts';
import { createShareWriter, shareRoute } from './shell/share-writer.ts';
import { createMetaShareSource } from './shell/share-source.ts';
import { createPush } from './shell/push.ts';
import { createHttpPushTransport } from './shell/push-transport.ts';
import { openPrivateDatabase } from './shell/private-db.ts';
import { systemRandom } from './shell/random.ts';
import { createTrustInstaller } from './shell/trust-installer.ts';
import { createUpdater } from './shell/updater.ts';

interface Config {
  readonly stateDir: string;
  readonly socket: string;
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
  const domain = env['KB_DOMAIN'];
  const staging = join(stateDir, 'staging');
  const installResults = env['KB_INSTALL_RESULTS'] ?? '/var/lib/keybox-install';
  const current = env['KB_CURRENT'] ?? '/opt/keybox/current';
  if (![stateDir, socket, installResults, current].every((p) => isAbsolute(p))) throw new RangeError('KB_STATE_DIR, KB_SOCKET, KB_INSTALL_RESULTS and KB_CURRENT are absolute paths');
  if (domain !== undefined && !DOMAIN_NAME.test(domain)) throw new RangeError('KB_DOMAIN is a lower-case domain name');
  return { stateDir, socket, domain, staging, installResults, current };
}

/** The kinds whose proposal check needs a platform adapter's profile; with none registered they are refused. */
const NEEDS_ADAPTER: ReadonlySet<Action['kind']> = new Set(['add_key', 'add_destination', 'set_allow_rules', 'vercel_set_domain', 'vercel_set_team_setting']);
const vetWithoutAdapters = (action: Action): 'ok' | 'rejected' => (NEEDS_ADAPTER.has(action.kind) ? 'rejected' : 'ok');

/** No platform adapter registers its key shape yet, so no admin or master key is watched; each adapter unit adds its `shape` here. */
const noShapeYet = (): undefined => undefined;

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

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const journal = (code: string): void => void process.stderr.write(`keybox core: ${code}\n`);
  const parts = openCore({ stateDir: config.stateDir, clock: systemClock, scheduler: systemScheduler, random: systemRandom });
  const privateStore = openPrivateDatabase(join(config.stateDir, 'private.db'));
  let approve: ReturnType<typeof openApproveCore> | undefined;
  let idle: IdleWatch | undefined;
  const wait = (ms: number): Promise<void> => new Promise((resolve) => void systemScheduler.after(ms, resolve));
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
    const trust = createTrustInstaller({ stagingDir: config.staging, resultsDir: config.installResults, random: systemRandom, clock: systemClock, wait });
    const push = createPush({ store: privateStore, transport: createHttpPushTransport(), scheduler: systemScheduler, clock: systemClock, random: systemRandom, audit: parts.audit, subject: `https://keys.${config.domain}` });
    const wordlist = parseWordlist(readFileSync(new URL('./data/wordlist.txt', import.meta.url), 'utf8'));
    idle = createIdleWatch({ files: { stat: '/proc/stat', meminfo: '/proc/meminfo', netdev: '/proc/net/dev' }, clock: systemClock, push, linkMbps: linkMbps(), notifier: { notice: journal } });
    approve = openApproveCore({ parts, approverStore: privateStore, trust, push, clock: systemClock, random: systemRandom, domain: config.domain, wordlist, vet: vetWithoutAdapters, executors: { install_update: updater.executor }, updateChanges: (action) => updater.changes(action) });
  }
  const shares = createShareWriter({
    dir: join(config.stateDir, 'share'),
    meta: parts.meta,
    signingKey: parts.share.signingKey,
    source: createMetaShareSource({ meta: parts.meta, values: parts.share.values, shapeOf: noShapeYet }),
    events: parts.events,
    hub: parts.hub,
    clock: systemClock,
    scheduler: systemScheduler,
    random: systemRandom,
    audit: parts.audit,
  });
  // A first file that cannot be written does not stop the box: the file is served as stale (503) until the next key.changed makes one.
  await shares.start().catch(() => parts.audit.append({ action: 'share.refresh_failed', subject: 'share', at: systemClock.now(), detail: { code: 'start_failed' } }));
  const server = createApiServer({
    routes: [...coreRoutes(parts.routes, approve?.routes ?? [], approve === undefined || running === undefined ? [] : updater.routes), shareRoute(shares)],
    tokens: approve?.tokens.tokenStore ?? parts.meta,
    audit: parts.audit,
    random: systemRandom,
    clock: systemClock,
    journal,
  });
  await server.listen(config.socket);
  let cancelSweep = (): void => undefined;
  const sweep = (): void => {
    approve?.approvals.sweep();
    cancelSweep = systemScheduler.after(SWEEP_EVERY_MS, sweep);
  };
  let cancelSettle = (): void => undefined;
  const settle = (): void => {
    updater.settle();
    cancelSettle = systemScheduler.after(SETTLE_EVERY_MS, settle);
  };
  if (approve !== undefined) settle();
  let cancelIdle = (): void => undefined;
  const sampleIdle = (): void => {
    idle?.sample();
    cancelIdle = systemScheduler.after(IDLE_SAMPLE_EVERY_MS, sampleIdle);
  };
  if (idle !== undefined) sampleIdle();
  if (approve !== undefined) sweep();
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => {
      cancelSweep();
      cancelSettle();
      cancelIdle();
      idle?.stop();
      shares.stop();
      void server.stop().then(() => {
        privateStore.close();
        parts.close();
        resolve();
      });
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  });
  process.stdout.write('keybox core listening\n');
  await stopped;
}

if (import.meta.main) process.exitCode = await main().then(
  () => 0,
  (error: unknown) => {
    process.stderr.write(`keybox core failed to start${osErrorCode(error) === undefined ? '' : ` (${osErrorCode(error)})`}\n`);
    return 1;
  },
);
