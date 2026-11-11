// The core process: opens the state directory, serves the machine API and, once the box's domain is configured, the phone
// app and its approvals on one unix socket; stops on SIGTERM. Later units add their routes, ports and executors here. This is
// the only file besides the private-db adapter that names private.db.
import { readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import type { TrustPort } from './ports/trust.ts';
import { DOMAIN_NAME } from './pure/actions.ts';
import type { Action } from './pure/actions.ts';
import { parseWordlist } from './pure/codes.ts';
import { osErrorCode } from './pure/errors.ts';
import { openApproveCore } from './shell/approve-core.ts';
import { systemClock, systemScheduler } from './shell/clock.ts';
import { openCore } from './shell/core.ts';
import { createApiServer } from './shell/http.ts';
import { createShareWriter, shareRoute } from './shell/share-writer.ts';
import { createMetaShareSource } from './shell/share-source.ts';
import { createPush } from './shell/push.ts';
import { createHttpPushTransport } from './shell/push-transport.ts';
import { openPrivateDatabase } from './shell/private-db.ts';
import { systemRandom } from './shell/random.ts';

interface Config {
  readonly stateDir: string;
  readonly socket: string;
  /** The box's domain; the phone app lives on `keys.<domain>`. Absent until the bootstrap configures it. */
  readonly domain: string | undefined;
}

/** The environment is parsed once, here; the rest of the process takes the typed value. */
function readConfig(env: NodeJS.ProcessEnv): Config {
  const stateDir = env['KB_STATE_DIR'] ?? '/var/lib/keybox';
  const socket = env['KB_SOCKET'] ?? '/run/keybox/http.sock';
  const domain = env['KB_DOMAIN'];
  if (!isAbsolute(stateDir) || !isAbsolute(socket)) throw new RangeError('KB_STATE_DIR and KB_SOCKET are absolute paths');
  if (domain !== undefined && !DOMAIN_NAME.test(domain)) throw new RangeError('KB_DOMAIN is a lower-case domain name');
  return { stateDir, socket, domain };
}

/** Until the update unit wires kb-install, root answers no trust request: setup, recovery and approver changes cannot complete. */
const noInstaller: TrustPort = { apply: () => Promise.resolve({ result: 'refused', code: 'no_installer' }) };

/** The kinds whose proposal check needs a platform adapter's profile; with none registered they are refused. */
const NEEDS_ADAPTER: ReadonlySet<Action['kind']> = new Set(['add_key', 'add_destination', 'set_allow_rules', 'vercel_set_domain', 'vercel_set_team_setting']);
const vetWithoutAdapters = (action: Action): 'ok' | 'rejected' => (NEEDS_ADAPTER.has(action.kind) ? 'rejected' : 'ok');

/** No platform adapter registers its key shape yet, so no admin or master key is watched; each adapter unit adds its `shape` here. */
const noShapeYet = (): undefined => undefined;

const SWEEP_EVERY_MS = 60 * 60_000;

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const journal = (code: string): void => void process.stderr.write(`keybox core: ${code}\n`);
  const parts = openCore({ stateDir: config.stateDir, clock: systemClock, scheduler: systemScheduler, random: systemRandom });
  const privateStore = openPrivateDatabase(join(config.stateDir, 'private.db'));
  let approve: ReturnType<typeof openApproveCore> | undefined;
  if (config.domain === undefined) journal('no_domain');
  else {
    const push = createPush({ store: privateStore, transport: createHttpPushTransport(), scheduler: systemScheduler, clock: systemClock, random: systemRandom, audit: parts.audit, subject: `https://keys.${config.domain}` });
    const wordlist = parseWordlist(readFileSync(new URL('./data/wordlist.txt', import.meta.url), 'utf8'));
    approve = openApproveCore({ parts, approverStore: privateStore, trust: noInstaller, push, clock: systemClock, random: systemRandom, domain: config.domain, wordlist, vet: vetWithoutAdapters });
  }
  const shares = createShareWriter({
    dir: join(config.stateDir, 'share'),
    meta: parts.meta,
    vault: parts.vault,
    source: createMetaShareSource({ meta: parts.meta, vault: parts.vault, shapeOf: noShapeYet }),
    events: parts.events,
    hub: parts.hub,
    clock: systemClock,
    random: systemRandom,
    audit: parts.audit,
  });
  // A first file that cannot be written does not stop the box: the file is served as stale (503) until the next key.changed makes one.
  await shares.start().catch(() => parts.audit.append({ action: 'share.refresh_failed', subject: 'share', at: systemClock.now(), detail: { code: 'start_failed' } }));
  const server = createApiServer({
    routes: [...parts.routes, ...(approve?.routes ?? []), shareRoute(shares)],
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
  if (approve !== undefined) sweep();
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => {
      cancelSweep();
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

process.exitCode = await main().then(
  () => 0,
  (error: unknown) => {
    process.stderr.write(`keybox core failed to start${osErrorCode(error) === undefined ? '' : ` (${osErrorCode(error)})`}\n`);
    return 1;
  },
);
