// The core process, frame only: opens the state directory, serves the machine API on one unix socket, stops on SIGTERM.
// Later units add their routes and ports here. This is the only file besides the private-db adapter that names private.db.
import { isAbsolute, join } from 'node:path';
import { osErrorCode } from './pure/errors.ts';
import { systemClock, systemScheduler } from './shell/clock.ts';
import { openCore } from './shell/core.ts';
import { createApiServer } from './shell/http.ts';
import { openPrivateDatabase } from './shell/private-db.ts';
import { systemRandom } from './shell/random.ts';

interface Config {
  readonly stateDir: string;
  readonly socket: string;
}

/** The environment is parsed once, here; the rest of the process takes the typed value. */
function readConfig(env: NodeJS.ProcessEnv): Config {
  const stateDir = env['KB_STATE_DIR'] ?? '/var/lib/keybox';
  const socket = env['KB_SOCKET'] ?? '/run/keybox/http.sock';
  if (!isAbsolute(stateDir) || !isAbsolute(socket)) throw new RangeError('KB_STATE_DIR and KB_SOCKET are absolute paths');
  return { stateDir, socket };
}

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const parts = openCore({ stateDir: config.stateDir, clock: systemClock, scheduler: systemScheduler, random: systemRandom });
  const privateStore = openPrivateDatabase(join(config.stateDir, 'private.db'));
  const server = createApiServer({
    routes: parts.routes,
    tokens: parts.meta,
    audit: parts.audit,
    random: systemRandom,
    clock: systemClock,
    journal: (code) => void process.stderr.write(`keybox core: ${code}\n`),
  });
  await server.listen(config.socket);
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => {
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
