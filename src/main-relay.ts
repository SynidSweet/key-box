// The relay process (kb-relay, uid keyrelay): serves /r/* on its own unix socket behind Caddy, asks core for every pass,
// grant, lent value, scan and audit row over the lend socket, and reaches upstream only through the egress gate. It holds
// no state and reads no vault; it stops on SIGTERM (KBOX-3, KBOX-13, KBOX-45, KBOX-47).
import { isAbsolute } from 'node:path';
import { createRelayRegistry } from './platforms/registry.ts';
import { DOMAIN_NAME } from './pure/actions.ts';
import { osErrorCode } from './pure/errors.ts';
import { RegistryRefused } from './pure/profile.ts';
import { createSystemEgress } from './shell/egress-system.ts';
import { systemClock } from './shell/clock.ts';
import { createLendClient } from './shell/lend-socket.ts';
import { createRelayServer } from './shell/relay-http.ts';

interface Config {
  readonly socket: string;
  readonly lendSocket: string;
  /** The box's domain, for the relay URLs /r/_/grants hands out. Absent until the bootstrap configures it. */
  readonly domain: string | undefined;
}

/** The environment is parsed once, here; the rest of the process takes the typed value. */
function readConfig(env: NodeJS.ProcessEnv): Config {
  const socket = env['KB_RELAY_SOCKET'] ?? '/run/keyrelay/http.sock';
  const lendSocket = env['KB_LEND_SOCKET'] ?? '/run/keybox-lend/lend.sock';
  const domain = env['KB_DOMAIN'];
  if (!isAbsolute(socket) || !isAbsolute(lendSocket)) throw new RangeError('KB_RELAY_SOCKET and KB_LEND_SOCKET are absolute paths');
  if (domain !== undefined && !DOMAIN_NAME.test(domain)) throw new RangeError('KB_DOMAIN is a lower-case domain name');
  return { socket, lendSocket, domain };
}

async function main(): Promise<void> {
  const config = readConfig(process.env);
  const journal = (code: string): void => void process.stderr.write(`keybox relay: ${code}\n`);
  const registry = createRelayRegistry(systemClock);
  const egress = createSystemEgress(registry);
  const server = createRelayServer({ registry, lend: createLendClient(config.lendSocket), egress, domain: config.domain, journal });
  if (config.domain === undefined) journal('no_domain');
  await server.listen(config.socket);
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => void server.stop().then(resolve);
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  });
  process.stdout.write('keybox relay listening\n');
  await stopped;
}

process.exitCode = await main().then(
  () => 0,
  (error: unknown) => {
    const why = error instanceof RegistryRefused ? `: ${error.message}` : osErrorCode(error) === undefined ? '' : ` (${osErrorCode(error)})`;
    process.stderr.write(`keybox relay failed to start${why}\n`);
    return 1;
  },
);
