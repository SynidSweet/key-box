// The relay journey's two processes over the test profiles, built from the real modules: `core <stateDir> <lendSocket>` runs
// core's lend side, `relay <relaySocket> <lendSocket> <upstreamPort>` runs kb-relay with the egress gate's loopback connector
// (the platform units supply real profiles; until then main-relay.ts has none to relay through). Run with no arguments (as
// `node --test` does to every file under test/) it does nothing.
import { systemClock, systemScheduler } from '../../src/shell/clock.ts';
import { openCore } from '../../src/shell/core.ts';
import { createEgress } from '../../src/shell/egress.ts';
import { createLendHandler, loadCredentialShapes } from '../../src/shell/lend-core.ts';
import { createMintedValues } from '../../src/shell/minted-values.ts';
import { createLendClient, createLendServer } from '../../src/shell/lend-socket.ts';
import { systemRandom } from '../../src/shell/random.ts';
import { adapterHostsOf, createRelayServer } from '../../src/shell/relay-http.ts';
import { TEST_REGISTRY } from '../fixtures/profiles.ts';
import { loopbackConnector } from '../support/loopback-connector.ts';

const [role, first, lendSocket, port] = process.argv.slice(2);
const journal = (code: string): void => void process.stderr.write(`${role ?? ''}: ${code}\n`);

/** Says it is listening, and runs `stop` on SIGTERM. */
const serveUntilTerm = (stop: () => Promise<void>): void => {
  process.stdout.write('listening\n');
  process.once('SIGTERM', () => void stop());
};

if (role === 'core' && first !== undefined && lendSocket !== undefined) {
  process.umask(0o007);
  const core = openCore({ stateDir: first, clock: systemClock, scheduler: systemScheduler, random: systemRandom });
  const handler = createLendHandler({ meta: core.meta, tokens: core.meta, vault: core.vault, audit: core.audit, events: core.events, registry: TEST_REGISTRY, shapes: loadCredentialShapes(), clock: systemClock, minted: createMintedValues(systemClock), journal });
  const server = createLendServer(handler, journal);
  await server.listen(lendSocket);
  serveUntilTerm(async () => {
    await server.stop();
    core.close();
  });
} else if (role === 'relay' && first !== undefined && lendSocket !== undefined && port !== undefined) {
  process.umask(0o007);
  const egress = createEgress({ adapterHosts: adapterHostsOf(TEST_REGISTRY), listed: [], resolver: { resolve: () => Promise.resolve(['203.0.113.10']) }, connector: loopbackConnector(Number(port)), scheduler: systemScheduler });
  const server = createRelayServer({ registry: TEST_REGISTRY, lend: createLendClient(lendSocket), egress, domain: 'box.example', journal });
  await server.listen(first);
  serveUntilTerm(() => server.stop());
}
