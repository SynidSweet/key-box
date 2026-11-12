// KBOX-47: the egress gate as both processes run it: the registry's hosts, `deploy/egress-hosts.json` for the other
// callers, DNS and TLS offering only HTTP/1.1. A list that does not parse stops the start, so a bad list never means "allow".
import { readFileSync } from 'node:fs';
import type { PlatformEntry } from '../ports/platform.ts';
import { parseEgressHosts } from '../pure/egress-policy.ts';
import type { EgressHost } from '../pure/egress-policy.ts';
import { registryHostsOf } from '../pure/registry-entry.ts';
import { systemScheduler } from './clock.ts';
import { createEgress, createTlsConnector, systemResolver } from './egress.ts';
import type { Egress } from './egress.ts';
import { adapterHostsOf } from './relay-http.ts';

const DEFAULT_HOSTS_FILE = new URL('../../deploy/egress-hosts.json', import.meta.url);

/** Reads and checks the closed host list; throws (`SyntaxError`, `RangeError`) when the file is not JSON or not the closed shape. Call it at the start. */
export function loadEgressHosts(file: URL = DEFAULT_HOSTS_FILE): readonly EgressHost[] {
  const listed = parseEgressHosts(JSON.parse(readFileSync(file, 'utf8')) as unknown);
  if (!listed.ok) throw new RangeError('deploy/egress-hosts.json does not parse');
  return listed.value;
}

export function createSystemEgress(registry: readonly PlatformEntry[], listed: readonly EgressHost[] = loadEgressHosts()): Egress {
  return createEgress({
    adapterHosts: adapterHostsOf(registry),
    registryHosts: registryHostsOf(registry),
    listed,
    resolver: systemResolver,
    connector: createTlsConnector(),
    scheduler: systemScheduler,
  });
}

/**
 * The system gate with its registry hosts bound on first use. Core needs it before the registry exists: the adapters' HTTP client holds the
 * gate and the registry holds the client. The host list is read by the caller, at the start; only the registry's hosts are bound late.
 */
export function createLazyEgress(registry: () => readonly PlatformEntry[], listed: readonly EgressHost[]): Egress {
  let gate: Egress | undefined;
  const get = (): Egress => (gate ??= createSystemEgress(registry(), listed));
  return { open: (caller, url, signal) => get().open(caller, url, signal) };
}
