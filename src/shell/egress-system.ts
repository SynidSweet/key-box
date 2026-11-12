// KBOX-47: the egress gate as both processes run it: the registry's hosts, `deploy/egress-hosts.json` for the other
// callers, DNS and TLS offering only HTTP/1.1. A list that does not parse stops the start, so a bad list never means "allow".
import { readFileSync } from 'node:fs';
import type { PlatformEntry } from '../ports/platform.ts';
import { parseEgressHosts } from '../pure/egress-policy.ts';
import { registryHostsOf } from '../pure/registry-entry.ts';
import { systemScheduler } from './clock.ts';
import { createEgress, createTlsConnector, systemResolver } from './egress.ts';
import type { Egress } from './egress.ts';
import { adapterHostsOf } from './relay-http.ts';

export function createSystemEgress(registry: readonly PlatformEntry[]): Egress {
  const listed = parseEgressHosts(JSON.parse(readFileSync(new URL('../../deploy/egress-hosts.json', import.meta.url), 'utf8')) as unknown);
  if (!listed.ok) throw new RangeError('deploy/egress-hosts.json does not parse');
  return createEgress({
    adapterHosts: adapterHostsOf(registry),
    registryHosts: registryHostsOf(registry),
    listed: listed.value,
    resolver: systemResolver,
    connector: createTlsConnector(),
    scheduler: systemScheduler,
  });
}

/**
 * The system gate, built on first use from the registry as it stands then. Core needs it before the registry exists: the adapters' HTTP
 * client holds the gate and the registry holds the client.
 */
export function createLazyEgress(registry: () => readonly PlatformEntry[]): Egress {
  let gate: Egress | undefined;
  const get = (): Egress => (gate ??= createSystemEgress(registry()));
  return { open: (caller, url, signal) => get().open(caller, url, signal) };
}
