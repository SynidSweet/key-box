// KBOX-47: what the egress gate allows. A host is allowed when a registered adapter declares it (for relay and adapter calls)
// or deploy/egress-hosts.json names it for exactly that caller; an address is refused when it is private, loopback,
// link-local, unspecified, shared, multicast or reserved, including an IPv4 address inside IPv6.
import { parseIpv4, parseIpv6 } from './address.ts';
import { hostAllowed } from './pushsub.ts';
import type { Parsed } from './schemas.ts';

/** Who makes the call. Adapter hosts serve `relay` and `adapter`; each listed host serves the one caller it names. */
export type Caller = 'relay' | 'adapter' | 'push' | 'update';
export type ListedCaller = 'push' | 'update';

export interface EgressHost {
  /** A host name, or `*.` and a domain for any name below it. */
  readonly host: string;
  readonly purpose: string;
  readonly caller: ListedCaller;
}

export type HostVerdict = 'allowed' | 'undeclared_host' | 'wrong_caller';

/**
 * `adapterHosts` are the relay profiles' hosts (relay and adapter calls); `registryHosts` are the hosts of the registry entries' own
 * calls (adapter calls only).
 */
export function hostVerdict(caller: Caller, host: string, adapterHosts: readonly string[], listed: readonly EgressHost[], registryHosts: readonly string[] = []): HostVerdict {
  const adapter = adapterHosts.includes(host);
  const own = registryHosts.includes(host);
  const entries = listed.filter((e) => hostAllowed(host, [e.host]));
  if (!adapter && !own && entries.length === 0) return 'undeclared_host';
  if (caller === 'relay') return adapter ? 'allowed' : 'wrong_caller';
  if (caller === 'adapter') return adapter || own ? 'allowed' : 'wrong_caller';
  return entries.some((e) => e.caller === caller) ? 'allowed' : 'wrong_caller';
}

const inV4 = (o: readonly number[], net: readonly [number, number, number, number], bits: number): boolean => {
  const value = (a: readonly number[]): number => (((a[0] ?? 0) << 24) | ((a[1] ?? 0) << 16) | ((a[2] ?? 0) << 8) | (a[3] ?? 0)) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value(o) & mask) >>> 0 === (value(net) & mask) >>> 0;
};

const V4_REFUSED: readonly (readonly [readonly [number, number, number, number], number])[] = [
  [[0, 0, 0, 0], 8], // this network, unspecified
  [[10, 0, 0, 0], 8],
  [[100, 64, 0, 0], 10], // shared address space
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16], // link-local, the metadata address included
  [[172, 16, 0, 0], 12],
  [[192, 0, 0, 0], 24],
  [[192, 168, 0, 0], 16],
  [[198, 18, 0, 0], 15],
  [[224, 0, 0, 0], 4], // multicast
  [[240, 0, 0, 0], 4], // reserved and broadcast
];

const v4Refused = (octets: readonly number[]): boolean => V4_REFUSED.some(([net, bits]) => inV4(octets, net, bits));

const embeddedV4 = (g: readonly number[]): number[] => [(g[6] ?? 0) >> 8, (g[6] ?? 0) & 0xff, (g[7] ?? 0) >> 8, (g[7] ?? 0) & 0xff];

function v6Refused(g: readonly number[]): boolean {
  const first = g[0] ?? 0;
  const zeroTo = (n: number): boolean => g.slice(0, n).every((x) => x === 0);
  if (zeroTo(5) && g[5] === 0xffff) return v4Refused(embeddedV4(g)); // IPv4-mapped
  if (zeroTo(6)) return true; // unspecified, loopback and the old IPv4-compatible form
  if (first === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4Refused(embeddedV4(g)); // NAT64
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00;
}

/** True for every address the box must never connect to; an address that does not parse is refused too. */
export function addressRefused(address: string): boolean {
  const v4 = parseIpv4(address);
  if (v4 !== undefined) return v4Refused(v4);
  const v6 = parseIpv6(address);
  return v6 === undefined || v6Refused(v6);
}

const HOST = /^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** deploy/egress-hosts.json: `{hosts: [{host, purpose, caller}]}`, closed. */
export function parseEgressHosts(raw: unknown): Parsed<readonly EgressHost[]> {
  const refused = { ok: false } as const;
  if (!isRecord(raw) || Object.keys(raw).some((k) => k !== 'hosts') || !Array.isArray(raw['hosts'])) return refused;
  const hosts: EgressHost[] = [];
  for (const entry of raw['hosts'] as unknown[]) {
    if (!isRecord(entry) || Object.keys(entry).some((k) => !['host', 'purpose', 'caller'].includes(k))) return refused;
    const { host, purpose, caller } = entry;
    if (typeof host !== 'string' || !HOST.test(host) || typeof purpose !== 'string' || purpose.length === 0 || (caller !== 'push' && caller !== 'update')) return refused;
    hosts.push({ host, purpose, caller });
  }
  return { ok: true, value: hosts };
}
