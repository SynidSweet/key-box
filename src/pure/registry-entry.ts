// KBOX-23: the registry checks that concern an entry as a whole rather than its relay profile.
import type { PlatformEntry } from '../ports/platform.ts';

export type EntryFailure = 'shape_twice' | 'shape_missing' | 'classify_twice' | 'classify_missing' | 'destination_twice' | 'bad_host';

/** One source of a shape and one of a class: an entry with an issuer takes each from the issuer, one without states them (KBOX-40). */
export function checkShapeSource(entry: PlatformEntry): EntryFailure | undefined {
  if (entry.issuer !== undefined) {
    if (entry.shape !== undefined) return 'shape_twice';
    return entry.classify === undefined ? undefined : 'classify_twice';
  }
  if (entry.shape === undefined) return 'shape_missing';
  return entry.classify === undefined ? 'classify_missing' : undefined;
}

/** A destination kind is provided by at most one entry, and once within an entry; returns the first platform that repeats one. */
export function checkDestinationKinds(entries: readonly PlatformEntry[]): { readonly code: EntryFailure; readonly platform: string } | undefined {
  const seen = new Set<string>();
  for (const entry of entries) {
    for (const kit of entry.destinations ?? []) {
      if (seen.has(kit.destination.kind)) return { code: 'destination_twice', platform: entry.id };
      seen.add(kit.destination.kind);
    }
  }
  return undefined;
}

const EXACT_HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

/** A host an adapter's own calls reach: an exact lower-case DNS name, no wildcard, port, path or address literal (KBOX-23, KBOX-47). */
export const isExactHost = (host: string): boolean => host.length <= 253 && EXACT_HOST.test(host);

export const checkHosts = (entry: PlatformEntry): 'bad_host' | undefined => ((entry.hosts ?? []).every(isExactHost) ? undefined : 'bad_host');

/** Every host the entries' own adapter calls reach (the egress gate's list for caller `adapter`). */
export const registryHostsOf = (entries: readonly PlatformEntry[]): string[] => entries.flatMap((e) => [...(e.hosts ?? [])]);
