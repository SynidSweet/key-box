// KBOX-23: the registry checks that concern an entry as a whole rather than its relay profile.
import type { PlatformEntry } from '../ports/platform.ts';

export type EntryFailure = 'shape_twice' | 'shape_missing' | 'destination_twice';

/** One source of a shape: an entry with an issuer takes it from the issuer, one without states it (KBOX-40). */
export function checkShapeSource(entry: PlatformEntry): EntryFailure | undefined {
  if (entry.issuer !== undefined) return entry.shape === undefined ? undefined : 'shape_twice';
  return entry.shape === undefined ? 'shape_missing' : undefined;
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
