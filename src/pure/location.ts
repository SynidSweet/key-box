// KBOX-57: a key's location is checked against the fields its registry entry declares, once, wherever it enters or is used: the proposal,
// a settling paste, the start of a run and the schedule's due check. Placement has one source: a scope item that names a declared field is
// refused, so no second place can say where a key lives. Pure.
import type { KeyClass, KeyLocation, LocationField, LocationSchema } from '../ports/types.ts';

export type LocationRefusal = 'location_field_unknown' | 'location_bad_value' | 'location_missing' | 'location_in_scope';

const FIELDS: readonly LocationField[] = ['region', 'project'];

/** The whole value matches the pattern, whether or not the pattern is anchored (and whatever state a `g` or `y` flag would keep). */
const fullMatch = (pattern: RegExp, value: string): boolean => new RegExp(`^(?:${pattern.source})$`, pattern.flags.replace(/[gy]/g, '')).test(value);

/** Every field the location names, as a list: undefined members are no field. */
const named = (at: KeyLocation): readonly LocationField[] => FIELDS.filter((f) => at[f] !== undefined);

/**
 * `ok`, or why the entry refuses this location for a key of this class with these scope items: a field the entry does not declare, a value
 * its pattern refuses, a field the class must name and the location lacks, or a `region:`/`project:` scope item for a declared field.
 */
export function checkLocation(schema: LocationSchema | undefined, at: KeyLocation, klass: KeyClass, scopeItems: readonly string[]): 'ok' | LocationRefusal {
  const declared = schema ?? {};
  for (const field of named(at)) {
    const rule = declared[field];
    const value = at[field];
    if (rule === undefined) return 'location_field_unknown';
    if (value === undefined || !fullMatch(rule.pattern, value)) return 'location_bad_value';
  }
  for (const field of FIELDS) {
    if (declared[field]?.requiredFor.includes(klass) === true && at[field] === undefined) return 'location_missing';
  }
  const placementItem = (item: string): boolean => FIELDS.some((f) => declared[f] !== undefined && item.startsWith(`${f}:`));
  return scopeItems.some(placementItem) ? 'location_in_scope' : 'ok';
}

/** The platform's answer and the stored location name the same place: equal over the fields either names (a field on one side only differs). */
export const sameLocation = (a: KeyLocation, b: KeyLocation): boolean => FIELDS.every((f) => a[f] === b[f]);
