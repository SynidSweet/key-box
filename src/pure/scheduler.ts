// KBOX-52: when a key is due. Pure: time comes in as a number. A schedule, not a cap: staggering only moves admin and master
// rotations EARLIER, one to a day, and a manual "replace now" is never held back.
import type { KeyClass } from '../ports/types.ts';

const HOUR_MS = 3600_000;
const DAY_MS = 24 * HOUR_MS;

export interface SchedKey {
  readonly keyref: string;
  readonly class: KeyClass;
  readonly rotateEveryDays: number;
  readonly graceHours: number;
  /** When the current generation became current (or was created). */
  readonly lastRotatedAt: number;
  /** The platform's own expiry of the current key, when it has one. */
  readonly expiresAt: number | null;
  /** The owner or an agent asked for a replacement now. */
  readonly manual: boolean;
}

/** The earlier of the schedule and `expiresAt - grace - 1 day`. */
export function unstaggeredDue(key: SchedKey): number {
  const scheduled = key.lastRotatedAt + key.rotateEveryDays * DAY_MS;
  if (key.expiresAt === null) return scheduled;
  return Math.min(scheduled, key.expiresAt - key.graceHours * HOUR_MS - DAY_MS);
}

/**
 * The due date of every key. Admin and master keys are taken from the latest due date backwards, and each is moved whole days
 * earlier until no other admin or master key is due on its day, so every due date is no later than the unstaggered one.
 * A manual rotation is due at `now`.
 */
export function dueDates(keys: readonly SchedKey[], now = 0): ReadonlyMap<string, number> {
  const due = new Map<string, number>();
  const privileged: { readonly keyref: string; readonly at: number }[] = [];
  for (const key of keys) {
    if (key.manual) due.set(key.keyref, now);
    else if (key.class === 'ordinary') due.set(key.keyref, unstaggeredDue(key));
    else privileged.push({ keyref: key.keyref, at: unstaggeredDue(key) });
  }
  privileged.sort((a, b) => b.at - a.at || (a.keyref < b.keyref ? -1 : a.keyref > b.keyref ? 1 : 0));
  let earliestFreeDay = Number.POSITIVE_INFINITY;
  for (const { keyref, at } of privileged) {
    const wanted = Math.floor(at / DAY_MS);
    const day = Math.min(wanted, earliestFreeDay - 1);
    due.set(keyref, at - (wanted - day) * DAY_MS);
    earliestFreeDay = day;
  }
  return due;
}
