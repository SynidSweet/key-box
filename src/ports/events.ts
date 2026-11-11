// KBOX-31: the append-only event log and the signal that tells waiting pollers it grew.
import type { EventData, EventKind } from '../pure/schemas.ts';

export interface EventRow {
  readonly seq: number;
  readonly at: number;
  readonly kind: EventKind;
  readonly data: Readonly<Record<string, string | number | boolean>>;
}

export interface EventLog {
  /** The sequence number of the newest event; 0 when there is none. */
  head(): number;
  /** Events with a sequence number above `since`, oldest first. */
  after(since: number): readonly EventRow[];
  /** Writes one event of the closed list and wakes the pollers; returns its sequence number. A refusal writes nothing and wakes no one. */
  append<K extends EventKind>(kind: K, data: EventData<K>): number;
}

/** Told after a commit that added events. */
export interface EventSignal {
  notify(): void;
  /** The returned function stops the listening. */
  subscribe(listener: () => void): () => void;
}
