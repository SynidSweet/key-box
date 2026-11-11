// KBOX-31: events are append-only rows in meta.db; a long poll holds a request until one arrives or the hold ends.
import type { DatabaseSync } from 'node:sqlite';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { EventLog, EventRow, EventSignal } from '../ports/events.ts';
import { ApiError, WriteRefused } from '../pure/errors.ts';
import { isEventKind, parseEventData } from '../pure/schemas.ts';
import type { EventData, EventKind } from '../pure/schemas.ts';

export function createEventHub(): EventSignal {
  const listeners = new Set<() => void>();
  return {
    notify(): void {
      for (const listener of [...listeners]) listener();
    },
    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
  };
}

/** Validates against the closed list and inserts one event row; the caller commits and then notifies. Returns the sequence number. */
export function insertEvent<K extends EventKind>(db: DatabaseSync, at: number, kind: K, data: EventData<K>): number {
  if (!isEventKind(kind)) throw new WriteRefused();
  const parsed = parseEventData(kind, data);
  if (!parsed.ok) throw new WriteRefused();
  const result = db.prepare('INSERT INTO events (at, kind, data_json) VALUES (?, ?, ?)').run(at, kind, JSON.stringify(parsed.value));
  return Number(result.lastInsertRowid);
}

interface StoredEvent {
  readonly seq: number;
  readonly at: number;
  readonly kind: string;
  readonly data_json: string;
}

export function createEventLog(db: DatabaseSync, clock: Clock, signal: EventSignal): EventLog {
  return {
    head(): number {
      return (db.prepare('SELECT coalesce(max(seq), 0) AS seq FROM events').get() as { seq: number }).seq;
    },
    after(since: number): readonly EventRow[] {
      const rows = db.prepare('SELECT seq, at, kind, data_json FROM events WHERE seq > ? ORDER BY seq').all(since) as unknown as StoredEvent[];
      return rows.map((r) => ({ seq: r.seq, at: r.at, kind: r.kind as EventKind, data: JSON.parse(r.data_json) as EventRow['data'] }));
    },
    append<K extends EventKind>(kind: K, data: EventData<K>): number {
      const seq = insertEvent(db, clock.now(), kind, data);
      signal.notify();
      return seq;
    },
  };
}

export interface PollAnswer {
  readonly events: readonly EventRow[];
  readonly cursor: number;
}

export interface EventPoller {
  /**
   * Events after `since` (the current head when omitted) at once if there are any; otherwise holds until the first
   * one arrives or `holdMs` pass, then answers an empty batch. An abort answers `unavailable`: never an empty batch.
   */
  wait(since: number | undefined, abort: AbortSignal): Promise<PollAnswer>;
}

export function createEventPoller(log: EventLog, signal: EventSignal, scheduler: Scheduler, holdMs: number): EventPoller {
  const answerFrom = (since: number): PollAnswer | undefined => {
    const events = log.after(since);
    const last = events[events.length - 1];
    return last === undefined ? undefined : { events, cursor: last.seq };
  };
  return {
    wait(since: number | undefined, abort: AbortSignal): Promise<PollAnswer> {
      if (abort.aborted) return Promise.reject(new ApiError('unavailable'));
      const start = since ?? log.head();
      const ready = answerFrom(start);
      if (ready !== undefined) return Promise.resolve(ready);
      return new Promise<PollAnswer>((resolve, reject) => {
        let finished = false;
        const finish = (settle: () => void): void => {
          if (finished) return;
          finished = true;
          unsubscribe();
          cancelTimer();
          abort.removeEventListener('abort', onAbort);
          settle();
        };
        const onAbort = (): void => finish(() => reject(new ApiError('unavailable')));
        const unsubscribe = signal.subscribe(() => {
          const arrived = answerFrom(start);
          if (arrived !== undefined) finish(() => resolve(arrived));
        });
        const cancelTimer = scheduler.after(holdMs, () => finish(() => resolve({ events: [], cursor: start })));
        abort.addEventListener('abort', onAbort, { once: true });
      });
    },
  };
}
