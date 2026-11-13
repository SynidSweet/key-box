// KBOX-30, KBOX-31, KBOX-1: the control read routes: metadata, audit, events and the bootstrap facts. Scope `control` only.
import { readFileSync } from 'node:fs';
import type { AuditLog } from '../ports/audit.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import { ApiError } from '../pure/errors.ts';
import { int, optional, text } from '../pure/schemas.ts';
import type { EventPoller } from './events.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';

export interface ControlDeps {
  /** Where the bootstrap wrote what it looked at (KBOX-1); root's file, served read-only. */
  readonly bootstrapFactsPath: string;
  readonly meta: MetaStore;
  readonly audit: AuditLog;
  readonly events: EventLog;
  readonly poller: EventPoller;
}

/** The facts file's bytes, once checked to be JSON: a missing file is `not_found`, one that is not JSON is `unavailable`; any other read fault is the frame's 500. */
function bootstrapFacts(path: string): Uint8Array {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') throw new ApiError('not_found', 'no_bootstrap_facts');
    throw error;
  }
  try {
    JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new ApiError('unavailable', 'bootstrap_facts_unreadable');
  }
  return Uint8Array.from(bytes);
}

export function controlRoutes(deps: ControlDeps): Route[] {
  return [
    route({
      method: 'GET',
      path: '/api/bootstrap-facts',
      surface: 'api',
      scope: 'control',
      handle: () => ({ raw: { type: 'application/json; charset=utf-8', bytes: bootstrapFacts(deps.bootstrapFactsPath) } }),
    }),

    route({ method: 'GET', path: '/api/meta', surface: 'api', scope: 'control', handle: () => ({ json: deps.meta.controlSnapshot() }) }),

    route({
      method: 'GET',
      path: '/api/audit',
      surface: 'api',
      scope: 'control',
      query: { since: optional(int()), limit: optional(int(1)) },
      handle: ({ query }) => {
        const since = query.since ?? 0;
        const page = deps.audit.read(since, query.limit);
        const last = page.entries[page.entries.length - 1];
        return { json: { entries: page.entries, cursor: last?.seq ?? since, more: page.more } };
      },
    }),

    route({
      method: 'GET',
      path: '/api/events',
      surface: 'api',
      scope: 'control',
      query: { since: optional(int()), epoch: optional(text(/^[0-9a-f]{8}$/)) },
      handle: async ({ query, abort }) => {
        if (query.epoch !== undefined && query.epoch !== deps.meta.epoch()) throw new ApiError('conflict', 'epoch_changed');
        if (query.since !== undefined && query.since > deps.events.head()) throw new ApiError('bad_request');
        const answer = await deps.poller.wait(query.since, abort);
        return { json: { events: answer.events.map((e) => ({ seq: e.seq, at: e.at, kind: e.kind, data: e.data })), cursor: answer.cursor } };
      },
    }),
  ];
}
