// KBOX-30, KBOX-31: the control read routes: metadata, audit and events. Scope `control` only.
import type { AuditLog } from '../ports/audit.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import { ApiError } from '../pure/errors.ts';
import { int, optional, text } from '../pure/schemas.ts';
import type { EventPoller } from './events.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';

export interface ControlDeps {
  readonly meta: MetaStore;
  readonly audit: AuditLog;
  readonly events: EventLog;
  readonly poller: EventPoller;
}

export function controlRoutes(deps: ControlDeps): Route[] {
  return [
    route({ method: 'GET', path: '/api/meta', surface: 'api', scope: 'control', handle: () => ({ json: deps.meta.snapshot() }) }),

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
