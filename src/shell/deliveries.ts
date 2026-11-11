// KBOX-34: deliveries to the workstation. A box-issued ORDINARY key reaches the workstation through the one route that carries a value; a
// delivery stays available until it is acknowledged (retry-safe, identical bytes), and the delivery row keeps no value.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { Vault } from '../ports/vault.ts';
import { ApiError } from '../pure/errors.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';
import type { RotationStore } from './rotation-store.ts';

export interface DeliveryDeps {
  readonly store: RotationStore;
  readonly vault: Vault;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly clock: Clock;
}

const HOUR_MS = 3600_000;

export function deliveryRoutes(deps: DeliveryDeps): Route[] {
  const { store } = deps;
  return [
    route({
      method: 'GET',
      path: '/api/deliveries',
      surface: 'api',
      scope: 'control',
      handle: () => ({
        json: { deliveries: store.deliveries().filter((d) => d.ackedAt === null).map((d) => ({ delivery_id: d.deliveryId, keyref: d.keyref, project: d.project, name: d.name, gen: d.gen })) },
      }),
    }),

    route({
      method: 'GET',
      path: '/api/deliveries/:id/value',
      surface: 'api',
      scope: 'control',
      handle: async ({ params }) => {
        const delivery = store.delivery(params['id'] ?? '');
        if (delivery === undefined) throw new ApiError('not_found');
        if (store.key(delivery.keyref)?.class !== 'ordinary') throw new ApiError('forbidden', 'ordinary_only');
        if (delivery.ackedAt !== null) throw new ApiError('not_found');
        const bytes = await deps.vault.lend(delivery.keyref, delivery.gen).use((value) => Promise.resolve(Uint8Array.from(value)));
        return { raw: { type: 'application/octet-stream', bytes } };
      },
    }),

    route({
      method: 'POST',
      path: '/api/deliveries/:id/ack',
      surface: 'api',
      scope: 'control',
      handle: ({ params }) => {
        const id = params['id'] ?? '';
        if (store.delivery(id) === undefined) throw new ApiError('not_found');
        store.ackDelivery(id, deps.clock.now());
        deps.audit.append({ action: 'delivery.acked', subject: id, at: deps.clock.now() });
        return { json: { status: 'acked' } };
      },
    }),
  ];
}

/** One `box.notice` for each delivery still unacknowledged after its key's grace period; a delivery never stalls a run. */
export function noticeStaleDeliveries(deps: DeliveryDeps): void {
  for (const delivery of deps.store.deliveries()) {
    if (delivery.ackedAt !== null || delivery.notified) continue;
    const graceHours = deps.store.key(delivery.keyref)?.graceHours ?? 24;
    if (deps.clock.now() - delivery.createdAt < graceHours * HOUR_MS) continue;
    deps.events.append('box.notice', { code: 'delivery_unacked', text: 'delivery unacknowledged' });
    deps.store.markDeliveryNotified(delivery.deliveryId);
  }
}
