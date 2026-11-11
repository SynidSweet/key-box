// KBOX-22: the shell of Web Push. Subscriptions and the VAPID key pair live only in the private store; every outside call
// goes through the one PushTransport; time, timers and randomness come in through ports.
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { PrivateStore } from '../ports/private.ts';
import type { Push, PushMessage, PushSubscriptionInput, PushSubscriptions, PushTransport, SubscribeResult } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import { parseSubscription } from '../pure/pushsub.ts';
import hosts from '../data/push-hosts.json' with { type: 'json' };

export interface PushDeps {
  readonly store: PrivateStore;
  readonly transport: PushTransport;
  readonly scheduler: Scheduler;
  readonly clock: Clock;
  readonly random: Random;
  readonly audit: Audit;
  /** The VAPID `sub` claim: a `mailto:` or `https:` contact for the push service operator. */
  readonly subject: string;
}

export function createPush(deps: PushDeps): Push & PushSubscriptions {
  return {
    subscribe(input: PushSubscriptionInput): SubscribeResult {
      const parsed = parseSubscription(input, hosts);
      if (!parsed.ok) return { ok: false, code: parsed.code };
      deps.store.addPushSubscription({ endpoint: parsed.endpoint.href, p256dh: input.p256dh, auth: input.auth });
      return { ok: true };
    },
    send(_message: PushMessage): void {},
  };
}
