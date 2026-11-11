import type { Push, PushMessage, PushSubscriptionInput, PushSubscriptions, SubscribeResult } from '../../src/ports/push.ts';

/** Records every push message; a subscription is accepted only over https (the real host list is tested in web-push). */
export class FakePush implements Push, PushSubscriptions {
  readonly sent: PushMessage[] = [];
  readonly subscriptions: PushSubscriptionInput[] = [];
  /** Called on each send before it is recorded, so a test can see what the world looked like at that moment. */
  onSend: (message: PushMessage) => void = () => undefined;

  send(message: PushMessage): void {
    this.onSend(message);
    this.sent.push(message);
  }

  subscribe(input: PushSubscriptionInput): SubscribeResult {
    if (!input.endpoint.startsWith('https://')) return { ok: false, code: 'bad_endpoint' };
    this.subscriptions.push(input);
    return { ok: true };
  }
}
