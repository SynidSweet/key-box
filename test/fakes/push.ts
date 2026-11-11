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

  /** The approvers whose subscriptions the box asked to remove, and the sets it asked to keep (the real removal is tested over the store). */
  readonly forgotten: string[] = [];
  readonly retained: (readonly string[])[] = [];

  forgetApprover(approverId: string): void {
    this.forgotten.push(approverId);
  }

  retainApprovers(approverIds: readonly string[]): void {
    this.retained.push(approverIds);
  }

  /** A fixed 65-byte point; the fake signs nothing. */
  applicationServerKey(): string {
    return Buffer.from(Uint8Array.of(4, ...new Uint8Array(64).fill(7))).toString('base64url');
  }
}
