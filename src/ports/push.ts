// KBOX-22: how the owner learns something waits. Web Push from the box itself: a message carries the box's one-line title,
// a names-only kind and, for coalesced enrols, how many wait. Never a URL, never a value, never requester text.
export interface PushMessage {
  /** The box's own one-line title of the thing that waits (`src/pure/words.ts`). */
  readonly title: string;
  /** A names-only code: an approval kind, `enrol`, `new_network`, `recovery`. */
  readonly kind: string;
  /** How many wait, for the coalesced enrol push. */
  readonly count?: number;
}

export interface Push {
  /** Sends to every subscription. Returns at once and never throws: a push service that fails or hangs never blocks the caller. */
  send(message: PushMessage): void;
}

export interface PushSubscriptionInput {
  readonly endpoint: string;
  /** The browser's P-256 public key, uncompressed point, base64url. */
  readonly p256dh: string;
  /** The 16-byte auth secret, base64url. */
  readonly auth: string;
}

export type SubscribeResult = { readonly ok: true } | { readonly ok: false; readonly code: 'bad_endpoint' | 'bad_key' };

export interface PushSubscriptions {
  /** Accepts an endpoint only over https with a host in `src/data/push-hosts.json`, and only well-formed keys. */
  subscribe(input: PushSubscriptionInput, approverId?: string): SubscribeResult;
  /** An approver was removed: their subscriptions go, so their phone gets no more notices. */
  forgetApprover(approverId: string): void;
  /** Recovery replaced the approvers: every subscription but those of `approverIds` goes. */
  retainApprovers(approverIds: readonly string[]): void;
  /** The box's VAPID public key (base64url, 65-byte uncompressed point): the applicationServerKey the phone subscribes with. */
  applicationServerKey(): string;
}

/** The one outside call: one POST to a push service. Answers the HTTP status, or rejects when the call failed or was aborted. */
export interface PushTransport {
  post(endpoint: URL, headers: Readonly<Record<string, string>>, body: Uint8Array, signal: AbortSignal): Promise<number>;
}
