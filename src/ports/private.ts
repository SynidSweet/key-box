// KBOX-5: what the private database holds. It is its own port and its own connection, and nothing here is ever exported.
export interface PushSubscriptionRow {
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

export interface ApproverRow {
  readonly approverId: string;
  readonly credentialId: string;
  readonly publicKey: string;
}

// --- Web Push (KBOX-22): subscriptions and the box's VAPID key pair live here and nowhere else -----------------------
/** The box's VAPID key pair, both base64url: the 32-byte private scalar and the 65-byte uncompressed public point. */
export interface VapidKeyPairRow {
  readonly privateKey: string;
  readonly publicKey: string;
}

export interface PushStore {
  listPushSubscriptions(): readonly PushSubscriptionRow[];
  removePushSubscription(endpoint: string): void;
  /** The stored VAPID key pair, or `undefined` before the first one was put. */
  getVapidKeyPair(): VapidKeyPairRow | undefined;
  putVapidKeyPair(row: VapidKeyPairRow): void;
}

export interface PrivateStore extends PushStore {
  addPushSubscription(row: PushSubscriptionRow): void;
  addApprover(row: ApproverRow): void;
  close(): void;
}
