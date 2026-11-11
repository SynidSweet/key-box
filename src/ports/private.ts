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
  /** Removes every subscription registered by this approver (a removed approver's phone gets no more notices). Ownerless rows stay. */
  removePushSubscriptionsOf(approverId: string): void;
  /** Removes every subscription not registered by one of these approvers, ownerless rows included (recovery replaces the approvers). */
  retainPushSubscriptionsOf(approverIds: readonly string[]): void;
  /** The stored VAPID key pair, or `undefined` before the first one was put. */
  getVapidKeyPair(): VapidKeyPairRow | undefined;
  putVapidKeyPair(row: VapidKeyPairRow): void;
}

// --- Approvers (KBOX-9, KBOX-49, KBOX-20): core's own table; it follows the root copy only after an `applied` ---------
/** One approver: a passkey and a device key registered together, its phrase and its last signature counter. Public keys only. */
export interface ApproverRecord {
  readonly approverId: string;
  /** base64url. */
  readonly credentialId: string;
  /** The passkey's COSE_Key, base64url. */
  readonly coseKey: string;
  /** The device key, uncompressed P-256 point, base64url. */
  readonly devicePublicKey: string;
  /** The short phrase typed at registration, shown on paste pages (KBOX-12). */
  readonly phrase: string;
  readonly signCount: number;
}

export interface ApproverStore {
  /** Approvers with both keys; a row without a device key can never approve and is not listed. */
  listApprovers(): readonly ApproverRecord[];
  putApprover(record: ApproverRecord): void;
  removeApprover(approverId: string): void;
  /** Recovery: every approver is replaced by these, in one transaction. */
  replaceApprovers(records: readonly ApproverRecord[]): void;
  setSignCount(approverId: string, signCount: number): void;
}

export interface PrivateStore extends PushStore, ApproverStore {
  /** `approverId` is the approver who registered it; a subscription added without one is ownerless. One endpoint is one row. */
  addPushSubscription(row: PushSubscriptionRow, approverId?: string): void;
  addApprover(row: ApproverRow): void;
  close(): void;
}
