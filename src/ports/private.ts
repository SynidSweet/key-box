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

export interface PrivateStore {
  addPushSubscription(row: PushSubscriptionRow): void;
  addApprover(row: ApproverRow): void;
  close(): void;
}
