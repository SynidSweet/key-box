export type ApprovalId = string;

export interface Action {
  readonly kind: string;
  readonly summary: string;
}

export interface Decision {
  readonly kind: 'approved' | 'denied' | 'expired';
}

export interface Approvals {
  propose(a: Action): Promise<ApprovalId>;
  /** Resolves when the approvers have decided; rejects for an id never proposed. */
  decided(id: ApprovalId): Promise<Decision>;
}
