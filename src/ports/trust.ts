// KBOX-6, KBOX-49, KBOX-20: the root copy of the approvers (/etc/keybox/trust.json) changes only through this port. Core
// sends a request; root (kb-install) checks it itself and answers. Core's own approver table follows only an `applied`.
// For setup and recovery the proof is a code root made and checks: core relays the typed code and never sees its hash.
// The real port is built by the `update` unit (it writes the trust requests kb-install reads); tests use a fake.

/** An approver as the root copy holds it: public keys only. */
export interface TrustApprover {
  readonly id: string;
  /** The passkey's COSE_Key, base64url. */
  readonly cose_b64: string;
  /** The device key, uncompressed P-256 point, base64url. */
  readonly device_pub_b64: string;
}

/** What the phone sent for one approval (KBOX-9): public data, no value. kb-install verifies it again itself. */
export interface ApprovalProof {
  readonly approval_id: string;
  readonly approver_id: string;
  readonly nonce_b64: string;
  readonly credential_id_b64: string;
  readonly authenticator_data_b64: string;
  readonly client_data_json_b64: string;
  readonly signature_b64: string;
  readonly device_signature_b64: string;
}

export type TrustRequest =
  | { readonly kind: 'trust'; readonly change: 'setup'; readonly code: string; readonly domain: string; readonly approvers: readonly TrustApprover[] }
  | { readonly kind: 'trust'; readonly change: 'recovery'; readonly code: string; readonly approvers: readonly TrustApprover[] }
  | { readonly kind: 'trust'; readonly change: 'approver_add'; readonly approval: ApprovalProof; readonly approver: TrustApprover }
  | { readonly kind: 'trust'; readonly change: 'approver_remove'; readonly approval: ApprovalProof; readonly approver_id: string };

/** Root's answer. A refusal carries a fixed code only. */
export type TrustResult = { readonly result: 'applied' } | { readonly result: 'refused'; readonly code: string };

export interface TrustPort {
  apply(request: TrustRequest): Promise<TrustResult>;
}
