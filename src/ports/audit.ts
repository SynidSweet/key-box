// Design section 5.1, KBOX-50: names only, hash-chained by the adapter. The port has append and read; there is no
// update and no delete.
export interface AuditEvent {
  readonly action: string;
  /** The row's `ref`: a key reference, a route, an approval id. */
  readonly subject: string;
  readonly at: number;
  /** A token label, an approver id or `box` (the default). */
  readonly actor?: string;
  /** A closed object per action: names, ids, codes, statuses, byte counts. */
  readonly detail?: Readonly<Record<string, string | number | boolean>>;
}

export interface Audit {
  append(event: AuditEvent): void;
}

export interface AuditRow {
  readonly seq: number;
  readonly at: number;
  readonly actor: string;
  readonly action: string;
  readonly ref: string;
  readonly detail: Readonly<Record<string, string | number | boolean>>;
  readonly prev_hash: string;
  readonly hash: string;
}

export type ChainVerdict = { readonly ok: true; readonly rows: number } | { readonly ok: false; readonly firstBadSeq: number };

export interface AuditLog extends Audit {
  /** Rows after `since`, at most `limit` of them (all when omitted); `more` says rows remain beyond the page. */
  read(since: number, limit?: number): { readonly entries: readonly AuditRow[]; readonly more: boolean };
  verifyChain(): ChainVerdict;
}
