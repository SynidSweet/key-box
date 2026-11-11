// Design section 5.1: names only, hash-chained by the adapter.
export interface AuditEvent {
  readonly action: string;
  readonly subject: string;
  readonly at: number;
}

export interface Audit {
  append(event: AuditEvent): void;
}
