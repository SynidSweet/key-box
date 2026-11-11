import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Audit, AuditEvent } from '../../src/ports/audit.ts';

export interface AuditSubject {
  readonly audit: Audit;
  /** What the adapter has recorded, in order. */
  entries(): readonly AuditEvent[];
}

/** KBOX-35: what every Audit must do, run against the fake and each real adapter. */
export function auditContract(name: string, make: () => AuditSubject): void {
  test(`KBOX-35 audit contract (${name}): events are kept in the order they were appended`, () => {
    const { audit, entries } = make();
    audit.append({ action: 'key.issued', subject: 'openai/master', at: 1 });
    audit.append({ action: 'key.revoked', subject: 'openai/master', at: 2 });
    audit.append({ action: 'key.issued', subject: 'vercel/master', at: 3 });
    assert.deepEqual(entries().map((e) => [e.action, e.at]), [['key.issued', 1], ['key.revoked', 2], ['key.issued', 3]]);
  });

  test(`KBOX-35 audit contract (${name}): an event changed by the caller after append is not changed in the log`, () => {
    const { audit, entries } = make();
    const event = { action: 'key.issued', subject: 'a', at: 1 };
    audit.append(event);
    event.action = 'tampered';
    assert.equal(entries()[0]?.action, 'key.issued');
  });
}
