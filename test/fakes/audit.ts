import type { Audit, AuditEvent } from '../../src/ports/audit.ts';

export class FakeAudit implements Audit {
  readonly #events: AuditEvent[] = [];

  append(event: AuditEvent): void {
    this.#events.push({ ...event });
  }

  entries(): readonly AuditEvent[] {
    return this.#events.map((e) => ({ ...e }));
  }
}
