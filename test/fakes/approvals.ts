import type { Action, ApprovalId, Approvals, Decision } from '../../src/ports/approvals.ts';

type Waiter = { resolve: (d: Decision) => void };

export class FakeApprovals implements Approvals {
  readonly #proposed = new Set<ApprovalId>();
  readonly #decisions = new Map<ApprovalId, Decision>();
  readonly #waiting = new Map<ApprovalId, Waiter[]>();
  #next = 1;

  propose(a: Action): Promise<ApprovalId> {
    void a;
    const id = `approval-${this.#next}`;
    this.#next += 1;
    this.#proposed.add(id);
    return Promise.resolve(id);
  }

  decided(id: ApprovalId): Promise<Decision> {
    if (!this.#proposed.has(id)) return Promise.reject(new Error(`unknown approval ${id}`));
    const done = this.#decisions.get(id);
    if (done !== undefined) return Promise.resolve(done);
    return new Promise((resolve) => this.#waiting.set(id, [...(this.#waiting.get(id) ?? []), { resolve }]));
  }

  /** The approvers' side: settle one proposal. */
  decide(id: ApprovalId, decision: Decision): void {
    this.#decisions.set(id, decision);
    for (const waiter of this.#waiting.get(id) ?? []) waiter.resolve(decision);
    this.#waiting.delete(id);
  }
}
