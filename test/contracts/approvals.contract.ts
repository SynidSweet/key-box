import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Approvals, ApprovalId, Decision } from '../../src/ports/approvals.ts';

export interface ApprovalsSubject {
  readonly approvals: Approvals;
  /** The approvers' side: settle one proposal. */
  decide(id: ApprovalId, decision: Decision): void;
}

/** KBOX-35: what every Approvals must do, run against the fake and each real adapter. */
export function approvalsContract(name: string, make: () => ApprovalsSubject): void {
  const action = { kind: 'rotate', summary: 'Change the OpenAI admin key' };

  test(`KBOX-35 approvals contract (${name}): two proposals get two different ids`, async () => {
    const { approvals } = make();
    assert.notEqual(await approvals.propose(action), await approvals.propose(action));
  });

  test(`KBOX-35 approvals contract (${name}): decided waits for the decision and then gives it, also to a later asker`, async () => {
    const { approvals, decide } = make();
    const id = await approvals.propose(action);
    let settled = false;
    const waiting = approvals.decided(id).then((d) => {
      settled = true;
      return d;
    });
    await Promise.resolve();
    assert.equal(settled, false);
    decide(id, { kind: 'approved' });
    assert.deepEqual(await waiting, { kind: 'approved' });
    assert.deepEqual(await approvals.decided(id), { kind: 'approved' });
  });

  test(`KBOX-35 approvals contract (${name}): a decision on one proposal does not settle another`, async () => {
    const { approvals, decide } = make();
    const a = await approvals.propose(action);
    const b = await approvals.propose(action);
    decide(a, { kind: 'denied' });
    decide(b, { kind: 'expired' });
    assert.deepEqual(await approvals.decided(a), { kind: 'denied' });
    assert.deepEqual(await approvals.decided(b), { kind: 'expired' });
  });

  test(`KBOX-35 approvals contract (${name}): asking about an id that was never proposed is refused`, { timeout: 5000 }, async () => {
    const { approvals } = make();
    await assert.rejects(() => approvals.decided('never-proposed'));
  });
}
