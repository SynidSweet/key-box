import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { DestinationTarget, Redeployer } from '../../src/ports/destination.ts';
import type { Lent } from '../../src/ports/types.ts';

export interface RedeployerSubject {
  readonly redeployer: Redeployer;
  readonly target: DestinationTarget;
  readonly master: Lent;
  /** Make the next deploy that starts end as failed. */
  failNext(): void;
}

/** KBOX-35: what every Redeployer must do, run against the fake and each adapter over fakePlatform. */
export function redeployerContract(name: string, make: () => RedeployerSubject): void {
  test(`KBOX-35 redeployer contract (${name}): a deploy becomes ready, and each redeploy gets its own reference`, async () => {
    const { redeployer, target, master } = make();
    const a = await redeployer.redeploy(target, master);
    const b = await redeployer.redeploy(target, master);
    assert.notEqual(a, b);
    assert.equal(await redeployer.ready(a), 'ready');
  });

  test(`KBOX-35 redeployer contract (${name}): a deploy that fails is failed, and only that one`, async () => {
    const { redeployer, target, master, failNext } = make();
    failNext();
    const bad = await redeployer.redeploy(target, master);
    const good = await redeployer.redeploy(target, master);
    assert.equal(await redeployer.ready(bad), 'failed');
    assert.equal(await redeployer.ready(good), 'ready');
  });
}
