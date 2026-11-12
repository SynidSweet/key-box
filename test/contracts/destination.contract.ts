import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { bytesOf } from '../kit/index.ts';
import type { Destination, DestinationTarget } from '../../src/ports/destination.ts';
import type { Lent } from '../../src/ports/types.ts';

export interface DestinationSubject {
  readonly destination: Destination;
  readonly target: DestinationTarget;
  readonly master: Lent;
  readonly valueOne: Lent;
  readonly valueTwo: Lent;
  /** Whether the destination now holds a value under `name`. */
  has(name: string): boolean;
}

/** KBOX-35: what every Destination must do, run against the fake and each adapter over fakePlatform. */
export function destinationContract(name: string, make: () => DestinationSubject): void {
  test(`KBOX-35 destination contract (${name}): properties say who can read the value and whether a redeploy is needed`, () => {
    const { destination } = make();
    const p = destination.properties();
    assert.ok(p.readableBy === 'api' || p.readableBy === 'runtime');
    assert.equal(typeof p.needsRedeploy, 'boolean');
  });

  test(`KBOX-35 destination contract (${name}): push makes it so, and repeating the same push changes nothing`, async () => {
    const { destination, target, master, valueOne, has } = make();
    const first = await destination.push(target, 'API_KEY', valueOne, master);
    const again = await destination.push(target, 'API_KEY', valueOne, master);
    assert.equal(has('API_KEY'), true);
    assert.equal(first.outcome, 'applied', 'a push that took effect says so');
    assert.deepEqual(again, first);
  });

  test(`KBOX-2 KBOX-35 destination contract (${name}): pushing a different value gives a receipt that, as of the KBOX-2 ruling, carries no part and no digest of either value`, async () => {
    const { destination, target, master, valueOne, valueTwo } = make();
    const first = await destination.push(target, 'API_KEY', valueOne, master);
    const second = await destination.push(target, 'API_KEY', valueTwo, master);
    // as of the KBOX-2 ruling the receipt names the object, so it no longer differs per value; it must hold nothing of either value
    const seen = JSON.stringify([first, second]);
    for (const lent of [valueOne, valueTwo]) {
      const bytes = Buffer.from(await bytesOf(lent));
      const forms = [bytes.toString('utf8'), bytes.toString('hex'), bytes.toString('base64'), createHash('sha256').update(bytes).digest('hex').slice(0, 16)];
      for (const form of forms) assert.equal(seen.includes(form), false, form);
    }
  });

  test(`KBOX-35 destination contract (${name}): remove deletes the value, and removing what is absent counts as done`, async () => {
    const { destination, target, master, valueOne, has } = make();
    await destination.push(target, 'API_KEY', valueOne, master);
    await destination.remove(target, 'API_KEY', master);
    assert.equal(has('API_KEY'), false);
    await destination.remove(target, 'API_KEY', master);
    await destination.remove(target, 'NEVER_PUSHED', master);
  });
}
