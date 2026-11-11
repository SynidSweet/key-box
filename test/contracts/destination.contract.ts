import assert from 'node:assert/strict';
import { test } from 'node:test';
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

  test(`KBOX-35 destination contract (${name}): pushing a different value gives a different receipt`, async () => {
    const { destination, target, master, valueOne, valueTwo } = make();
    const first = await destination.push(target, 'API_KEY', valueOne, master);
    const second = await destination.push(target, 'API_KEY', valueTwo, master);
    assert.notDeepEqual(second, first);
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
