import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import type { Vault } from '../../src/ports/vault.ts';
import { bytesOf, canary } from '../kit/index.ts';

/** KBOX-35: what every Vault must do, run against the fake and each real adapter. */
export function vaultContract(name: string, make: () => Vault): void {
  test(`KBOX-35 vault contract (${name}): a lent key gives back the bytes that were put`, async () => {
    const vault = make();
    const c = canary();
    vault.put('openai/master', 1, c.bytes);
    assert.deepEqual(await bytesOf(vault.lend('openai/master', 1)), Uint8Array.from(c.bytes));
  });

  test(`KBOX-35 vault contract (${name}): a lent key shows only its label when printed, stringified or inspected`, () => {
    const vault = make();
    const c = canary();
    vault.put('openai/master', 1, c.bytes);
    const lent = vault.lend('openai/master', 1);
    c.assertAbsent({ string: String(lent), template: `${lent}`, json: JSON.stringify({ lent }), inspect: inspect(lent, { depth: 5 }) });
  });

  test(`KBOX-35 vault contract (${name}): generations are separate and a later put does not change a key already lent`, async () => {
    const vault = make();
    vault.put('k', 1, Buffer.from('one'));
    const first = vault.lend('k', 1);
    vault.put('k', 2, Buffer.from('two'));
    assert.equal(Buffer.from(await bytesOf(first)).toString(), 'one');
    assert.equal(Buffer.from(await bytesOf(vault.lend('k', 2))).toString(), 'two');
  });

  test(`KBOX-35 vault contract (${name}): lending a key that was never put or was retired is refused`, () => {
    const vault = make();
    assert.throws(() => vault.lend('missing', 1));
    vault.put('k', 1, Buffer.from('one'));
    vault.retire('k', 1);
    assert.throws(() => vault.lend('k', 1));
    assert.doesNotThrow(() => vault.retire('never-put', 7));
  });

  test(`KBOX-35 vault contract (${name}): changing the bytes passed to put afterwards does not change the stored key`, async () => {
    const vault = make();
    const bytes = Buffer.from('original');
    vault.put('k', 1, bytes);
    bytes.fill(0);
    assert.equal(Buffer.from(await bytesOf(vault.lend('k', 1))).toString(), 'original');
  });
}
