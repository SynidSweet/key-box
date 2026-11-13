// KBOX-14 as amended by revoke-proof (2026-11-13): the relay's response scanner looks for the current generation of each key and every `grace`
// generation (a value that may still work, KBOX-51), chosen by status and never by generation number: failed runs use numbers up, and several
// grace generations may linger at once. Without the rotation store's view (nothing rotates) it keeps today's current and current - 1.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { GenStatus } from '../src/shell/rotation-store.ts';
import { hashToken } from '../src/pure/tokens.ts';
import { lendWorld } from './support/lend-world.ts';
import type { LendWorld, LendWorldOptions } from './support/lend-world.ts';

const KEY = 'gracekey01';
const VALUES = ['GenOneValueOnlyCoreHolds0123456789abcd', 'GenTwoValueOnlyCoreHolds0123456789abcd', 'GenThreeValueOnlyCoreHolds0123456789ab'] as const;

/** Gen 3 current, gens 1 and 2 stored with the given statuses (as the rotation store would show them), and a pass granted the key. */
async function scanWorld(t: TestContext, statuses: readonly [GenStatus, GenStatus] | undefined, stored: readonly [Uint8Array, Uint8Array] = [Buffer.from(VALUES[0]), Buffer.from(VALUES[1])]): Promise<{ readonly w: LendWorld; readonly pass: string }> {
  const options: LendWorldOptions =
    statuses === undefined
      ? {}
      : { generations: (keyref) => (keyref === KEY ? [{ gen: 1, status: statuses[0] }, { gen: 2, status: statuses[1] }, { gen: 3, status: 'current' }] : []) };
  const w = await lendWorld(t, undefined, options);
  w.addKey({ keyref: KEY, value: Buffer.from(VALUES[2]), gen: 3, grants: ['laptop'] });
  w.core.vault.put(KEY, 1, stored[0]);
  w.core.vault.put(KEY, 2, stored[1]);
  return { w, pass: w.enrol('laptop') };
}

async function cut(w: LendWorld, pass: string, value: string): Promise<boolean> {
  const opened = await w.client.scan({ op: 'scan', token_hash: hashToken(pass), keyref: KEY });
  assert.ok(opened.ok);
  try {
    const step = await opened.session.feed(Buffer.from(`{"echo":"${value}"}`));
    return step.kind === 'hit' || (await opened.session.end()).kind === 'hit';
  } finally {
    opened.session.close();
  }
}

test('KBOX-14 a grace generation below a failed one (gen 1 grace, 2 failed, 3 current) is caught by the relay scan', async (t) => {
  const { w, pass } = await scanWorld(t, ['grace', 'failed']);
  assert.equal(await cut(w, pass, VALUES[0]), true, 'gen 1 may still work');
  assert.equal(await cut(w, pass, VALUES[2]), true, 'the current one');
  assert.equal(await cut(w, pass, VALUES[1]), false, 'a failed generation never went live');
});

test('KBOX-14 two lingering grace generations are both caught', async (t) => {
  const { w, pass } = await scanWorld(t, ['grace', 'grace']);
  assert.equal(await cut(w, pass, VALUES[0]), true);
  assert.equal(await cut(w, pass, VALUES[1]), true);
});

test('KBOX-14 a retired generation is not scanned, so a value file it left behind writes no forms_unbuildable line', async (t) => {
  const { w, pass } = await scanWorld(t, ['grace', 'retired'], [Buffer.from(VALUES[0]), Buffer.from('ab\0cd')]);
  assert.equal(await cut(w, pass, VALUES[0]), true);
  assert.deepEqual(w.journal, []);
});

test('KBOX-14 control: without the rotation store\'s view the scan reads the current generation and the one before it, as before', async (t) => {
  const { w, pass } = await scanWorld(t, undefined);
  assert.equal(await cut(w, pass, VALUES[1]), true, 'current - 1');
  assert.equal(await cut(w, pass, VALUES[0]), false, 'current - 2 is not read');
});
