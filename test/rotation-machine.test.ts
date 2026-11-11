// KBOX-51 and KBOX-17: the pure parts of the rotation state machine: step order, intent names, grace, the retry schedule and what proves a key dead.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkProperty, seedFor } from './kit/index.ts';
import { confirmDead, defaultGraceHours, intentName, nextStep, retryDelayMs, stepsFor } from '../src/pure/rotation-machine.ts';

const MINUTE = 60_000;

test('KBOX-51 the order is create, store, verify, push, redeploy, check, promote, revoke', () => {
  assert.deepEqual(stepsFor({ overlap: true }), ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'grace', 'revoking']);
});

test('KBOX-17 overlap false skips the grace wait: the old value dies as soon as the new one is set', () => {
  assert.deepEqual(stepsFor({ overlap: false }), ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'revoking']);
});

test('KBOX-51 nextStep follows the list and ends at done', () => {
  assert.equal(nextStep('issuing', { overlap: true }), 'verifying');
  assert.equal(nextStep('promoting', { overlap: true }), 'grace');
  assert.equal(nextStep('promoting', { overlap: false }), 'revoking');
  assert.equal(nextStep('revoking', { overlap: true }), 'done');
});

test('KBOX-51 the grace default is 24 h when any destination is a runtime, else 1 h', () => {
  assert.equal(defaultGraceHours(['runtime', 'api']), 24);
  assert.equal(defaultGraceHours(['api']), 1);
  assert.equal(defaultGraceHours([]), 1);
});

test('KBOX-51 intent names are lower case, valid on every platform (Supabase ^[a-z_][a-z0-9_]+$, 4 to 64 characters), and carry ref, generation and run', () => {
  const name = intentName('google/Shop-App/OPENAI_KEY', 3, 'run_0123456789abcdef');
  assert.match(name, /^[a-z_][a-z0-9_]+$/);
  assert.ok(name.length >= 4 && name.length <= 64);
  assert.ok(name.startsWith('kbox_') && name.endsWith('_g3_01234567'));
});

test('KBOX-51 property: whatever the ref, the name is valid, at most 64 characters and keeps its generation and run suffix', () => {
  const seed = seedFor(process.env);
  const chars = 'abcXYZ019/._:@- é中';
  checkProperty(seed, 200, (rng) => {
    const ref = Array.from({ length: 1 + rng.int(150) }, () => chars[rng.int(chars.length)] ?? 'a').join('');
    const run = `run_${Buffer.from(rng.bytes(8)).toString('hex')}`;
    const gen = 1 + rng.int(100000);
    const name = intentName(ref, gen, run);
    assert.match(name, /^[a-z_][a-z0-9_]{3,63}$/);
    assert.ok(name.endsWith(`_g${gen}_${run.slice(4, 12)}`));
    assert.equal(intentName(ref, gen, run), name, 'the same inputs give the same name');
  });
});

test('KBOX-17 the retry after a failed revoke starts at 1 minute, doubles, and stops growing at 1 hour', () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 7, 20, 1000].map(retryDelayMs), [1, 2, 4, 8, 16, 32, 60, 60, 60, 60].map((m) => m * MINUTE));
});

test('KBOX-51 only the verifier rejecting the old value, or the lister showing the id absent, proves a key dead', () => {
  assert.equal(confirmDead({ by: 'verifier', verdict: 'rejected' }), true);
  assert.equal(confirmDead({ by: 'verifier', verdict: 'ok' }), false, 'a 404 while the old value still works');
  assert.equal(confirmDead({ by: 'verifier', verdict: 'unreachable' }), false);
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', listed: [{ platformKeyId: 'pk-2', name: 'n' }] }), true);
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', listed: [{ platformKeyId: 'pk-1', name: 'n', location: { region: 'us' } }] }), false, 'listed anywhere is alive');
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', listed: undefined }), false, 'a list that failed proves nothing');
});
