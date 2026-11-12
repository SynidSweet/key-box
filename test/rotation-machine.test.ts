// KBOX-51 and KBOX-17: the pure parts of the rotation state machine: step order, intent names, grace, the retry schedule and what proves a key dead.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkProperty, seedFor } from './kit/index.ts';
import { afterProof, confirmDead, defaultGraceHours, intentAbsent, intentName, nextStep, retryDelayMs, stepsFor } from '../src/pure/rotation-machine.ts';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const LEAD = 24 * HOUR;

test('KBOX-51 the order is create, store, verify, push, redeploy, check, promote, revoke', () => {
  assert.deepEqual(stepsFor({ overlap: true, boxMade: false }), ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'grace', 'revoking']);
});

test('KBOX-17 overlap false skips the grace wait: the old value dies as soon as the new one is set', () => {
  assert.deepEqual(stepsFor({ overlap: false, boxMade: false }), ['issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'revoking']);
});

test('KBOX-51 nextStep follows the list and ends at done', () => {
  assert.equal(nextStep('issuing', { overlap: true, boxMade: false }), 'verifying');
  assert.equal(nextStep('promoting', { overlap: true, boxMade: false }), 'grace');
  assert.equal(nextStep('promoting', { overlap: false, boxMade: false }), 'revoking');
  assert.equal(nextStep('revoking', { overlap: true, boxMade: false }), 'done');
});

test('KBOX-55 a box-made key has no pushing and no redeploying (both would ask for a master): issue, verify, check, promote, grace, revoke', () => {
  assert.deepEqual(stepsFor({ overlap: true, boxMade: true }), ['issuing', 'verifying', 'checking', 'promoting', 'grace', 'revoking']);
  assert.equal(nextStep('verifying', { overlap: true, boxMade: true }), 'checking');
  assert.equal(nextStep('checking', { overlap: true, boxMade: true }), 'promoting');
});

test('KBOX-55 a proof the token service accepted promotes, at any time, even past the deadline', () => {
  for (const now of [0, LEAD, 2 * LEAD, 3 * LEAD]) assert.deepEqual(afterProof('ok', { now, openedAt: 0, leadMs: LEAD, attempt: 5 }), { then: 'promote' });
});

test('KBOX-55 KBOX-17 a refused or unanswered proof is retried with the backoff until opened_at + 2 x lead, never later: one millisecond before it a retry, at it and after the run fails', () => {
  const at = (now: number, attempt = 0) => ({ now, openedAt: 1000, leadMs: LEAD, attempt });
  const deadline = 1000 + 2 * LEAD;
  assert.deepEqual(afterProof('rejected', at(1000 + LEAD)), { then: 'retry', inMs: MINUTE });
  assert.deepEqual(afterProof('unreachable', at(1000 + LEAD, 3)), { then: 'retry', inMs: 8 * MINUTE });
  assert.deepEqual(afterProof('rejected', at(deadline - 1, 9)), { then: 'retry', inMs: 1 }, 'the last retry lands on the deadline, not an hour after it');
  assert.deepEqual(afterProof('rejected', at(deadline)), { then: 'fail', code: 'jwks_not_taken' });
  assert.deepEqual(afterProof('rejected', at(deadline + 1)), { then: 'fail', code: 'jwks_not_taken' });
  assert.deepEqual(afterProof('unreachable', at(deadline)), { then: 'fail', code: 'sts_unreachable' });
});

test('KBOX-55 property: a failed proof before the deadline is retried within the backoff and never past the deadline; at or after it the code names the last answer', () => {
  const seed = seedFor(process.env);
  checkProperty(seed, 300, (rng) => {
    const openedAt = rng.int(1_000_000);
    const leadMs = 1 + rng.int(2 * LEAD);
    const now = openedAt + rng.int(5 * leadMs);
    const attempt = rng.int(30);
    const verdict = rng.int(2) === 0 ? 'rejected' : 'unreachable';
    const next = afterProof(verdict, { now, openedAt, leadMs, attempt });
    const deadline = openedAt + 2 * leadMs;
    if (now >= deadline) {
      assert.deepEqual(next, { then: 'fail', code: verdict === 'rejected' ? 'jwks_not_taken' : 'sts_unreachable' });
      return;
    }
    assert.ok(next.then === 'retry', `a retry before the deadline, got ${next.then}`);
    assert.ok(next.inMs > 0 && next.inMs <= retryDelayMs(attempt) && now + next.inMs <= deadline, `inMs ${next.inMs}`);
  });
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
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', at: {}, listing: { complete: true, at: {}, keys: [{ platformKeyId: 'pk-2', name: 'n' }] } }), true);
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', at: {}, listing: { complete: true, at: {}, keys: [{ platformKeyId: 'pk-1', name: 'n', location: { region: 'us' } }] } }), false, 'listed anywhere is alive');
  assert.equal(confirmDead({ by: 'lister', id: 'pk-1', at: {}, listing: undefined }), false, 'a list that failed proves nothing');
});

test('KBOX-51 a listing proves a key dead only when it is complete, is for the location recorded with the key, and shows the id absent or disabled', () => {
  const at = { region: 'eu', project: 'shop' };
  const other = { platformKeyId: 'pk-2', name: 'n' };
  const dead = (listing: { complete: boolean; at: { region?: string; project?: string }; keys: { platformKeyId: string; name: string; disabled?: true }[] } | undefined): boolean =>
    confirmDead({ by: 'lister', id: 'pk-1', at, listing });
  assert.equal(dead({ complete: true, at, keys: [other] }), true, 'absent from a complete listing of its own location');
  assert.equal(dead({ complete: true, at, keys: [other, { platformKeyId: 'pk-1', name: 'n', disabled: true }] }), true, 'disabled there');
  assert.equal(dead({ complete: true, at, keys: [{ platformKeyId: 'pk-1', name: 'n' }] }), false, 'listed and enabled');
  assert.equal(dead({ complete: false, at, keys: [other] }), false, 'one page of several proves nothing');
  assert.equal(dead({ complete: true, at: { region: 'us', project: 'shop' }, keys: [other] }), false, 'another region');
  assert.equal(dead({ complete: true, at: { project: 'shop' }, keys: [other] }), false, 'a listing that omits the region');
  assert.equal(dead({ complete: true, at: { region: 'eu', project: 'blog' }, keys: [other] }), false, 'another project');
  assert.equal(dead({ complete: true, at: { region: 'eu' }, keys: [other] }), false, 'a listing that omits the project');
  assert.equal(dead(undefined), false, 'a listing that failed proves nothing');
});

test('KBOX-51 an intent key is absent only on a complete listing of the key location that does not name it', () => {
  const at = { region: 'eu', project: 'shop' };
  const named = { platformKeyId: 'pk-9', name: 'kbox_a_g2_ab12cd34' };
  const other = { platformKeyId: 'pk-2', name: 'kbox_b_g1_ffffffff' };
  assert.equal(intentAbsent({ complete: true, at, keys: [other] }, at, named.name), true, 'a complete listing without it');
  assert.equal(intentAbsent({ complete: true, at, keys: [] }, at, named.name), true, 'an empty complete listing');
  assert.equal(intentAbsent({ complete: true, at, keys: [other, named] }, at, named.name), false, 'it is listed');
  assert.equal(intentAbsent({ complete: false, at, keys: [other] }, at, named.name), false, 'one page of several proves nothing');
  assert.equal(intentAbsent({ complete: true, at: { region: 'us', project: 'shop' }, keys: [other] }, at, named.name), false, 'a listing of another region');
  assert.equal(intentAbsent(undefined, at, named.name), false, 'a listing that failed');
});
