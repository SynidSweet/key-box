// KBOX-61: a key's own allow set narrows its profile. set_allow_rules is checked at proposal (F2) and again at execution (F1) by one
// function, replaces the set in one transaction, and a set never widens relay use: only the empty set is the whole profile.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { RelayProfile } from '../src/ports/relay-profile.ts';
import { parseAction } from '../src/pure/actions.ts';
import type { Action } from '../src/pure/actions.ts';
import { ApiError } from '../src/pure/errors.ts';
import { platformOfKeyref } from '../src/pure/class.ts';
import { hashToken } from '../src/pure/tokens.ts';
import type { StoredApproval } from '../src/shell/approvals.ts';
import { createAllowRuleActions } from '../src/shell/key-executors.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import { openAiRelayProfile } from '../src/platforms/openai/relay.ts';
import { supabaseProfile } from '../src/platforms/supabase/relay.ts';
import { googleRelayProfile } from '../src/platforms/google/relay.ts';
import { TEST_REGISTRY } from './fixtures/profiles.ts';
import { lendWorld } from './support/lend-world.ts';
import type { LendWorld } from './support/lend-world.ts';

const VALUE = Buffer.from('AllowRulesKeyValue0123456789abcd');
const KEY = 'allowkey1';
const approval = (action: Action): StoredApproval => ({ approvalId: 'apr_AAAAAAAAAAAAAAAA', revision: 1, action, requester: { kind: 'box' }, proof: undefined });
const set = (keyref: string, ...ops: readonly string[]): Action => ({ kind: 'set_allow_rules', keyref, rules: ops.map((op) => ({ op, params: {} })) });
const rejects = (code: string) => (e: unknown): boolean => e instanceof ApiError && e.code === 'rejected' && e.detail !== undefined && 'code' in e.detail && e.detail.code === code;

/** The same registry with one rule gone from the path platform's profile: what an update that removes an operation leaves. */
const without = (ruleId: string): readonly PlatformEntry[] =>
  TEST_REGISTRY.map((e): PlatformEntry => (e.id === 'pathplat' && e.relay !== undefined ? { ...e, relay: { ...e.relay, allow: e.relay.allow.filter((r) => r.id !== ruleId) } as RelayProfile } : e));

async function world(t: TestContext, registry: readonly PlatformEntry[] = TEST_REGISTRY) {
  const w: LendWorld = await lendWorld(t, TEST_REGISTRY);
  const store = createRotationStore(w.core.db, w.clock, w.core.hub);
  const make = (reg: readonly PlatformEntry[]) => createAllowRuleActions({ registry: reg, store, meta: w.core.meta, audit: w.core.audit, clock: w.clock });
  const pass = w.enrol('laptop');
  w.addKey({ keyref: KEY, value: VALUE, grants: ['laptop'] });
  const seeded = w.core.events.head();
  const actions = make(registry);
  return {
    w,
    pass,
    actions,
    make,
    run: (action: Action, a = actions) => a.executor(approval(action)),
    rulesOf: (keyref = KEY) => w.core.meta.snapshot().keys.find((k) => k.keyref === keyref)?.allow_rules,
    changed: () => w.core.events.after(seeded).filter((e) => e.kind === 'key.changed').length,
    audited: () => w.core.audit.read(0).entries.filter((r) => r.action === 'key.allow_rules_set').map((r) => [r.ref, r.detail]),
    lend: (rule: string, keyref = KEY) => w.client.lend({ op: 'lend', token_hash: hashToken(pass), keyref, rule_id: rule }),
  };
}

// ------------------------------------------------------------------------------------------------------ F2: the proposal checks

test('KBOX-61 a proposal for an unknown key is rejected (unknown_key) and writes nothing', async (t) => {
  const x = await world(t);
  assert.throws(() => x.actions.precheck(set('nopekey01', 'models-list')), rejects('unknown_key'));
  assert.equal(x.changed(), 0);
});

test('KBOX-61 KBOX-3 a proposal for a master key is rejected (never_relayed), whatever it lists', async (t) => {
  const x = await world(t);
  x.w.addKey({ keyref: 'allowmast1', value: VALUE, cls: 'master' });
  for (const action of [set('allowmast1', 'models-list'), set('allowmast1')]) assert.throws(() => x.actions.precheck(action), rejects('never_relayed'));
});

test('KBOX-61 a proposal naming an op the key\'s profile does not declare is rejected (unknown_op), even beside a good one', async (t) => {
  const x = await world(t);
  assert.throws(() => x.actions.precheck(set(KEY, 'models-list', 'admin-key-create')), rejects('unknown_op'));
  assert.throws(() => x.actions.precheck(set(KEY, 'items-lis')), rejects('unknown_op'), 'one character short');
  assert.throws(() => x.actions.precheck(set(KEY, 'objects-list')), rejects('unknown_op'), 'a rule of another platform\'s profile');
});

test('KBOX-61 a proposal naming one op twice is rejected (duplicate_op), also when the other rules differ', async (t) => {
  const x = await world(t);
  assert.throws(() => x.actions.precheck(set(KEY, 'models-list', 'model-get', 'models-list')), rejects('duplicate_op'));
});

test('KBOX-61 a rule with any param is rejected (params_unsupported) at proposal and written nowhere: v1 pins nothing', async (t) => {
  const x = await world(t);
  const pinned: Action = { kind: 'set_allow_rules', keyref: KEY, rules: [{ op: 'model-get', params: { id: 'gpt' } }] };
  assert.throws(() => x.actions.precheck(pinned), rejects('params_unsupported'));
  assert.deepEqual(await x.run(pinned), { result: 'failed', reason: 'params_unsupported' });
  assert.deepEqual(x.rulesOf(), []);
  assert.equal(x.changed(), 0);
});

test('KBOX-61 a key of a platform with no relay profile is rejected (no_profile): nothing of it can be lent', async (t) => {
  const x = await world(t);
  x.w.addKey({ keyref: 'plainkey1', value: VALUE, platform: 'plain' });
  assert.throws(() => x.actions.precheck(set('plainkey1')), rejects('no_profile'));
});

test('KBOX-61 a good proposal passes the check, and any other kind passes it untouched', async (t) => {
  const x = await world(t);
  x.actions.precheck(set(KEY, 'models-list', 'model-get'));
  x.actions.precheck(set(KEY));
  x.actions.precheck({ kind: 'demote', keyref: 'nopekey01' });
});

// ------------------------------------------------------------------------------------------------------ F1 and the write

test('KBOX-61 execution re-checks: an op an update removed from the profile since the proposal fails (unknown_op) and the set is unchanged', async (t) => {
  const x = await world(t);
  assert.deepEqual(await x.run(set(KEY, 'models-list', 'model-get')), { result: 'done' });
  const before = x.changed();
  const later = x.make(without('model-get'));
  assert.deepEqual(await x.run(set(KEY, 'models-list', 'model-get'), later), { result: 'failed', reason: 'unknown_op' });
  assert.deepEqual(x.rulesOf(), ['model-get', 'models-list']);
  assert.equal(x.changed(), before, 'no key.changed');
});

test('KBOX-61 execution of an unknown key or a master key fails with the proposal\'s code', async (t) => {
  const x = await world(t);
  x.w.addKey({ keyref: 'allowmast1', value: VALUE, cls: 'master' });
  assert.deepEqual(await x.run(set('nopekey01')), { result: 'failed', reason: 'unknown_key' });
  assert.deepEqual(await x.run(set('allowmast1', 'models-list')), { result: 'failed', reason: 'never_relayed' });
  assert.deepEqual(x.rulesOf('allowmast1'), []);
});

test('KBOX-61 a second set replaces the first (nothing is appended), one key.changed and one key.allow_rules_set {count} per write', async (t) => {
  const x = await world(t);
  assert.deepEqual(await x.run(set(KEY, 'models-list', 'model-get')), { result: 'done' });
  assert.deepEqual(x.rulesOf(), ['model-get', 'models-list']);
  assert.equal(x.changed(), 1);
  assert.deepEqual(await x.run(set(KEY, 'items-list')), { result: 'done' });
  assert.deepEqual(x.rulesOf(), ['items-list'], 'the first set is gone');
  assert.equal(x.changed(), 2);
  assert.deepEqual(x.audited(), [[KEY, { count: 2 }], [KEY, { count: 1 }]]);
});

test('KBOX-61 the empty list removes the set (the whole profile again), and setting the same set twice leaves the same state', async (t) => {
  const x = await world(t);
  await x.run(set(KEY, 'models-list'));
  await x.run(set(KEY, 'models-list'));
  assert.deepEqual(x.rulesOf(), ['models-list']);
  assert.deepEqual(await x.run(set(KEY)), { result: 'done' });
  assert.deepEqual(x.rulesOf(), []);
  assert.deepEqual(x.audited().at(-1), [KEY, { count: 0 }]);
});

test('KBOX-61 another key\'s set is left alone by a replace', async (t) => {
  const x = await world(t);
  x.w.addKey({ keyref: 'allowkey2', value: VALUE, grants: ['laptop'] });
  await x.run(set('allowkey2', 'item-create'));
  await x.run(set(KEY, 'models-list'));
  await x.run(set(KEY));
  assert.deepEqual(x.rulesOf('allowkey2'), ['item-create']);
});

// ------------------------------------------------------------------------------------------------------ the relay never widens

test('KBOX-61 KBOX-3 after a set, a lend for a rule outside it is refused and one inside it passes; the empty list gives the whole profile back', async (t) => {
  const x = await world(t);
  assert.equal((await x.lend('items-list')).ok, true, 'control: no set, the whole profile');
  await x.run(set(KEY, 'models-list'));
  assert.equal((await x.lend('models-list')).ok, true, 'inside');
  assert.deepEqual(await x.lend('items-list'), { ok: false, code: 'forbidden' }, 'a profile rule outside the set');
  await x.run(set(KEY));
  assert.equal((await x.lend('items-list')).ok, true, 'the empty list');
});

test('KBOX-61 KBOX-3 a set whose every id has left the profile lends nothing: it is not the whole profile', async (t) => {
  const x = await world(t);
  await x.run(set(KEY, 'model-get'));
  // The stored set is only an id the profile has since lost (a profile update removed that rule).
  x.w.core.meta.putAllowRule(KEY, 'rule-long-gone');
  x.w.core.db.prepare('DELETE FROM allow_rules WHERE keyref = ? AND rule_id = ?').run(KEY, 'model-get');
  assert.deepEqual(x.rulesOf(), ['rule-long-gone']);
  for (const rule of ['models-list', 'model-get', 'items-list', 'rule-long-gone']) assert.deepEqual(await x.lend(rule), { ok: false, code: 'forbidden' }, rule);
});

// ------------------------------------------------------------------------------------------------------ the action parser

test('KBOX-61 KBOX-53 every allow-rule id of the three real profiles parses as an op (they carry hyphens)', () => {
  for (const profile of [openAiRelayProfile, supabaseProfile, googleRelayProfile]) {
    for (const rule of profile.allow) {
      const parsed = parseAction({ kind: 'set_allow_rules', keyref: `${profile.platform}/p/K`, rules: [{ op: rule.id, params: {} }] });
      assert.ok(parsed.ok, `${profile.platform} ${rule.id}`);
    }
  }
});

test('KBOX-61 the platform of a keyref is its first segment', () => {
  assert.equal(platformOfKeyref('google/shop/GOOGLE_KEY'), 'google');
  assert.equal(platformOfKeyref('bare'), 'bare');
});
