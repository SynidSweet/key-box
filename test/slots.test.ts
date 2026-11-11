// KBOX-7: one approval per action, bound to one exact action, and one pending proposal per slot (kind and subject).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canary } from './kit/index.ts';
import { approveWorld } from './support/approve-world.ts';
import type { Action } from '../src/pure/actions.ts';
import { ApiError } from '../src/pure/errors.ts';

const DAY = 24 * 3600_000;
const dest = (target: string) => ({ kind: 'vercel_env', target }) as const;

/** For each kind: an action, a second action in the SAME slot, and one in another slot (another subject). */
const SLOT_TABLE: readonly (readonly [name: string, same: [Action, Action], other: Action])[] = [
  ['add_key (the platform)', [{ kind: 'add_key', platform: 'openai', name: 'A', projects: ['p'], scope: { items: [] } }, { kind: 'add_key', platform: 'openai', name: 'B', projects: ['p'], scope: { items: [] } }], { kind: 'add_key', platform: 'google', name: 'A', projects: ['p'], scope: { items: [] } }],
  ['delete_key (the key)', [{ kind: 'delete_key', keyref: 'k1' }, { kind: 'delete_key', keyref: 'k1' }], { kind: 'delete_key', keyref: 'k2' }],
  ['rotate_key (the key)', [{ kind: 'rotate_key', keyref: 'k1' }, { kind: 'rotate_key', keyref: 'k1' }], { kind: 'rotate_key', keyref: 'k2' }],
  ['demote (the key)', [{ kind: 'demote', keyref: 'k1' }, { kind: 'demote', keyref: 'k1' }], { kind: 'demote', keyref: 'k2' }],
  ['set_allow_rules (the key)', [{ kind: 'set_allow_rules', keyref: 'k1', rules: [] }, { kind: 'set_allow_rules', keyref: 'k1', rules: [{ op: 'list', params: {} }] }], { kind: 'set_allow_rules', keyref: 'k2', rules: [] }],
  ['set_schedule (the key)', [{ kind: 'set_schedule', keyref: 'k1', rotate_every_days: 30, grace_hours: 24 }, { kind: 'set_schedule', keyref: 'k1', rotate_every_days: 7, grace_hours: 1 }], { kind: 'set_schedule', keyref: 'k2', rotate_every_days: 30, grace_hours: 24 }],
  ['grant (shared with revoke_grant, the key)', [{ kind: 'grant', keyref: 'k1', machine: 'ws-1' }, { kind: 'revoke_grant', keyref: 'k1', machine: 'ws-2' }], { kind: 'grant', keyref: 'k2', machine: 'ws-1' }],
  ['revoke_grant (shared with grant, the key)', [{ kind: 'revoke_grant', keyref: 'k1', machine: 'ws-1' }, { kind: 'grant', keyref: 'k1', machine: 'ws-1' }], { kind: 'revoke_grant', keyref: 'k2', machine: 'ws-1' }],
  ['add_destination (shared with remove_destination, the key)', [{ kind: 'add_destination', keyref: 'k1', destination: dest('a') }, { kind: 'remove_destination', keyref: 'k1', destination: dest('b') }], { kind: 'add_destination', keyref: 'k2', destination: dest('a') }],
  ['remove_destination (shared with add_destination, the key)', [{ kind: 'remove_destination', keyref: 'k1', destination: dest('a') }, { kind: 'add_destination', keyref: 'k1', destination: dest('a') }], { kind: 'remove_destination', keyref: 'k2', destination: dest('a') }],
  ['enrol (the source address)', [{ kind: 'enrol', label: 'ws-1', token_sha256: 'a'.repeat(64), address: '198.51.100.1' }, { kind: 'enrol', label: 'ws-2', token_sha256: 'b'.repeat(64), address: '198.51.100.1' }], { kind: 'enrol', label: 'ws-1', token_sha256: 'a'.repeat(64), address: '198.51.100.2' }],
  ['vercel_set_domain (project and operation)', [{ kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'a.example.com' }, { kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'b.example.com' }], { kind: 'vercel_set_domain', project: 'shop', op: 'remove', domain: 'a.example.com' }],
  ['vercel_set_team_setting (the setting name)', [{ kind: 'vercel_set_team_setting', setting: 'deploymentProtection', value: 'on' }, { kind: 'vercel_set_team_setting', setting: 'deploymentProtection', value: 'off' }], { kind: 'vercel_set_team_setting', setting: 'previewComments', value: 'on' }],
  // FORCED-FLIP: as of the spec revision 4 approver_add names the new approver's key hashes.
  ['approver_add (one slot)', [{ kind: 'approver_add', cose_sha256: '5'.repeat(64), device_sha256: '6'.repeat(64) }, { kind: 'approver_add', cose_sha256: '7'.repeat(64), device_sha256: '8'.repeat(64) }], { kind: 'install_update', install: '1'.repeat(64), commit: '2'.repeat(40), base: '3'.repeat(64) }],
  ['install_update (one slot)', [{ kind: 'install_update', install: '1'.repeat(64), commit: '2'.repeat(40), base: '3'.repeat(64) }, { kind: 'install_update', install: '4'.repeat(64), commit: '2'.repeat(40), base: '3'.repeat(64) }], { kind: 'approver_add', cose_sha256: '5'.repeat(64), device_sha256: '6'.repeat(64) }],
];

const slotTaken = (pendingId: string) => (e: unknown): boolean => e instanceof ApiError && e.code === 'slot_taken' && JSON.stringify(e.detail) === JSON.stringify({ pending_approval_id: pendingId });

for (const [name, [first, second], other] of SLOT_TABLE) {
  test(`KBOX-7 slot of ${name}: another token is refused 409 naming the pending approval, the same token replaces, another subject opens its own`, async (t) => {
    const w = await approveWorld(t);
    const a = w.propose(first, 'ctl-1');
    assert.deepEqual([a.status, a.revision, a.replaced], ['pending', 1, false]);
    assert.throws(() => w.propose(second, 'ctl-2'), slotTaken(a.approval_id));
    const replaced = w.propose(second, 'ctl-1');
    assert.deepEqual([replaced.approval_id, replaced.revision, replaced.replaced, replaced.slot], [a.approval_id, 2, true, a.slot]);
    const b = w.propose(other, 'ctl-2');
    assert.notEqual(b.slot, a.slot);
    assert.equal(b.replaced, false);
  });
}

test('KBOX-7 approver_remove sits in the slot of the approver it names, and removing the last approver is refused rejected', async (t) => {
  const w = await approveWorld(t);
  assert.throws(() => w.propose({ kind: 'approver_remove', approver_id: w.ownerId }), (e: unknown) => e instanceof ApiError && e.code === 'rejected');
  const second = await w.addApprover();
  const a = w.propose({ kind: 'approver_remove', approver_id: second.approverId }, 'ctl-1');
  assert.throws(() => w.propose({ kind: 'approver_remove', approver_id: second.approverId }, 'ctl-2'), slotTaken(a.approval_id));
  const b = w.propose({ kind: 'approver_remove', approver_id: w.ownerId }, 'ctl-2');
  assert.notEqual(b.slot, a.slot);
});

test('KBOX-7 five add_key proposals with different names on one platform give one pending approval and one push', async (t) => {
  const w = await approveWorld(t);
  const before = w.push.sent.length;
  const ids = new Set<string>();
  for (const name of ['A', 'B', 'C', 'D', 'E']) ids.add(w.propose({ kind: 'add_key', platform: 'openai', name, projects: ['p'], scope: { items: [] } }, 'ctl-1').approval_id);
  assert.equal(ids.size, 1);
  assert.equal((await w.queue()).filter((q) => q.kind === 'add_key').length, 1);
  assert.equal(w.push.sent.length - before, 1);
  assert.equal((await w.queue())[0]?.lines[0], 'Add the openai key E for p.', 'the pending content is the last one');
});

test('KBOX-7 50 unauthenticated enrol requests from 50 addresses give 50 proposals and one push that says only how many wait', async (t) => {
  const w = await approveWorld(t);
  const before = w.push.sent.length;
  for (let i = 0; i < 50; i += 1) {
    const reply = await w.call('/api/enrol', { json: { token_sha256: i.toString(16).padStart(64, '0'), label: `ws-${i}`, scope: 'relay' }, ip: `198.51.100.${i + 1}` });
    assert.equal(reply.status, 202, reply.body);
  }
  assert.equal((await w.queue()).filter((q) => q.kind === 'enrol').length, 50);
  const pushes = w.push.sent.slice(before);
  assert.deepEqual(pushes, [{ title: 'Machines wait to be enrolled', kind: 'enrol', count: 1 }]);
  await w.call('/api/enrol', { json: { token_sha256: 'f'.repeat(64), label: 'ws-late', scope: 'relay' }, ip: '198.51.100.200' });
  assert.deepEqual(w.push.sent.slice(before + 1), [{ title: 'Machines wait to be enrolled', kind: 'enrol', count: 51 }], 'once the queue was seen, the next enrol pushes again with the count');
});

test('KBOX-7 a second token gets 409 and the same token replaces with no second push; the replaced revision voids the earlier assertion', async (t) => {
  const w = await approveWorld(t);
  const before = w.push.sent.length;
  const a = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  const [rendered] = await w.queue();
  assert.ok(rendered);
  const early = w.proofFor(rendered);
  assert.throws(() => w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-2'), slotTaken(a.approval_id));
  w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  assert.equal(w.push.sent.length - before, 1, 'one push for the slot');
  const refused = await w.decide(a.approval_id, 'approve', early);
  assert.equal(refused.status, 403, 'the assertion over revision 1 does not apply to revision 2, even with the same digest');
  const [fresh] = await w.queue();
  assert.ok(fresh);
  assert.equal(fresh.revision, 2);
  assert.equal((await w.decide(a.approval_id, 'approve', w.proofFor(fresh))).status, 200);
});

test('KBOX-7 a box rotation takes over a slot a token squats, and the squatter\'s pending assertion no longer applies', async (t) => {
  const w = await approveWorld(t);
  const squat = w.propose({ kind: 'rotate_key', keyref: 'k1' }, 'ctl-1');
  const [rendered] = await w.queue();
  assert.ok(rendered);
  const squatterProof = w.proofFor(rendered);
  const box = w.propose({ kind: 'rotate_key', keyref: 'k1' }, 'box');
  assert.deepEqual([box.approval_id, box.revision, box.replaced], [squat.approval_id, 2, true]);
  assert.throws(() => w.propose({ kind: 'rotate_key', keyref: 'k1' }, 'ctl-1'), slotTaken(squat.approval_id), 'the squatter cannot take it back');
  assert.equal((await w.decide(squat.approval_id, 'approve', squatterProof)).status, 403);
  const [item] = await w.queue();
  assert.ok(item);
  assert.ok(item.lines.includes('Asked for by the box itself (a schedule or a platform expiry).'));
});

test('KBOX-7 a pending proposal still holds its slot at 14 days minus 1 ms and has expired at 14 days plus 1 ms', async (t) => {
  for (const [after, held] of [[14 * DAY - 1, true], [14 * DAY + 1, false]] as const) {
    const w = await approveWorld(t);
    const a = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
    w.clock.advance(after);
    if (held) {
      assert.throws(() => w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-2'), slotTaken(a.approval_id));
    } else {
      const b = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-2');
      assert.notEqual(b.approval_id, a.approval_id);
      const decided = w.parts.events.after(0).filter((e) => e.kind === 'approval.decided');
      assert.deepEqual(decided.map((e) => e.data), [{ approval_id: a.approval_id, decision: 'expired' }]);
    }
  }
});

test('KBOX-7 a denial frees the slot; the denied approval cannot then be approved', async (t) => {
  const w = await approveWorld(t);
  const a = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  const [item] = await w.queue();
  assert.ok(item);
  assert.equal((await w.decide(a.approval_id, 'deny', w.proofFor(item))).status, 200);
  const b = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-2');
  assert.notEqual(b.approval_id, a.approval_id);
  assert.equal((await w.decide(a.approval_id, 'approve', w.proofFor(item))).status, 409);
});

test('KBOX-7 no route takes a list of actions: an array action, an array body or an actions member is refused', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const one = { kind: 'demote', keyref: 'k1' };
  for (const body of [{ action: [one, { kind: 'demote', keyref: 'k2' }] }, [{ action: one }, { action: one }], { actions: [one] }, { action: one, more: [one] }]) {
    const reply = await w.call('/api/proposals', { json: body, token });
    assert.equal(reply.status, 400, JSON.stringify(body));
  }
  assert.equal((await w.queue()).length, 0);
});

test('KBOX-7 a canary in a requester reason reaches no push payload; the page shows it apart', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const c = canary();
  const reason = { agent: 'claude', text: `because ${Buffer.from(c.bytes).toString('base64url')}` };
  const reply = await w.call('/api/proposals', { json: { action: { kind: 'demote', keyref: 'k1' }, reason }, token });
  assert.equal(reply.status, 201, reply.body);
  c.assertAbsent({ push: JSON.stringify(w.push.sent) });
  const [item] = await w.queue();
  assert.equal(item?.lines.at(-1), `Reason given by ctl-1/claude (not checked): ${reason.text}`);
});

test('KBOX-7 a proposal the vetting port refuses (a mustDeny match) is rejected and never reaches the phone', async (t) => {
  const w = await approveWorld(t, { vet: (a) => (a.kind === 'set_allow_rules' ? 'rejected' : 'ok') });
  const token = w.token('ctl-1', 'control');
  const before = w.push.sent.length;
  const reply = await w.call('/api/proposals', { json: { action: { kind: 'set_allow_rules', keyref: 'k1', rules: [{ op: 'create_key', params: {} }] } }, token });
  assert.equal(reply.status, 422);
  assert.deepEqual(w.push.sent.slice(before).map((p) => p.kind), ['new_network'], 'only the first-use push of the token, no approval push');
  assert.equal((await w.queue()).length, 0);
});
