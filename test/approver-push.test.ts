// KBOX-22, KBOX-20, KBOX-53: a Web Push subscription belongs to the approver who registered it. When an approver is removed, or
// recovery replaces the approvers, their subscriptions go with them, so a removed phone gets no more notices. Real push over the real
// private store, through the real setup, add, remove and recovery routes.
import assert from 'node:assert/strict';
import { createECDH } from 'node:crypto';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { PushSubscriptionInput } from '../src/ports/push.ts';
import { createPush } from '../src/shell/push.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';
import { seededRandom, tempDir } from './kit/index.ts';
import { approveWorld } from './support/approve-world.ts';
import type { World, WorldOptions } from './support/approve-world.ts';

const rng = seededRandom(5);
/** A well-formed subscription on a push service host, with its own P-256 key and auth secret. */
function subscription(name: string): PushSubscriptionInput {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(rng.bytes(32)));
  return { endpoint: `https://fcm.googleapis.com/fcm/send/${name}`, p256dh: Buffer.from(ecdh.getPublicKey()).toString('base64url'), auth: Buffer.from(rng.bytes(16)).toString('base64url') };
}
const realPush: NonNullable<WorldOptions['pushFor']> = ({ store, audit, clock, random }) =>
  createPush({ store, transport: { post: () => Promise.resolve(201) }, scheduler: clock, clock, random, audit, subject: 'mailto:box@example.test' });

const endpointsOf = (w: World): string[] => w.priv.listPushSubscriptions().map((s) => s.endpoint.slice(s.endpoint.lastIndexOf('/') + 1)).sort();

async function twoApprovers(t: TestContext): Promise<{ w: World; second: string }> {
  const w = await approveWorld(t, { pushFor: realPush, ownerSubscription: subscription('owner-phone') });
  const added = await w.addApprover(subscription('second-phone'));
  assert.deepEqual(endpointsOf(w), ['owner-phone', 'second-phone'], 'control: both phones are subscribed');
  return { w, second: added.approverId };
}

test('KBOX-53 removing an approver removes that approver\'s push subscriptions and no one else\'s', async (t) => {
  const { w, second } = await twoApprovers(t);
  const removal = w.propose({ kind: 'approver_remove', approver_id: second }, 'box');
  assert.ok(removal);
  const item = (await w.queue()).find((q) => q.kind === 'approver_remove');
  assert.ok(item);
  const decided = await w.decide(item.approval_id, 'approve', w.proofFor(item));
  assert.equal(decided.status, 200, decided.body);
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId]);
  assert.deepEqual(endpointsOf(w), ['owner-phone'], 'the removed phone no longer gets notices');
});

test('KBOX-20 recovery removes every push subscription of the replaced approvers, and any that no approver owns, and keeps the new approver\'s', async (t) => {
  const { w } = await twoApprovers(t);
  w.priv.addPushSubscription({ endpoint: 'https://fcm.googleapis.com/fcm/send/ownerless', p256dh: 'AAAA', auth: 'AAAA' });
  assert.deepEqual(endpointsOf(w), ['owner-phone', 'ownerless', 'second-phone']);
  const recovered = await w.recover(subscription('recovery-phone'));
  assert.deepEqual(w.core.approvers.ids(), [recovered.approverId]);
  assert.deepEqual(endpointsOf(w), ['recovery-phone']);
});

test('KBOX-20 a recovery whose new approver brings no subscription leaves no subscription behind', async (t) => {
  const { w } = await twoApprovers(t);
  await w.recover();
  assert.deepEqual(endpointsOf(w), []);
});

test('KBOX-22 a subscription is stored under its approver: forgetting one approver and retaining a set act on the owner column, and an older private.db without it is migrated at open', async (t) => {
  const dir = await tempDir(t);
  const path = join(dir, 'private.db');
  const old = new DatabaseSync(path);
  old.exec('CREATE TABLE push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL) STRICT');
  old.exec("INSERT INTO push_subscriptions VALUES ('https://fcm.googleapis.com/fcm/send/legacy', 'AAAA', 'AAAA')");
  old.close();
  const store = openPrivateDatabase(path);
  t.after(() => store.close());
  const row = (name: string): { endpoint: string; p256dh: string; auth: string } => ({ endpoint: `https://fcm.googleapis.com/fcm/send/${name}`, p256dh: 'AAAA', auth: 'AAAA' });
  store.addPushSubscription(row('a1'), 'ap-a');
  store.addPushSubscription(row('a2'), 'ap-a');
  store.addPushSubscription(row('b1'), 'ap-b');
  const names = (): string[] => store.listPushSubscriptions().map((s) => s.endpoint.slice(s.endpoint.lastIndexOf('/') + 1)).sort();
  assert.deepEqual(names(), ['a1', 'a2', 'b1'], 'the legacy ownerless row was deleted at migration (no key box exists in the wild, so none is real)');
  store.removePushSubscriptionsOf('ap-a');
  assert.deepEqual(names(), ['b1'], 'only that approver\'s rows go');
  store.addPushSubscription(row('c1'), 'ap-c');
  store.retainPushSubscriptionsOf(['ap-c']);
  assert.deepEqual(names(), ['c1'], 'a retained set keeps only its own rows');
  store.retainPushSubscriptionsOf([]);
  assert.deepEqual(names(), []);
  store.addPushSubscription(row('c1'), 'ap-c');
  store.addPushSubscription(row('c1'), 'ap-d');
  assert.deepEqual(names(), ['c1'], 'one endpoint is one row: the last approver to register it owns it');
  store.removePushSubscriptionsOf('ap-c');
  assert.deepEqual(names(), ['c1']);
});
