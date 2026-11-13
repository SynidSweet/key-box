// KBOX-58: a verifier may state which keys its call can test (`appliesTo`), and an issuer the shape of a key of another kind (`shapeFor`).
// Every caller asks `verifierFor`; a verifier asked about a key it cannot judge must never confirm a live key dead. The fixture platform
// `twokind` has a recording verifier that applies to keys whose scope items include `acct`, and an issuer that makes `acct` and `root`
// master and gives `acct` keys their own shape.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Issuer, IssuerCapabilities, KeyListing, KeyLister, Verifier } from '../src/ports/issuer.ts';
import type { KeyClass, KeyShape, Scope } from '../src/ports/types.ts';
import type { PlatformKit, PlatformSource } from '../src/shell/rotation-ports.ts';
import { revokeAndConfirm } from '../src/shell/revoke-confirm.ts';
import { bytesOf, lent } from './kit/index.ts';
import { HOUR, MINUTE, rotationWorld } from './support/rotation-world.ts';
import type { RotationWorld } from './support/rotation-world.ts';
import { routesWorld } from './support/routes-world.ts';
import type { PasteView, RoutesWorld } from './support/routes-world.ts';

const DAY = 24 * HOUR;
const TWOKIND = 'twokind';
const TWOPASTE = 'twopaste';
const ACCT_SHAPE: KeyShape = { prefix: 'ac-', alphabet: 'hex', coreLength: { min: 40, max: 40 }, random: true };
const TK_SHAPE: KeyShape = { prefix: 'tk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };
/** A value of the `acct` shape, and one of the platform's default shape. */
const acctValue = (c: string): string => `ac-${c.repeat(40)}`;
const tkValue = (c: string): string => `tk-${c.repeat(32)}`;

const itemsOf = (scope: Scope): readonly string[] => {
  const items = scope['items'];
  return typeof items === 'string' ? [items] : (items ?? []);
};

/** How the fixture verifier states its reach: `acct` (applies to `acct` keys), none at all (`absent`), never, or a predicate that throws. */
type ReachMode = 'acct' | 'absent' | 'never' | 'throws';

const appliesToOf = (mode: () => ReachMode) => (scope: Scope): boolean => {
  switch (mode()) {
    case 'throws':
      throw new Error('the reach of this key is unknown');
    case 'never':
      return false;
    case 'acct':
    case 'absent':
      return itemsOf(scope).includes('acct');
  }
};

/** A verifier whose `appliesTo` follows `mode` at each call; with the mode `absent` as the kit is built, it has none. */
const reachingVerifier = (mode: () => ReachMode, verify: Verifier['verify']): Verifier => (mode() === 'absent' ? { verify } : { verify, appliesTo: appliesToOf(mode) });

// --- the routes: proposal, paste, schedule -----------------------------------------------------------------------------------

interface TwoKind {
  mode: ReachMode;
  /** The values the verifier answers ok for. */
  readonly accepted: Set<string>;
  /** The values the verifier was asked about, in order. */
  readonly asked: string[];
  /** The hint of every verifier call, in order. */
  readonly hints: (string | undefined)[];
}

const twoKindClass = (scope: Scope): KeyClass => {
  const items = itemsOf(scope);
  return items.includes('acct') || items.includes('root') ? 'master' : items.includes('admin') ? 'admin' : 'ordinary';
};

/** The two fixture kits as they are now (the source builds them at each ask, so a changed mode is what the next caller sees). */
function twoKindKits(state: TwoKind): { readonly issuerKit: PlatformKit; readonly pasteKit: PlatformKit } {
  const verifier = reachingVerifier(
    () => state.mode,
    async (key, target) => {
      const value = Buffer.from(await bytesOf(key)).toString('utf8');
      state.asked.push(value);
      state.hints.push(target.hint);
      return state.accepted.has(value) ? 'ok' : 'rejected';
    },
  );
  const issuer: Issuer = {
    platform: TWOKIND,
    capabilities: (): IssuerCapabilities => ({
      create: 'api',
      revoke: 'api',
      selfRotate: false,
      overlap: true,
      set: 'none',
      revealOnce: false,
      scopeSchema: { fields: ['items'] },
      shape: TK_SHAPE,
      classify: twoKindClass,
      shapeFor: (scope) => (itemsOf(scope).includes('acct') ? ACCT_SHAPE : undefined),
    }),
    issue: () => Promise.reject(new Error('this fixture issues nothing')),
    revoke: () => Promise.resolve('absent'),
  };
  const hints = { verifyHints: ['projects'], keyPageUrl: 'https://twokind.example/keys' } as const;
  return {
    issuerKit: { issuer, verifier, ...hints },
    // A paste-only entry of the same reach: `admin` is admin, anything else ordinary.
    pasteKit: { verifier, shape: TK_SHAPE, classify: (scope) => (itemsOf(scope).includes('admin') ? 'admin' : 'ordinary'), ...hints },
  };
}

async function twoKindWorld(t: Parameters<typeof routesWorld>[0], mode: ReachMode): Promise<{ readonly w: RoutesWorld; readonly state: TwoKind }> {
  const state: TwoKind = { mode, accepted: new Set(), asked: [], hints: [] };
  const w = await routesWorld(t, {
    source: (real): PlatformSource => ({ ...real, platform: (id) => (id === TWOKIND ? twoKindKits(state).issuerKit : id === TWOPASTE ? twoKindKits(state).pasteKit : real.platform(id)) }),
  });
  return { w, state };
}

const keyBody = (items: readonly string[], name: string, platform = TWOKIND): object => ({ platform, name, projects: ['shop'], scope: { items } });
const errorOf = (reply: { json(): unknown }): readonly [string, string | undefined] => {
  const { error } = reply.json() as { error: { code: string; detail?: { code?: string } } };
  return [error.code, error.detail?.code];
};
const tasks = (w: RoutesWorld): { paste_id: string; status: string }[] => w.parts.db.prepare('SELECT paste_id, status FROM paste_tasks ORDER BY rowid').all() as unknown as { paste_id: string; status: string }[];
const statusOfTask = (w: RoutesWorld, id: string): string | undefined => tasks(w).find((r) => r.paste_id === id)?.status;
const statusOfKey = (w: RoutesWorld, keyref: string): string | undefined => w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.status;

async function openTask(w: RoutesWorld, items: readonly string[], name: string, platform = TWOKIND): Promise<string> {
  const reply = await w.api('/api/keys', { json: keyBody(items, name, platform) });
  assert.equal(reply.status, 202, reply.body);
  return (reply.json() as { paste_task_id: string }).paste_task_id;
}
async function render(w: RoutesWorld, id: string): Promise<{ readonly view: PasteView; readonly cookie: string }> {
  const cookie = await w.view();
  const reply = await w.call(`/p/${id}`, { cookie });
  assert.equal(reply.status, 200, reply.body);
  return { view: reply.json() as PasteView, cookie };
}
async function paste(w: RoutesWorld, id: string, value: string, hint?: string) {
  const { view, cookie } = await render(w, id);
  return w.call(`/p/${id}`, { json: { value, proof: w.pasteProof(view), ...(hint === undefined ? {} : { verify_hint: hint }) }, cookie });
}

test('KBOX-58 KBOX-34 a master result opens a paste task only where the verifier applies to its scope: acct is 202, root is rejected no_verifier with nothing opened; control: without appliesTo root opens one', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const acct = await w.api('/api/keys', { json: keyBody(['acct'], 'ACCT_TOKEN') });
  assert.equal(acct.status, 202, acct.body);
  assert.equal((acct.json() as { class: string }).class, 'master');
  const root = await w.api('/api/keys', { json: keyBody(['root'], 'ROOT_TOKEN') });
  assert.deepEqual([root.status, ...errorOf(root)], [422, 'rejected', 'no_verifier']);
  assert.equal(tasks(w).length, 1, 'only the acct task was opened');
  state.mode = 'absent';
  const control = await w.api('/api/keys', { json: keyBody(['root'], 'ROOT_TOKEN') });
  assert.equal(control.status, 202, 'a verifier that states no reach applies to every key');
});

test('KBOX-58 KBOX-34 an admin add_key that would open a paste task asks the verifier at proposal: none applies is rejected no_verifier before anything is opened or pushed', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const refused = await w.api('/api/keys', { json: keyBody(['admin'], 'ADMIN_KEY', TWOPASTE) });
  assert.deepEqual([refused.status, ...errorOf(refused)], [422, 'rejected', 'no_verifier']);
  assert.equal(tasks(w).length, 0);
  assert.deepEqual(w.push.sent.filter((p) => p.kind === 'add_key'), [], 'the owner is never asked');
  assert.equal((await w.api('/api/keys', { json: keyBody(['admin', 'acct'], 'ADMIN_KEY', TWOPASTE) })).status, 202, 'one the verifier applies to opens');
  state.mode = 'absent';
  assert.equal((await w.api('/api/keys', { json: keyBody(['admin'], 'OTHER_KEY', TWOPASTE) })).status, 202, 'control: without appliesTo it opens');
});

/** A stored `root` master of twokind, entered by paste while the verifier stated no reach. */
async function storedRoot(w: RoutesWorld, state: TwoKind): Promise<string> {
  state.mode = 'absent';
  const id = await openTask(w, ['root'], 'ROOT_TOKEN');
  state.accepted.add(tkValue('1'));
  const stored = await paste(w, id, tkValue('1'));
  assert.equal(stored.status, 201, stored.body);
  return `${TWOKIND}/shop/ROOT_TOKEN`;
}

test('KBOX-58 KBOX-34 POST /api/rotations of a stored master the verifier does not apply to is rejected no_verifier: no paste task, the key status unchanged', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const keyref = await storedRoot(w, state);
  state.mode = 'acct';
  const before = tasks(w);
  const reply = await w.api('/api/rotations', { json: { keyref } });
  assert.deepEqual([reply.status, ...errorOf(reply)], [422, 'rejected', 'no_verifier']);
  assert.deepEqual(tasks(w), before, 'no task opened');
  assert.equal(statusOfKey(w, keyref), 'works', 'the refusal leaves the status as it was');
});

test('KBOX-58 KBOX-34 the schedule skips a due master the verifier does not apply to with one box.notice no_verifier "rotation skipped" across ticks and opens nothing; control: with a verifier that applies it opens the paste task', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const keyref = await storedRoot(w, state);
  state.mode = 'acct';
  const before = tasks(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  w.rotation.tick();
  assert.deepEqual(tasks(w), before);
  assert.equal(statusOfKey(w, keyref), 'works');
  const notices = w.parts.events.after(0).filter((e) => e.kind === 'box.notice' && e.data['text'] === 'rotation skipped');
  assert.deepEqual(notices.map((e) => e.data['code']), ['no_verifier'], 'one notice per key and code');
  state.mode = 'absent';
  w.rotation.tick();
  assert.equal(tasks(w).filter((r) => r.status === 'pending').length, 1);
  assert.equal(statusOfKey(w, keyref), 'awaiting_paste');
});

test('KBOX-58 KBOX-12 a paste whose key the verifier stopped applying to while the task waited fails the task no_verifier: the verifier never sees the value and nothing is stored', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const id = await openTask(w, ['acct'], 'ACCT_TOKEN');
  state.accepted.add(acctValue('2'));
  state.mode = 'never';
  const reply = await paste(w, id, acctValue('2'));
  assert.deepEqual([reply.status, ...errorOf(reply)], [422, 'rejected', 'no_verifier']);
  assert.equal(statusOfTask(w, id), 'failed');
  assert.deepEqual(state.asked, []);
  assert.equal(w.rotation.store.key(`${TWOKIND}/shop/ACCT_TOKEN`), undefined);
});

test('KBOX-58 KBOX-12 a verifier whose appliesTo throws counts as applying, never as none: the task opens, the paste is refused verifier_unreachable, the verifier is not called and nothing is stored', async (t) => {
  const { w, state } = await twoKindWorld(t, 'throws');
  const id = await openTask(w, ['acct'], 'ACCT_TOKEN');
  state.accepted.add(acctValue('3'));
  const reply = await paste(w, id, acctValue('3'));
  assert.deepEqual([reply.status, ...errorOf(reply)], [422, 'rejected', 'verifier_unreachable']);
  assert.deepEqual(state.asked, []);
  assert.equal(w.rotation.store.key(`${TWOKIND}/shop/ACCT_TOKEN`), undefined);
});

test('KBOX-58 KBOX-12 an acct paste is checked against the key\'s own shape: a value of the default shape is bad_shape, one of ACCT_SHAPE is stored', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const id = await openTask(w, ['acct'], 'ACCT_TOKEN');
  state.accepted.add(tkValue('4'));
  state.accepted.add(acctValue('4'));
  const wrong = await paste(w, id, tkValue('4'));
  assert.deepEqual([wrong.status, ...errorOf(wrong)], [422, 'rejected', 'bad_shape']);
  assert.equal(state.asked.length, 0, 'a value of the wrong shape never reaches the verifier');
  const right = await paste(w, id, acctValue('4'));
  assert.equal(right.status, 201, right.body);
  assert.ok(state.asked.includes(acctValue('4')));
});

test('KBOX-58 KBOX-40 the hint choice is offered only for a key the verifier applies to, and the chosen hint goes to that verifier', async (t) => {
  const { w, state } = await twoKindWorld(t, 'acct');
  const acct = await openTask(w, ['acct'], 'ACCT_TOKEN');
  assert.deepEqual((await render(w, acct)).view.verify_hints, ['projects']);
  state.accepted.add(acctValue('5'));
  assert.equal((await paste(w, acct, acctValue('5'), 'projects')).status, 201);
  assert.deepEqual(state.hints, ['projects', 'projects', 'projects'], 'the paste check, step 5 and step 8 each carry the chosen hint');
  const waiting = await openTask(w, ['acct'], 'OTHER_TOKEN');
  state.mode = 'never';
  assert.equal((await render(w, waiting)).view.verify_hints, undefined, 'no choice for a key no verifier applies to');
});

// --- the run: steps 5, 8 and 10, reconcile ---------------------------------------------------------------------------------

interface Reach {
  mode: ReachMode;
  /** The verifier answers unreachable. */
  unreachable: boolean;
  /** Calls that reached the verifier's `verify`. */
  calls: number;
}

/** The rotation world's platform with its verifier given a reach; the verifier records every call. */
const reaching = (r: Reach) => (real: PlatformSource): PlatformSource => ({
  ...real,
  platform: (id) => {
    const kit = real.platform(id);
    const base = kit?.verifier;
    if (kit === undefined || base === undefined) return kit;
    const verify: Verifier['verify'] = (key, target) => {
      r.calls += 1;
      return r.unreachable ? Promise.resolve('unreachable') : base.verify(key, target);
    };
    return { ...kit, verifier: reachingVerifier(() => r.mode, verify) };
  },
});

async function seededWith(t: Parameters<typeof rotationWorld>[0], items: readonly string[], mode: ReachMode): Promise<{ readonly w: RotationWorld; readonly r: Reach; readonly keyref: string }> {
  const r: Reach = { mode, unreachable: false, calls: 0 };
  const w = await rotationWorld(t, { source: reaching(r) });
  const keyref = await w.seedKey({ scopeItems: items });
  return { w, r, keyref };
}
/** Starts a rotation and lets it reach the grace of the old generation. */
async function toGrace(w: RotationWorld, keyref: string): Promise<void> {
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  w.seenAt.listAt.length = 0;
}
const endGrace = async (w: RotationWorld): Promise<void> => {
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
};

test('KBOX-58 KBOX-51 steps 5 and 8 pass for an issued key the verifier does not apply to, with no verifier call; control: without appliesTo both steps call it', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['read'], 'acct');
  assert.equal(w.store.gen(keyref, 1)?.status, 'current');
  assert.equal(r.calls, 0);
  const control = await seededWith(t, ['read'], 'absent');
  assert.equal(control.w.store.gen(control.keyref, 1)?.status, 'current');
  assert.equal(control.r.calls, 2, 'step 5 and step 8');
});

test('KBOX-58 KBOX-51 negative control: step 10 of an acct key whose verifier is unreachable stays in grace with one notice, and the lister is never asked though it would show the key gone', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['acct'], 'acct');
  await toGrace(w, keyref);
  r.unreachable = true;
  await endGrace(w);
  w.clock.advance(HOUR);
  await w.orch.idle();
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  assert.deepEqual(w.seenAt.listAt, []);
  assert.equal(w.events('rotation.old_key_still_on').length, 1);
});

test('KBOX-58 KBOX-51 a verifier whose appliesTo throws at step 10 counts as applying, never as none: the old key stays in grace, the lister is not asked and the verifier is not called', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['read'], 'acct');
  await toGrace(w, keyref);
  r.mode = 'throws';
  await endGrace(w);
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  assert.deepEqual(w.seenAt.listAt, []);
  assert.equal(r.calls, 0);
});

test('KBOX-58 KBOX-51 reconcile confirms the orphan of a key the verifier does not apply to by the lister, with no verifier call', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['read'], 'acct');
  w.checkpoints.arm('issued');
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal((await w.live()).length, 2, 'the orphan beside the old key');
  w.checkpoints.crashAt = undefined;
  w.build();
  await w.reconciler.run();
  assert.equal(w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.orphan_revoked').length, 1);
  await w.settle();
  assert.equal(r.calls, 0);
});

test('KBOX-58 KBOX-51 revokeAndConfirm of a pasted generation (no id) the verifier does not apply to is not proof: false, with no verifier and no lister call', async () => {
  let verifies = 0;
  let listings = 0;
  // A verifier asked about a key it cannot judge answers rejected: that is the false proof of death this rule closes.
  const verifier = reachingVerifier(() => 'acct', () => {
    verifies += 1;
    return Promise.resolve('rejected');
  });
  const lister: KeyLister = {
    list: () => Promise.resolve([]),
    listAt: (at): Promise<KeyListing> => {
      listings += 1;
      return Promise.resolve({ complete: true, at, keys: [] });
    },
  };
  const master = lent(Buffer.from('master'), 'master:1');
  const value = lent(Buffer.from(tkValue('6')), 'old:1');
  const dead = await revokeAndConfirm({ kit: { verifier, lister }, platform: TWOKIND, id: null, at: {}, value, master, scopeItems: ['root'] });
  assert.equal(dead, false);
  assert.deepEqual([verifies, listings], [0, 0]);
  assert.equal(await revokeAndConfirm({ kit: { verifier, lister }, platform: TWOKIND, id: null, at: {}, value, master, scopeItems: ['acct'] }), true, 'positive control: the verifier that applies decides');
});

// --- re-pins of the retired step-10 listing tests (revoke-proof, S-795 unit retire-revoke): the listing ends the run, gen 1 stays grace --

test('KBOX-58 KBOX-51 step 10 of an issued key the verifier does not apply to ends on a complete listing without the id, with no verifier call; an incomplete listing keeps the run at step 10; gen 1 stays grace', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['read'], 'acct');
  await toGrace(w, keyref);
  w.faults.listingIncomplete = true;
  await endGrace(w);
  assert.equal(w.store.activeRunOf(keyref)?.state, 'revoking', 'absence from an incomplete listing proves nothing');
  w.faults.listingIncomplete = false;
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(w.store.activeRunOf(keyref), undefined, 'the run is done');
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  assert.ok(w.seenAt.listAt.length > 0);
  assert.equal(r.calls, 0, 'the verifier that does not apply was never asked');
});

test('KBOX-58 KBOX-51 step 10 of an acct key whose old value the vault no longer holds falls to the lister: a complete listing without the issued id ends the run, gen 1 grace', async (t) => {
  const { w, r, keyref } = await seededWith(t, ['acct'], 'acct');
  await toGrace(w, keyref);
  const callsBefore = r.calls;
  w.parts.vault.retire(keyref, 1);
  await endGrace(w);
  assert.equal(w.store.activeRunOf(keyref), undefined, 'the run is done');
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  assert.ok(w.seenAt.listAt.length > 0);
  assert.equal(r.calls, callsBefore, 'no value, so the verifier is not asked');
});
