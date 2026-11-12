// The rotation shell's view of the platform registry (KBOX-23, KBOX-51, KBOX-57): the adapters of a registered platform, nothing for an
// unregistered one, and the platform's master key for a key: chosen by platform and stored location (plus the entry's masterItems), never by
// `projects` or row order, as a typed result.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { KeyClass, KeyLocation, Scope } from '../src/ports/types.ts';
import { openCore } from '../src/shell/core.ts';
import { refusingAdapterHttp } from '../src/ports/http.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { issuerWith } from './fakes/platform-entry.ts';
import { TimedClock, bytesOf, seededRandom, tempDir } from './kit/index.ts';

const masterRow = (keyref: string, platform: string, gen: number): KeyRow => ({
  keyref,
  platform,
  name: 'MASTER_TOKEN',
  projects: [],
  class: 'master',
  status: 'works',
  gen_current: gen,
  schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

/**
 * The fixture platforms' classification (the KBOX-15 table, written here): `master` makes a master anywhere; `project-token` is master with
 * no project and ordinary at one (Vercel's project token: master only by the floor); anything else is ordinary.
 */
const classifyFixture = (scope: Scope, at: KeyLocation): KeyClass => {
  const items = scope['items'];
  const list = Array.isArray(items) ? items : [];
  if (list.includes('master')) return 'master';
  if (list.includes('project-token')) return at.project === undefined ? 'master' : 'ordinary';
  return 'ordinary';
};

/** `masterItems`: the `fake` entry's scope-item prefixes that decide authority (KBOX-57); none by default. */
async function world(t: TestContext, masterItems: readonly string[] = []) {
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(3);
  const parts = openCore({ stateDir: join(await tempDir(t), 'state'), clock, scheduler: clock, random });
  t.after(() => parts.close());
  const platform = new FakePlatformWorld(random);
  const entry: PlatformEntry = { id: 'fake', issuer: issuerWith(platform.issuer, { classify: classifyFixture }), lister: platform.lister, unverified: [], masterItems };
  const other: PlatformEntry = { id: 'other', issuer: issuerWith(platform.issuer, { classify: classifyFixture }), lister: platform.lister, unverified: [] };
  const store = createRotationStore(parts.db, clock, parts.hub);
  const source = createPlatformSource({ registry: [entry, other], meta: parts.meta, vault: parts.vault, keyInfo: (keyref) => store.keyInfo(keyref) });
  return { parts, store, clock, entry, source };
}
type World = Awaited<ReturnType<typeof world>>;

interface MasterSpec {
  readonly platform?: string;
  readonly at?: KeyLocation;
  readonly items?: readonly string[];
  readonly projects?: readonly string[];
  readonly gen?: number;
  /** The text of the row's current generation in the vault; null: the vault holds none (a failed create left the row). */
  readonly value?: string | null;
  readonly status?: KeyRow['status'];
}

/** A master key row as the box stores one: the `keys` row, its stored scope and location (`rotation_keys`) and its current value. */
function putMaster(w: World, keyref: string, spec: MasterSpec = {}): void {
  const gen = spec.gen ?? 1;
  if (spec.value !== null) w.parts.vault.put(keyref, gen, Buffer.from(spec.value ?? `${keyref}-value`));
  w.parts.meta.putKey({ ...masterRow(keyref, spec.platform ?? 'fake', gen), projects: [...(spec.projects ?? [])], status: spec.status ?? 'works' });
  w.store.putKeyInfo(keyref, { scopeItems: spec.items ?? ['master'], location: spec.at ?? {}, rotatedAt: w.clock.now(), markAdmin: false });
}

/** The chosen master's text, or the refusal code: the two never overlap in these fixtures. */
async function pick(w: World, platform: string, at: KeyLocation, items: readonly string[] = []): Promise<string> {
  const result = w.source.master(platform, at, items);
  return result.ok ? Buffer.from(await bytesOf(result.value)).toString('utf8') : result.code;
}

test('KBOX-23 a registered platform gives its issuer and lister, an unregistered one gives nothing', async (t) => {
  const w = await world(t);
  assert.equal(w.source.platform('fake')?.issuer, w.entry.issuer);
  assert.equal(w.source.platform('fake')?.lister, w.entry.lister);
  assert.equal(w.source.platform('other-unregistered'), undefined);
});

test('KBOX-51 the master key of a platform is the current generation of its master key row, lent from the vault, never another platform\'s', async (t) => {
  const w = await world(t);
  w.parts.vault.put('fake/master', 1, Buffer.from('old-master'));
  putMaster(w, 'fake/master', { gen: 2, value: 'current-master' });
  putMaster(w, 'other/master', { platform: 'other', value: 'other-master' });
  assert.equal(await pick(w, 'fake', {}), 'current-master');
  assert.equal(await pick(w, 'other', {}), 'other-master');
});

test('KBOX-51 a platform with no master key row, or one that is not master class, has no master to lend: a fixed error, no value', async (t) => {
  const w = await world(t);
  assert.deepEqual(w.source.master('fake', {}, []), { ok: false, code: 'no_master' });
  w.parts.vault.put('fake/admin', 1, Buffer.from('an-admin-value'));
  w.parts.meta.putKey({ ...masterRow('fake/admin', 'fake', 1), class: 'admin' });
  w.store.putKeyInfo('fake/admin', { scopeItems: ['master'], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
  const result = w.source.master('fake', {}, []);
  assert.deepEqual(result, { ok: false, code: 'no_master' });
  assert.equal('value' in result, false, 'no value');
  assert.ok(!JSON.stringify(result).includes('an-admin-value'));
});

// --- what makes a master row serve a key (KBOX-57) -------------------------------------------------------------------------------

test('KBOX-57 negative control: two master rows that differ only in projects are master_ambiguous for every key, never told apart by projects', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/shop/MASTER', { projects: ['shop'] });
  putMaster(w, 'fake/other/MASTER', { projects: ['other'] });
  assert.equal(await pick(w, 'fake', {}), 'master_ambiguous');
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'master_ambiguous', 'a key located at shop is not given the row whose projects say shop');
});

test('KBOX-57 negative control: a master whose projects overlap the key\'s but whose location does not cover it is not chosen', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/shop/MASTER', { at: { project: 'other' }, projects: ['shop'], value: 'elsewhere-master' });
  putMaster(w, 'fake/team/MASTER', { value: 'team-master' });
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'team-master');
});

test('KBOX-57 a stored location covers a key only when it names no field the key lacks or names differently; an empty one covers every place', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/eu/MASTER', { at: { region: 'eu' }, value: 'eu-master' });
  assert.equal(await pick(w, 'fake', {}), 'no_master', 'the key names no region: a region master is not its master');
  assert.equal(await pick(w, 'fake', { region: 'us' }), 'no_master', 'another region');
  assert.equal(await pick(w, 'fake', { region: 'eu', project: 'shop' }), 'eu-master', 'a field only the key names does not matter');
});

test('KBOX-57 KBOX-15 a row raised to master only by the class floor (a project token) is no master: none is no_master, and beside a team master it is never ambiguous', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/shop/PROJECT_TOKEN', { at: { project: 'shop' }, items: ['project-token'], value: 'project-token' });
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'no_master');
  putMaster(w, 'fake/team/MASTER', { value: 'team-master' });
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'team-master');
});

test('KBOX-57 with masterItems team:, a team:a key gets the team:a master and never the team:b one; a key naming no team gets neither', async (t) => {
  const w = await world(t, ['team:']);
  putMaster(w, 'fake/a/MASTER', { items: ['master', 'team:a'], value: 'team-a-master' });
  putMaster(w, 'fake/b/MASTER', { items: ['master', 'team:b'], value: 'team-b-master' });
  assert.equal(await pick(w, 'fake', {}, ['read', 'team:a']), 'team-a-master');
  assert.equal(await pick(w, 'fake', {}, ['team:b']), 'team-b-master');
  assert.equal(await pick(w, 'fake', {}, ['read']), 'no_master');
});

test('KBOX-57 without masterItems, scope items never choose a master: the same two team masters are master_ambiguous', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/a/MASTER', { items: ['master', 'team:a'] });
  putMaster(w, 'fake/b/MASTER', { items: ['master', 'team:b'] });
  assert.equal(await pick(w, 'fake', {}, ['team:a']), 'master_ambiguous');
});

test('KBOX-57 masters lists every candidate row of the platform with its stored location: not a floor-raised row, an unlendable one or another platform\'s', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/eu/MASTER', { at: { region: 'eu' }, value: 'eu-master' });
  putMaster(w, 'fake/us/MASTER', { at: { region: 'us' }, value: 'us-master' });
  putMaster(w, 'fake/shop/PROJECT_TOKEN', { at: { project: 'shop' }, items: ['project-token'] });
  putMaster(w, 'fake/leftover/MASTER', { value: null });
  putMaster(w, 'other/MASTER', { platform: 'other' });
  const listed = await Promise.all(w.source.masters('fake').map(async (m) => [m.at, Buffer.from(await bytesOf(m.value)).toString('utf8')] as const));
  assert.deepEqual([...listed].sort((a, b) => a[1].localeCompare(b[1])), [[{ region: 'eu' }, 'eu-master'], [{ region: 'us' }, 'us-master']]);
});

// --- which master row serves a key (review N5, KBOX-57) -----------------------------------------------------------------------------

test('KBOX-51 a master row whose current generation cannot be lent (a failed create left it) does not serve: the working master of the platform does, whatever the row order', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/a-leftover', { value: null, status: 'failed' });
  putMaster(w, 'fake/master', { value: 'working-master' });
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'working-master');
});

test('KBOX-51 with a master row per project, a key gets its own project\'s master, never the other project\'s', async (t) => {
  // KBOX-57: "per project" is the row's stored location (`{project}`), never its `projects` list.
  const w = await world(t);
  putMaster(w, 'fake/other/MASTER', { at: { project: 'other' }, value: 'other-master' });
  putMaster(w, 'fake/shop/MASTER', { at: { project: 'shop' }, value: 'shop-master' });
  assert.equal(await pick(w, 'fake', { project: 'shop' }), 'shop-master');
  assert.equal(await pick(w, 'fake', { project: 'other' }), 'other-master');
});

test('KBOX-51 KBOX-57 two masters that both still qualify are refused with master_ambiguous, never guessed: two at the key\'s own location, or two that cover every place', async (t) => {
  const w = await world(t);
  putMaster(w, 'fake/one/MASTER', { at: { project: 'shop' } });
  putMaster(w, 'fake/two/MASTER', { at: { project: 'shop' } });
  assert.deepEqual(w.source.master('fake', { project: 'shop' }, []), { ok: false, code: 'master_ambiguous' }, 'two at the key\'s own location');
  putMaster(w, 'fake/three/MASTER', {});
  putMaster(w, 'fake/four/MASTER', {});
  assert.deepEqual(w.source.master('fake', { project: 'third' }, []), { ok: false, code: 'master_ambiguous' }, 'none at the key\'s location and two that cover every place');
});

test('KBOX-55 a google entry whose classify never answers master still serves the box\'s signing key as master: candidates classify each row through kitFor', async (t) => {
  const w = await world(t);
  const deps = { http: refusingAdapterHttp, clock: w.clock };
  const google: PlatformEntry = { ...createGoogleEntry(deps), classify: () => 'ordinary' };
  const source = createPlatformSource({ registry: [google], meta: w.parts.meta, vault: w.parts.vault, keyInfo: (keyref) => w.store.keyInfo(keyref) });
  putMaster(w, 'google/p/OIDC_SIGNING_KEY', { platform: 'google', items: [], value: 'the-box-signing-key' });
  // Negative control: another google master row is classified by the entry, so it is no candidate.
  putMaster(w, 'google/shop/MAPS_ADMIN', { platform: 'google', items: [], value: 'an-api-key-master' });
  const chosen = source.master('google', { project: 'p-proj1' }, []);
  assert.ok(chosen.ok, JSON.stringify(chosen));
  assert.equal(Buffer.from(await bytesOf(chosen.value)).toString('utf8'), 'the-box-signing-key');
});
