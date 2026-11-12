// The rotation shell's view of the platform registry (KBOX-23, KBOX-51): the adapters of a registered platform, nothing for an
// unregistered one, and the platform's master key lent from the vault by the master key row of that platform.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import { ApiError } from '../src/pure/errors.ts';
import { openCore } from '../src/shell/core.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
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

async function world(t: TestContext) {
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(3);
  const parts = openCore({ stateDir: join(await tempDir(t), 'state'), clock, scheduler: clock, random });
  t.after(() => parts.close());
  const platform = new FakePlatformWorld(random);
  const entry: PlatformEntry = { id: 'fake', issuer: platform.issuer, lister: platform.lister, unverified: [] };
  return { parts, entry, source: createPlatformSource({ registry: [entry], meta: parts.meta, vault: parts.vault }) };
}

test('KBOX-23 a registered platform gives its issuer and lister, an unregistered one gives nothing', async (t) => {
  const w = await world(t);
  assert.equal(w.source.platform('fake')?.issuer, w.entry.issuer);
  assert.equal(w.source.platform('fake')?.lister, w.entry.lister);
  assert.equal(w.source.platform('other'), undefined);
});

test('KBOX-51 the master key of a platform is the current generation of its master key row, lent from the vault, never another platform\'s', async (t) => {
  const w = await world(t);
  w.parts.vault.put('fake/master', 1, Buffer.from('old-master'));
  w.parts.vault.put('fake/master', 2, Buffer.from('current-master'));
  w.parts.meta.putKey(masterRow('fake/master', 'fake', 2));
  w.parts.vault.put('other/master', 1, Buffer.from('other-master'));
  w.parts.meta.putKey(masterRow('other/master', 'other', 1));
  assert.equal(Buffer.from(await bytesOf(w.source.master('fake'))).toString('utf8'), 'current-master');
  assert.equal(Buffer.from(await bytesOf(w.source.master('other'))).toString('utf8'), 'other-master');
});

test('KBOX-51 a platform with no master key row, or one that is not master class, has no master to lend: a fixed error, no value', async (t) => {
  const w = await world(t);
  assert.throws(() => w.source.master('fake'), /no master key/);
  w.parts.vault.put('fake/admin', 1, Buffer.from('an-admin-value'));
  w.parts.meta.putKey({ ...masterRow('fake/admin', 'fake', 1), class: 'admin' });
  assert.throws(() => w.source.master('fake'), (error: unknown) => error instanceof RangeError && !String(error.message).includes('an-admin-value') && /no master key/.test(error.message));
});

// --- which master row serves a key (review N5) ----------------------------------------------------------------------------------

const textOf = async (w: Awaited<ReturnType<typeof world>>, platform: string, projects: readonly string[]): Promise<string> => Buffer.from(await bytesOf(w.source.master(platform, projects))).toString('utf8');
const ambiguous = (error: unknown): boolean => error instanceof ApiError && error.code === 'conflict' && JSON.stringify(error.detail) === JSON.stringify({ code: 'master_ambiguous' });

test('KBOX-51 a master row whose current generation cannot be lent (a failed create left it) does not serve: the working master of the platform does, whatever the row order', async (t) => {
  const w = await world(t);
  w.parts.meta.putKey({ ...masterRow('fake/a-leftover', 'fake', 1), status: 'failed' });
  w.parts.vault.put('fake/master', 1, Buffer.from('working-master'));
  w.parts.meta.putKey(masterRow('fake/master', 'fake', 1));
  assert.equal(await textOf(w, 'fake', ['shop']), 'working-master');
});

test('KBOX-51 with a master row per project, a key gets its own project\'s master, never the other project\'s', async (t) => {
  const w = await world(t);
  w.parts.vault.put('fake/other/MASTER', 1, Buffer.from('other-master'));
  w.parts.meta.putKey({ ...masterRow('fake/other/MASTER', 'fake', 1), projects: ['other'] });
  w.parts.vault.put('fake/shop/MASTER', 1, Buffer.from('shop-master'));
  w.parts.meta.putKey({ ...masterRow('fake/shop/MASTER', 'fake', 1), projects: ['shop'] });
  assert.equal(await textOf(w, 'fake', ['shop']), 'shop-master');
  assert.equal(await textOf(w, 'fake', ['other']), 'other-master');
});

test('KBOX-51 two masters that both still qualify are refused with master_ambiguous, never guessed: two of the key\'s own project, or two of other projects', async (t) => {
  const w = await world(t);
  for (const [ref, projects] of [['fake/one/MASTER', ['shop']], ['fake/two/MASTER', ['shop']]] as const) {
    w.parts.vault.put(ref, 1, Buffer.from(`${ref}-value`));
    w.parts.meta.putKey({ ...masterRow(ref, 'fake', 1), projects: [...projects] });
  }
  assert.throws(() => w.source.master('fake', ['shop']), ambiguous, 'two of the key\'s own project');
  assert.throws(() => w.source.master('fake', ['third']), ambiguous, 'none of the key\'s project and two of others');
});
