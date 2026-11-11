// The rotation shell's view of the platform registry (KBOX-23, KBOX-51): the adapters of a registered platform, nothing for an
// unregistered one, and the platform's master key lent from the vault by the master key row of that platform.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
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
  const entry: PlatformEntry = { id: 'fake', issuer: platform.issuer, lister: platform.lister };
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
