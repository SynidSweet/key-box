// KBOX-33 over the REAL share source (the box's metadata, vault and the rotation store), not the fake store: a rotation's key.changed
// gives a new share version that holds the generation the rotation retired. Review of unit share, major 2.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyShape } from '../src/ports/types.ts';
import { createMetaShareSource } from '../src/shell/share-source.ts';
import { createShareWriter } from '../src/shell/share-writer.ts';
import type { ShareWriter } from '../src/shell/share-writer.ts';
import { openShare } from './kit/reference-matcher.ts';
import { rawDocument } from './kit/share-store.ts';
import { seededRandom, tempDir } from './kit/index.ts';
import { HOUR, rotationWorld } from './support/rotation-world.ts';
import type { RotationWorld } from './support/rotation-world.ts';

/** The fake platform's key shape: `fk-` and 32 hex characters (test/fakes/platform.ts). Registered through the source's `shapeOf` seam. */
const FAKE_SHAPE: KeyShape = { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };

async function shareOver(t: TestContext, w: RotationWorld): Promise<ShareWriter> {
  const writer = createShareWriter({
    dir: join(await tempDir(t), 'share'),
    meta: w.parts.meta,
    signingKey: w.parts.share.signingKey,
    source: createMetaShareSource({
      meta: w.parts.meta,
      values: w.parts.share.values,
      shapeOf: (platform) => (platform === 'fake' ? FAKE_SHAPE : undefined),
      generations: (keyref: string) => w.store.gens(keyref),
    }),
    events: w.parts.events,
    hub: w.parts.hub,
    clock: w.clock,
    scheduler: w.clock,
    random: seededRandom(31),
    audit: w.parts.audit,
  });
  t.after(() => writer.stop());
  return writer;
}

interface Opened {
  readonly version: number;
  readonly entries: readonly { gen: number; retired: boolean; tier: string }[];
  readonly coverage: readonly { gen: number; tier: string }[];
  /** The names the reference matcher finds in a document holding `value`, with the generation and retired flag of each find. */
  found(value: string): readonly { gen: number; retired: boolean }[];
}

function open(w: RotationWorld, writer: ShareWriter): Opened {
  const file = writer.serve();
  const publicKey = w.parts.meta.shareState().publicKeyB64;
  assert.ok(publicKey !== null);
  const opened = openShare(file.bytes, publicKey);
  assert.ok(opened.ok, 'the file verifies with the published key');
  const envelope = JSON.parse(Buffer.from(file.bytes).toString('utf8')) as { body_b64: string };
  const body = JSON.parse(Buffer.from(envelope.body_b64, 'base64').toString('utf8')) as Pick<Opened, 'entries' | 'coverage'>;
  return { version: file.version, entries: body.entries, coverage: body.coverage, found: (value) => opened.share.scan(rawDocument(value)).map((f) => ({ gen: f.gen, retired: f.retired })) };
}

test('KBOX-33 a rotation of an admin key gives a new share version that lists the old generation as retired and still finds its value while the platform key lives (grace)', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  const keyref = await w.seedKey();
  const oldValue = await w.valueOf(keyref, 1);
  const writer = await shareOver(t, w);
  await writer.start();
  const before = open(w, writer);
  assert.deepEqual(before.entries.map((e) => [e.gen, e.retired]).filter((e, i, all) => all.findIndex((x) => x[0] === e[0] && x[1] === e[1]) === i), [[1, false]], 'one generation, current');

  w.orch.start({ keyref, origin: 'approval' });
  await w.orch.idle();
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace', 'the run waits out the grace of the old generation');
  const newValue = await w.valueOf(keyref, 2);
  await writer.idle();
  const during = open(w, writer);
  assert.ok(during.version > before.version, 'the rotation made a new version');
  assert.deepEqual(during.found(oldValue), [{ gen: 1, retired: true }], 'the old value is found, as a retired generation');
  assert.deepEqual(during.found(newValue), [{ gen: 2, retired: false }]);
});

test('KBOX-33 once the old generation is revoked and retired the file still lists it, as not watched (the vault no longer holds its value), under a newer version', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  const keyref = await w.seedKey();
  const writer = await shareOver(t, w);
  await writer.start();
  w.orch.start({ keyref, origin: 'approval' });
  await w.orch.idle();
  await writer.idle();
  const during = open(w, writer);
  w.clock.advance(25 * HOUR);
  await w.orch.idle();
  await writer.idle();
  assert.equal(w.store.gen(keyref, 1)?.status, 'retired');
  const after = open(w, writer);
  assert.ok(after.version > during.version, 'the retirement made a new version');
  assert.deepEqual(after.coverage.map((c) => [c.gen, c.tier]).sort(), [[1, 'none'], [2, 'windowed']], 'both generations are listed; the retired one is explicitly not watched');
  assert.deepEqual(after.entries.filter((e) => e.retired), [], 'no probe for a value the box no longer holds');
});

test('KBOX-33 a generation that never went live (pending, failed) is not a retired generation of the file', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  const keyref = await w.seedKey();
  w.destinations.redeployer.failNext();
  const writer = await shareOver(t, w);
  await writer.start();
  w.orch.start({ keyref, origin: 'approval' });
  await w.settle();
  await writer.idle();
  assert.equal(w.store.gens(keyref).some((g) => g.status === 'failed'), true, 'the run failed and its generation is marked failed');
  assert.deepEqual(open(w, writer).coverage.map((c) => c.gen), [1], 'the file lists generation 1 only');
});
