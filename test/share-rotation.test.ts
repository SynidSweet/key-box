// KBOX-33 over the REAL share source (the box's metadata, vault and the rotation store), not the fake store: a rotation's key.changed
// gives a new share version that holds the generation the rotation retired. Review of unit share, major 2.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyShape } from '../src/ports/types.ts';
import { createDeletionStore } from '../src/shell/deletion-store.ts';
import { PROOF_GAP_MS, createProofWatch } from '../src/shell/proof-watch.ts';
import type { ProofWatch } from '../src/shell/proof-watch.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
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

// --- re-pins of the retired retire-by-step-10 tests (revoke-proof, S-795 unit retire-revoke) ------------------------------------------

/**
 * A proof watch over the rotation world's platform, whose entry here declares proven revoked evidence: the verifier answers 200 for a key it
 * takes and 401 for one it refuses (KBOX-62), the only evidence that may retire a generation (KBOX-51 step 10 as amended).
 */
function provenWatch(w: RotationWorld): ProofWatch {
  const source: PlatformSource = {
    platform: () => ({
      issuer: w.platform.issuer,
      lister: w.platform.lister,
      verifier: { verify: (key, target) => w.platform.verifier.verify(key, target), answerStatus: async (key, target) => ((await w.platform.verifier.verify(key, target)) === 'ok' ? 200 : 401) },
      revoked: { statuses: [401] },
    }),
    destination: () => undefined,
    master: () => ({ ok: true, value: w.platform.master() }),
    masters: () => [],
  };
  return createProofWatch({ ...source, store: w.store, ledgers: createDeletionStore(w.parts.db, w.clock, w.parts.hub), vault: w.parts.vault, audit: w.parts.audit, clock: w.clock, scheduler: w.clock });
}

test('KBOX-33 after step 10 the old generation is still listed and watched (its value found, retired: true); once the proof watch retires it on proven evidence a newer version lists it as not watched', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  const keyref = await w.seedKey();
  const oldValue = await w.valueOf(keyref, 1);
  const writer = await shareOver(t, w);
  await writer.start();
  w.orch.start({ keyref, origin: 'approval' });
  await w.orch.idle();
  w.clock.advance(25 * HOUR);
  await w.orch.idle();
  await writer.idle();
  assert.equal(w.store.activeRunOf(keyref), undefined, 'the run is done');
  assert.equal(w.store.gen(keyref, 1)?.status, 'grace');
  const ended = open(w, writer);
  assert.deepEqual(ended.found(oldValue), [{ gen: 1, retired: true }], 'the ended, unproven old value is still watched');

  const watch = provenWatch(w);
  const sweep = watch.run();
  await watch.idle();
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  await writer.idle();
  assert.equal(w.store.gen(keyref, 1)?.status, 'retired');
  const after = open(w, writer);
  assert.ok(after.version > ended.version, 'the retirement made a new version');
  assert.deepEqual(after.coverage.map((c) => [c.gen, c.tier]).sort(), [[1, 'none'], [2, 'windowed']], 'both generations are listed; the retired one is explicitly not watched');
  assert.deepEqual(after.entries.filter((e) => e.retired), [], 'no probe for a value the box no longer holds');
});

test('KBOX-33 KBOX-17 a generation the platform never issued (an overlap:false rollback, failed) is not in the file; an issued one rolled back is grace and listed as watched', async (t) => {
  const never = await rotationWorld(t, { klass: 'admin', overlap: false });
  const neverRef = await never.seedKey();
  never.destinations.redeployer.failNext();
  const neverWriter = await shareOver(t, never);
  await neverWriter.start();
  never.orch.start({ keyref: neverRef, origin: 'approval' });
  await never.settle();
  await neverWriter.idle();
  assert.equal(never.store.gen(neverRef, 2)?.status, 'failed');
  assert.deepEqual(open(never, neverWriter).coverage.map((c) => c.gen), [1], 'the file lists generation 1 only');

  const issued = await rotationWorld(t, { klass: 'admin' });
  const keyref = await issued.seedKey();
  issued.destinations.redeployer.failNext();
  const writer = await shareOver(t, issued);
  await writer.start();
  issued.orch.start({ keyref, origin: 'approval' });
  await issued.settle();
  await writer.idle();
  assert.equal(issued.store.gen(keyref, 2)?.status, 'grace', 'issued, ended, not proven dead');
  assert.deepEqual(open(issued, writer).found(await issued.valueOf(keyref, 2)), [{ gen: 2, retired: true }]);
});
