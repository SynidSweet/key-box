// KBOX-23, KBOX-40, KBOX-12, KBOX-51: one registry entry carries everything an adapter registers. The platform source gives the kit of an
// entry (verifier, key page, shape) and the destination kit of a kind; the paste flow and the orchestrator reach them through it.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { Verifier } from '../src/ports/issuer.ts';
import type { KeyShape } from '../src/ports/types.ts';
import { isPasteSource } from '../src/shell/rotation-ports.ts';
import { classifierOf, shapeOf } from '../src/pure/platform-shape.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { FAKE_KEY_PAGE, fakeEntry, issuerWith, pasteOnlyEntry, sourceOf } from './fakes/platform-entry.ts';
import { RecordingDestination, RecordingRedeployer } from './fakes/recording-destination.ts';
import { bytesOf, seededRandom } from './kit/index.ts';
import { PASTE_PLATFORM, pasteValue, routesWorld } from './support/routes-world.ts';
import { rotationWorld } from './support/rotation-world.ts';

const SHAPE: KeyShape = { prefix: 'po-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };
const world = (): FakePlatformWorld => new FakePlatformWorld(seededRandom(2));

test('KBOX-23 the kit of an entry carries its verifier and its key page, and says nothing it was not given', () => {
  const w = world();
  const kit = sourceOf([fakeEntry(w)]).platform('fake');
  assert.equal(kit?.verifier, w.verifier);
  assert.equal(kit?.keyPageUrl, FAKE_KEY_PAGE);
  assert.equal(sourceOf([{ id: 'fake', issuer: w.issuer, unverified: [] }]).platform('fake')?.verifier, undefined);
  assert.equal(sourceOf([fakeEntry(w)]).platform('unknown'), undefined);
});

test('KBOX-23 a destination kind has the kit of the entry that registered it, spelled as the metadata spells it; an unknown kind has none', () => {
  const w = world();
  const destination = new RecordingDestination([]);
  const redeployer = new RecordingRedeployer([], destination);
  const source = sourceOf([fakeEntry(w), fakeEntry(w, { id: 'host', destinations: [{ destination, redeployer }] })]);
  assert.deepEqual(source.destination('vercel_env'), { destination, redeployer });
  assert.equal(source.destination('gcp_secret'), undefined, 'no entry registered this kind');
  assert.equal(source.destination('vercel-env'), undefined, 'the adapter spelling is not a metadata kind');
  assert.equal(source.destination('workstation'), undefined, 'the workstation is a delivery, not an adapter');
  assert.equal(source.destination('nonsense'), undefined);
});

test('KBOX-40 a paste-only entry (no issuer) is a registered paste source with the shape it states; a platform that issues is not one', () => {
  const w = world();
  const source = sourceOf([pasteOnlyEntry(w, SHAPE), fakeEntry(w)]);
  assert.equal(isPasteSource(source, { platform: 'pasteonly', keyref: 'pasteonly/p/KEY' }), true);
  assert.equal(isPasteSource(source, { platform: 'fake', keyref: 'fake/p/KEY' }), false);
  assert.equal(isPasteSource(source, { platform: 'unknown', keyref: 'unknown/p/KEY' }), false, 'an unregistered platform is no paste source');
  assert.deepEqual(source.platform('pasteonly')?.shape, SHAPE);
});

test('KBOX-23 the one shape of an entry is its issuer\'s, or the one it states', () => {
  const w = world();
  assert.deepEqual(shapeOf(fakeEntry(w)), w.issuer.capabilities().shape);
  assert.deepEqual(shapeOf(pasteOnlyEntry(w, SHAPE)), SHAPE);
});

test('KBOX-12 the paste page shows the entry\'s key page, and the entry\'s verifier decides the value', async (t) => {
  const seen: string[] = [];
  const verifier: Verifier = { verify: async (key) => (seen.push(Buffer.from(await bytesOf(key)).toString('utf8')), 'ok') };
  const entry = fakeEntry(world(), { id: PASTE_PLATFORM, verifier, keyPageUrl: 'https://entry.example/make-a-key', issuer: issuerWith(world().issuer, { create: 'paste', revoke: 'paste', revealOnce: false, shape: { prefix: 'pk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true }, classify: () => 'admin' }) });
  const w = await routesWorld(t, { source: (real) => ({ ...real, platform: (id) => sourceOf([entry]).platform(id) ?? real.platform(id) }) });
  const opened = await w.api('/api/keys', { json: { platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', projects: ['shop'], scope: { items: ['admin'] } } });
  assert.equal(opened.status, 202, opened.body);
  const id = (opened.json() as { paste_task_id: string }).paste_task_id;
  const cookie = await w.view();
  const page = await w.call(`/p/${id}`, { cookie });
  const view = page.json() as { platform_link?: string } & Parameters<typeof w.pasteProof>[0];
  assert.equal(view.platform_link, 'https://entry.example/make-a-key');
  const stored = await w.call(`/p/${id}`, { json: { value: pasteValue('b'.repeat(32)), proof: w.pasteProof(view) }, cookie });
  assert.equal(stored.status, 201, stored.body);
  assert.ok(seen.length > 0 && seen.every((v) => v === pasteValue('b'.repeat(32))), 'the entry\'s verifier saw the value');
});

/** A rotation whose platform source is built from a registry entry (through `createPlatformSource`) carrying `verifier` and nothing of the world's own. */
async function rotateWithEntryVerifier(t: TestContext, decide: (presented: string, newest: string) => 'ok' | 'rejected') {
  const seen: string[] = [];
  let newest: (() => Promise<string>) | undefined; // set once the key is seeded: the seeding run is not under test
  const verifier: Verifier = {
    verify: async (key) => {
      if (newest === undefined) return 'ok';
      const presented = Buffer.from(await bytesOf(key)).toString('utf8');
      seen.push(presented);
      return decide(presented, await newest());
    },
  };
  const w = await rotationWorld(t, {
    source: (real) => {
      const kit = real.platform('fake');
      const entry = fakeEntry(world(), { ...(kit?.issuer === undefined ? {} : { issuer: kit.issuer }), ...(kit?.lister === undefined ? {} : { lister: kit.lister }), verifier });
      return { ...real, platform: (id) => sourceOf([entry]).platform(id) };
    },
  });
  const keyref = await w.seedKey();
  newest = () => w.valueOf(keyref, 2);
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  return { w, keyref, seen };
}

test('KBOX-51 a rotation succeeds because the verifier of the registry entry accepts the new key: the world\'s own verifier is never asked', async (t) => {
  const { w, keyref, seen } = await rotateWithEntryVerifier(t, (presented, current) => (presented === current ? 'ok' : 'rejected'));
  const newValue = await w.valueOf(keyref, 2);
  assert.ok(seen.length >= 1 && seen.every((v) => v === newValue), 'the entry\'s verifier was asked about the new key');
  assert.equal(w.trace.includes('verify'), false, 'the world\'s own verifier was not');
  assert.equal(w.store.activeRunOf(keyref)?.state, 'grace', 'the run passed verify and check and waits out the grace');
  assert.equal(w.store.gens(keyref).find((g) => g.gen === 2)?.status, 'current');
});

test('KBOX-51 a rotation does not promote when the verifier of the registry entry rejects the new key, though the world\'s own verifier would accept it', async (t) => {
  const { w, keyref, seen } = await rotateWithEntryVerifier(t, () => 'rejected');
  assert.ok(seen.length >= 1, 'the entry\'s verifier was asked');
  assert.equal(w.trace.includes('verify'), false, 'the world\'s own verifier was not');
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.gen_current, 1);
  assert.notEqual(w.store.gens(keyref).find((g) => g.gen === 2)?.status ?? 'failed', 'current');
});

test('KBOX-40 KBOX-15 classifierOf reads the issuer\'s classification, or the entry\'s own when it has no issuer, and nothing for a platform that is not registered', () => {
  const w = world();
  const own = classifierOf(pasteOnlyEntry(w, SHAPE, { classify: (s) => (s['items'] === 'x' ? 'master' : 'admin') }));
  assert.deepEqual([own?.({ items: 'x' }, {}), own?.({ items: ['y'] }, {})], ['master', 'admin']);
  const issued = classifierOf(fakeEntry(w, { issuer: issuerWith(w.issuer, { classify: () => 'admin' }) }));
  assert.equal(issued?.({ items: ['read'] }, {}), 'admin');
  assert.equal(classifierOf(undefined), undefined);
});
