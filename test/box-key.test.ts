// KBOX-55 (the seam and the creation): the box's own Google signing key. Its value is drawn until it is a P-256 scalar; its kit carries no
// issuer, lister, verifier or retirer and classifies master, while every other Google key gets the platform's kit; core makes it once at
// start when the box has its identity; the JWKS lists its generations by status; the share file watches a pending generation; and no
// platform call made for API keys ever reaches it through the real orchestrator wiring.
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { Issuer, KeyLister, Retirer, Verifier } from '../src/ports/issuer.ts';
import { refusingAdapterHttp } from '../src/ports/http.ts';
import type { KeyRow } from '../src/ports/meta.ts';
import type { BoxMadeKey, PlatformEntry, RegistryDeps } from '../src/ports/platform.ts';
import type { Random } from '../src/ports/random.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { startCore } from '../src/main-core.ts';
import type { StartedCore } from '../src/main-core.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { SIGNING_KEY_SHAPE } from '../src/platforms/google/signing-key.ts';
import { ensureBoxKeys } from '../src/shell/box-keys.ts';
import { openCore } from '../src/shell/core.ts';
import type { CoreParts } from '../src/shell/core.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import { isPasteSource, kitFor, rotatesByPaste, verifierFor } from '../src/shell/rotation-ports.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import type { GenRow, RotationStore } from '../src/shell/rotation-store.ts';
import { createMetaShareSource } from '../src/shell/share-source.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { issuerWith, sourceOf } from './fakes/platform-entry.ts';
import { rotationWorld } from './support/rotation-world.ts';
import { TimedClock, bytesOf, drive, lent, seededRandom, tempDir } from './kit/index.ts';

const BOX_REF = 'google/p/OIDC_SIGNING_KEY';
const DOMAIN = 'box.example';
const AUDIENCE = '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-prov';
const NOW = 1_700_000_000_000;
const HOUR = 3600_000;
const DAY = 24 * HOUR;
/** The order n of the P-256 group (SEC 2): a scalar is valid when 0 < d < n. */
const ORDER = Buffer.from('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex');

const googleDeps = (clock = new TimedClock(NOW)): RegistryDeps => ({ http: refusingAdapterHttp, clock });
const boxKeyOf = (entry: PlatformEntry): BoxMadeKey => {
  const box = entry.boxKey;
  assert.ok(box !== undefined, 'the google entry declares its box-made key');
  return box;
};

/** A Random that hands out exactly these draws, each of 32 bytes, and records every size asked. */
function scripted(draws: readonly Uint8Array[]): Random & { readonly asked: number[] } {
  const queue = [...draws];
  const asked: number[] = [];
  return {
    asked,
    bytes: (n) => {
      asked.push(n);
      const next = queue.shift();
      if (next === undefined) throw new RangeError('kbox-test: no draw left');
      return Uint8Array.from(next);
    },
  };
}

/** The public JWK of a scalar given as 43 base64url characters, computed here (RFC 7638 thumbprint as kid), independent of src. */
function jwkOf(text: string): { kty: 'EC'; crv: 'P-256'; x: string; y: string; kid: string; alg: 'ES256'; use: 'sig' } {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(text, 'base64url'));
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  const kid = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url');
  return { kty: 'EC', crv: 'P-256', x, y, kid, alg: 'ES256', use: 'sig' };
}

const scalarText = (seed: string): string => createHash('sha256').update(`kbox-test-box-key-${seed}`).digest().toString('base64url');

// --- the value -----------------------------------------------------------------------------------------------------------------------

test('KBOX-55 generate draws again on zero and on the curve order and keeps the third draw, order - 1, as exactly its 32 bytes in 43 base64url characters', () => {
  const below = Buffer.from(ORDER);
  below[31] = (below[31] ?? 0) - 1;
  const random = scripted([new Uint8Array(32), ORDER, below]);
  const value = boxKeyOf(createGoogleEntry(googleDeps())).generate(random);
  assert.equal(Buffer.from(value).toString('latin1'), below.toString('base64url'));
  assert.deepEqual(random.asked, [32, 32, 32]);
});

test('KBOX-55 a draw with a leading zero byte keeps all 32 bytes (the 7bf8e11 lesson): its text decodes to the same 32 bytes', () => {
  const draw = Buffer.concat([Buffer.from([0]), createHash('sha256').update('kbox-test-leading-zero').digest().subarray(0, 31)]);
  const text = Buffer.from(boxKeyOf(createGoogleEntry(googleDeps())).generate(scripted([draw]))).toString('latin1');
  assert.equal(text.length, 43);
  assert.deepEqual(Buffer.from(text, 'base64url'), draw);
});

test('KBOX-55 check: a generated value opens as a P-256 key (ok); the order itself, a short value and text that is not base64url are rejected', async () => {
  const box = boxKeyOf(createGoogleEntry(googleDeps()));
  assert.equal(await box.check(lent(box.generate(seededRandom(11)), 'generated')), 'ok');
  for (const bad of [ORDER.toString('base64url'), scalarText('short').slice(0, 42), `${scalarText('star').slice(0, 42)}*`]) {
    assert.equal(await box.check(lent(Buffer.from(bad, 'latin1'), 'bad')), 'rejected', bad);
  }
});

test('KBOX-55 the google entry names the signing key OIDC_SIGNING_KEY with the signing key shape and a publish lead of 24 hours', () => {
  const box = boxKeyOf(createGoogleEntry(googleDeps()));
  assert.equal(box.name, 'OIDC_SIGNING_KEY');
  assert.deepEqual(box.shape, SIGNING_KEY_SHAPE);
  assert.equal(box.publishLeadMs, DAY);
});

// --- the kit ---------------------------------------------------------------------------------------------------------------------------

interface Calls {
  issue: number;
  revoke: number;
  list: number;
  listAt: number;
  verify: number;
  retire: number;
}

/** The google entry as it will stand once API keys are added: an issuer, lister, verifier and retirer beside the box key, each counting calls. */
function googleWithApiKeys(world: FakePlatformWorld, deps: RegistryDeps = googleDeps()): { readonly entry: PlatformEntry; readonly calls: Calls } {
  const calls: Calls = { issue: 0, revoke: 0, list: 0, listAt: 0, verify: 0, retire: 0 };
  const base = issuerWith(world.issuer, { classify: () => 'ordinary', shape: { prefix: 'AIza', alphabet: 'base64url', coreLength: { min: 35, max: 35 }, random: true } });
  const issuer: Issuer = {
    ...base,
    platform: 'google',
    issue: (...args) => {
      calls.issue += 1;
      return base.issue(...args);
    },
    revoke: (...args) => {
      calls.revoke += 1;
      return base.revoke(...args);
    },
  };
  const lister: KeyLister = {
    list: (master) => {
      calls.list += 1;
      return world.lister.list(master);
    },
    listAt: (at, master) => {
      calls.listAt += 1;
      return world.lister.listAt(at, master);
    },
  };
  const verifier: Verifier = {
    verify: (key, target) => {
      calls.verify += 1;
      return world.verifier.verify(key, target);
    },
  };
  const retirer: Retirer = {
    retire: () => {
      calls.retire += 1;
      return Promise.resolve('absent');
    },
  };
  const { shape: _shape, classify: _classify, ...rest } = createGoogleEntry(deps);
  return { entry: { ...rest, issuer, lister, verifier, retirer }, calls };
}

test('KBOX-55 kitFor gives the box keyref only its box key, its shape and master class: no issuer, lister, verifier or retirer even where the platform has them', () => {
  const { entry } = googleWithApiKeys(new FakePlatformWorld(seededRandom(4)));
  const kit = kitFor(sourceOf([entry]), { platform: 'google', keyref: BOX_REF });
  assert.ok(kit !== undefined);
  assert.deepEqual(Object.keys(kit).sort(), ['boxKey', 'classify', 'shape']);
  assert.equal(kit.boxKey, entry.boxKey);
  assert.deepEqual(kit.shape, SIGNING_KEY_SHAPE);
  assert.equal(kit.classify?.({ items: ['read'] }, { project: 'p-proj1' }), 'master');
  assert.equal(verifierFor(kit, { scopeItems: [], at: {} }), undefined);
});

test('KBOX-55 kitFor gives any other Google keyref the platform kit without the box key: the same name in a project, another name, and the platform view keeps it', () => {
  const { entry } = googleWithApiKeys(new FakePlatformWorld(seededRandom(4)));
  const source = sourceOf([entry]);
  for (const keyref of ['google/shop/OIDC_SIGNING_KEY', 'google/p/MAPS_KEY']) {
    const kit = kitFor(source, { platform: 'google', keyref });
    assert.ok(kit !== undefined, keyref);
    assert.equal(kit.boxKey, undefined, keyref);
    assert.equal(kit.issuer, entry.issuer, keyref);
    assert.equal(kit.lister, entry.lister, keyref);
    assert.equal(kit.retirer, entry.retirer, keyref);
    assert.equal(verifierFor(kit, { scopeItems: [], at: {} }), entry.verifier, keyref);
  }
  assert.equal(source.platform('google')?.boxKey, entry.boxKey, 'the platform view (add_key, POST /api/keys) still sees that the box makes a master here');
  assert.equal(kitFor(source, { platform: 'nosuch', keyref: 'nosuch/p/OIDC_SIGNING_KEY' }), undefined, 'an unregistered platform has no kit');
});

test('KBOX-55 a key whose kit makes it by box is never a paste source, and rotates by approval: isPasteSource and rotatesByPaste are asked per key', () => {
  const entry = createGoogleEntry(googleDeps());
  const source = sourceOf([entry]);
  assert.equal(isPasteSource(source, { platform: 'google', keyref: BOX_REF }), false);
  assert.equal(rotatesByPaste(source, { platform: 'google', keyref: BOX_REF, class: 'master' }), false);
  // Negative control: another key of the same platform (no issuer yet) is still a paste source and rotates by paste.
  assert.equal(isPasteSource(source, { platform: 'google', keyref: 'google/p/MAPS_KEY' }), true);
  assert.equal(rotatesByPaste(source, { platform: 'google', keyref: 'google/p/MAPS_KEY', class: 'master' }), true);
});

// --- creation at core start --------------------------------------------------------------------------------------------------------

interface Seeded {
  readonly parts: CoreParts;
  readonly store: RotationStore;
  readonly clock: TimedClock;
}

interface BoxCore {
  readonly clock: TimedClock;
  readonly stateDir: string;
  /** Starts core over the box's state directory (stopping any core still running) with the domain and audience asked. */
  start(o?: { readonly domain?: boolean; readonly audience?: boolean; readonly registry?: (deps: RegistryDeps) => readonly PlatformEntry[] }): Promise<StartedCore>;
  /** A phone request (no token) or a control request to the running core. */
  call(path: string, o?: { readonly phone?: true }): Promise<{ status: number; body: string }>;
  /** Stops the running core and opens the state directory for reading; closed when the test ends. */
  read(): Promise<Seeded>;
  /** Writes to the state directory before the next start. */
  seed(write: (s: Seeded) => void): void;
}

async function boxCore(t: TestContext): Promise<BoxCore> {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const socket = join(dir, 'http.sock');
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(NOW);
  const random = seededRandom(21);
  const token = newToken(random);
  const open = (): Seeded => {
    const parts = openCore({ stateDir, clock, scheduler: clock, random });
    return { parts, store: createRotationStore(parts.db, clock, parts.hub), clock };
  };
  const first = open();
  first.parts.meta.addMachine({ label: 'mc', scope: 'control', tokenSha256: hashToken(token), enrolledAt: NOW });
  first.parts.close();
  let running: StartedCore | undefined;
  const stop = async (): Promise<void> => {
    const core = running;
    running = undefined;
    if (core === undefined) return;
    await core.stop();
    await core.closed;
  };
  t.after(stop);
  const driver = drive(socket);
  return {
    clock,
    stateDir,
    async start(o = {}) {
      await stop();
      const env = {
        KB_STATE_DIR: stateDir,
        KB_SOCKET: socket,
        KB_INSTALL_RESULTS: join(dir, 'results'),
        KB_CURRENT: join(dir, 'current'),
        ...(o.domain === false ? {} : { KB_DOMAIN: DOMAIN }),
        ...(o.audience === false ? {} : { KB_OIDC_AUDIENCE: AUDIENCE }),
      };
      running = await startCore(env, { clock, scheduler: clock, random, journal: () => undefined, registry: o.registry ?? ((deps) => [createGoogleEntry({ ...deps, http: refusingAdapterHttp })]) });
      return running;
    },
    async call(path, o = {}) {
      const headers: Record<string, string> = { 'x-kb-client-ip': '203.0.113.9', ...(o.phone === true ? {} : { authorization: `Bearer ${token}` }) };
      const reply = await driver.request({ path, method: 'GET', headers });
      return { status: reply.status, body: reply.body };
    },
    async read() {
      await stop();
      const s = open();
      t.after(() => s.parts.close());
      return s;
    },
    seed(write) {
      const s = open();
      try {
        write(s);
      } finally {
        s.parts.close();
      }
    },
  };
}

const textOf = async (parts: CoreParts, keyref: string, gen: number): Promise<string> => Buffer.from(await bytesOf(parts.vault.lend(keyref, gen))).toString('latin1');
const gensOf = (store: RotationStore, keyref: string): readonly Pick<GenRow, 'gen' | 'status'>[] => store.gens(keyref).map(({ gen, status }) => ({ gen, status }));
const actions = (parts: CoreParts, action: string, keyref?: string): number => parts.audit.read(0).entries.filter((e) => e.action === action && (keyref === undefined || e.ref === keyref)).length;
const keyChanged = (parts: CoreParts, keyref: string): number => parts.events.after(0).filter((e) => e.kind === 'key.changed' && e.data['keyref'] === keyref).length;
const jwks = async (box: BoxCore): Promise<{ readonly keys: readonly unknown[] }> => {
  const reply = await box.call('/.well-known/jwks.json', { phone: true });
  assert.equal(reply.status, 200, reply.body);
  return JSON.parse(reply.body) as { keys: unknown[] };
};

test('KBOX-55 a first start with domain and audience makes the signing key: one master row, its rotation record dated now, generation 1 current, a 43-character value that opens, one key.issued and one key.changed; the JWKS lists exactly its key; no approval and no paste task', async (t) => {
  const box = await boxCore(t);
  await box.start();
  const listed = await jwks(box);
  const { parts, store } = await box.read();
  const row = parts.meta.snapshot().keys.find((k) => k.keyref === BOX_REF);
  assert.ok(row !== undefined, 'the key row exists');
  assert.deepEqual(
    { platform: row.platform, name: row.name, projects: row.projects, class: row.class, status: row.status, gen_current: row.gen_current, every: row.schedule.rotate_every_days, grace: row.schedule.grace_hours, destinations: row.destinations },
    { platform: 'google', name: 'OIDC_SIGNING_KEY', projects: [], class: 'master', status: 'works', gen_current: 1, every: 90, grace: 1, destinations: [] },
  );
  assert.deepEqual(store.keyInfo(BOX_REF), { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'current' }]);
  const value = await textOf(parts, BOX_REF, 1);
  assert.match(value, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(listed, { keys: [jwkOf(value)] });
  assert.equal(actions(parts, 'key.issued', BOX_REF), 1);
  assert.equal(keyChanged(parts, BOX_REF), 1);
  assert.deepEqual(parts.meta.snapshot().approvals, []);
  assert.equal((parts.db.prepare('SELECT count(*) AS n FROM paste_tasks').get() as { n: number }).n, 0);
});

test('KBOX-55 a restart reuses the key: the same vault bytes and kid, no new generation, no second key.issued', async (t) => {
  const box = await boxCore(t);
  await box.start();
  const before = await jwks(box);
  box.clock.advance(HOUR);
  await box.start();
  assert.deepEqual(await jwks(box), before);
  const { parts, store } = await box.read();
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'current' }]);
  assert.equal(store.keyInfo(BOX_REF)?.rotatedAt, NOW, 'the rotation record keeps its creation time');
  assert.equal(actions(parts, 'key.issued', BOX_REF), 1);
  assert.deepEqual(before, { keys: [jwkOf(await textOf(parts, BOX_REF, 1))] });
});

test('KBOX-55 without the audience, or without the domain, no key is made and no identity route is served; a later start with both makes it', async (t) => {
  const box = await boxCore(t);
  await box.start({ audience: false });
  assert.equal((await box.call('/.well-known/jwks.json', { phone: true })).status, 404);
  assert.equal((await box.read()).parts.meta.snapshot().keys.length, 0, 'no audience: no row');
  await box.start({ domain: false });
  assert.equal((await box.read()).parts.meta.snapshot().keys.length, 0, 'no domain: no row');
  await box.start();
  const { store } = await box.read();
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'current' }]);
});

test('KBOX-55 a crash after the vault write (a value, no generation row) makes the key again at the next start, and the JWKS never lists the orphan', async (t) => {
  const box = await boxCore(t);
  const orphan = scalarText('orphan');
  box.seed(({ parts }) => parts.vault.put(BOX_REF, 1, Buffer.from(orphan, 'latin1')));
  await box.start();
  const listed = await jwks(box);
  const { parts, store } = await box.read();
  const value = await textOf(parts, BOX_REF, 1);
  assert.notEqual(value, orphan);
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'current' }]);
  assert.deepEqual(listed, { keys: [jwkOf(value)] });
});

const googleRow = (keyref: string, cls: KeyRow['class'], platform = 'google'): KeyRow => ({
  keyref,
  platform,
  name: keyref.split('/')[2] ?? 'X',
  projects: ['box'],
  class: cls,
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

test('KBOX-55 another google master row left from old data stops creation: no row, no generation, one box_key.conflict audit row', async (t) => {
  const box = await boxCore(t);
  box.seed(({ parts }) => parts.meta.putKey(googleRow('google/box/KBOX_SIGNING_KEY', 'master')));
  await box.start();
  const { parts, store } = await box.read();
  assert.equal(parts.meta.snapshot().keys.some((k) => k.keyref === BOX_REF), false);
  assert.deepEqual(gensOf(store, BOX_REF), []);
  assert.equal(actions(parts, 'box_key.conflict'), 1);
});

test('KBOX-55 negative control: an admin google row, or a master row of another platform, does not stop creation and audits no conflict', async (t) => {
  const box = await boxCore(t);
  box.seed(({ parts }) => {
    parts.meta.putKey(googleRow('google/shop/MAPS_KEY', 'admin'));
    parts.meta.putKey(googleRow('openai/box/OPENAI_ADMIN', 'master', 'openai'));
  });
  await box.start();
  const { parts, store } = await box.read();
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'current' }]);
  assert.equal(actions(parts, 'box_key.conflict'), 0);
});

test('KBOX-55 KBOX-52 the rotation record makes the fresh key due on schedule: no rotate_key request before 90 days, exactly one approval (never a paste task) after', async (t) => {
  const box = await boxCore(t);
  await box.start();
  await box.read();
  // The days pass with core stopped; each start runs one hourly tick of its own: at 90 days less an hour, then at 90 days and an hour.
  box.clock.advance(90 * DAY - 2 * HOUR);
  await box.start();
  box.clock.advance(HOUR);
  assert.deepEqual((await box.read()).parts.meta.snapshot().approvals, [], 'not due before 90 days');
  box.clock.advance(HOUR);
  await box.start();
  box.clock.advance(HOUR);
  const { parts } = await box.read();
  assert.deepEqual(parts.meta.snapshot().approvals.map((a) => a.slot), [`rotate_key:${BOX_REF}`]);
  assert.equal((parts.db.prepare('SELECT count(*) AS n FROM paste_tasks').get() as { n: number }).n, 0);
});

// --- the JWKS ------------------------------------------------------------------------------------------------------------------------

test('KBOX-55 the JWKS lists the box key\'s pending, current and grace generations newest first, chosen by status: never a failed or retired one, nor one the vault cannot lend', async (t) => {
  const box = await boxCore(t);
  const text = { 1: scalarText('1'), 2: scalarText('2'), 3: scalarText('3'), 4: scalarText('4'), 5: scalarText('5'), 6: scalarText('6') };
  box.seed(({ parts, store }) => {
    parts.meta.putKey({ ...googleRow(BOX_REF, 'master'), projects: [], gen_current: 4 });
    store.putKeyInfo(BOX_REF, { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
    const statuses = { 1: 'retired', 2: 'grace', 3: 'failed', 4: 'current', 5: 'failed', 6: 'pending' } as const;
    for (const gen of [1, 2, 3, 4, 5, 6] as const) {
      parts.vault.put(BOX_REF, gen, Buffer.from(text[gen], 'latin1'));
      store.putGen({ keyref: BOX_REF, gen, status: statuses[gen], platformKeyId: null, location: {} });
    }
  });
  await box.start();
  // gen_current + 1 (5) is failed and its value is still in the vault: listing by arithmetic would publish it and miss 6 (failure 8).
  assert.deepEqual(await jwks(box), { keys: [jwkOf(text[6]), jwkOf(text[4]), jwkOf(text[2])] });
});

test('KBOX-55 a listed generation whose value the vault no longer lends is left out of the JWKS', async (t) => {
  const box = await boxCore(t);
  box.seed(({ parts, store }) => {
    parts.meta.putKey({ ...googleRow(BOX_REF, 'master'), projects: [], gen_current: 2 });
    store.putKeyInfo(BOX_REF, { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
    store.putGen({ keyref: BOX_REF, gen: 1, status: 'grace', platformKeyId: null, location: {} });
    parts.vault.put(BOX_REF, 2, Buffer.from(scalarText('current'), 'latin1'));
    store.putGen({ keyref: BOX_REF, gen: 2, status: 'current', platformKeyId: null, location: {} });
  });
  await box.start();
  assert.deepEqual(await jwks(box), { keys: [jwkOf(scalarText('current'))] });
});

test('KBOX-55 the JWKS never lists another google master key: only the box key\'s generations are published', async (t) => {
  const box = await boxCore(t);
  box.seed(({ parts, store }) => {
    parts.meta.putKey({ ...googleRow(BOX_REF, 'master'), projects: [] });
    store.putKeyInfo(BOX_REF, { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
    parts.vault.put(BOX_REF, 1, Buffer.from(scalarText('box'), 'latin1'));
    store.putGen({ keyref: BOX_REF, gen: 1, status: 'current', platformKeyId: null, location: {} });
    // A scalar-shaped value under another google master row: listing every master row would publish it.
    parts.meta.putKey(googleRow('google/shop/OTHER_MASTER', 'master'));
    store.putKeyInfo('google/shop/OTHER_MASTER', { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
    parts.vault.put('google/shop/OTHER_MASTER', 1, Buffer.from(scalarText('other'), 'latin1'));
    store.putGen({ keyref: 'google/shop/OTHER_MASTER', gen: 1, status: 'current', platformKeyId: null, location: {} });
  });
  await box.start();
  assert.deepEqual(await jwks(box), { keys: [jwkOf(scalarText('box'))] });
});

// --- the share file ------------------------------------------------------------------------------------------------------------------

test('KBOX-55 KBOX-33 the share file watches a box key\'s pending generation (not as retired); another key\'s pending generation is still not listed', async (t) => {
  const clock = new TimedClock(NOW);
  const parts = openCore({ stateDir: join(await tempDir(t), 'state'), clock, scheduler: clock, random: seededRandom(8) });
  t.after(() => parts.close());
  const store = createRotationStore(parts.db, clock, parts.hub);
  const entry = createGoogleEntry(googleDeps(clock));
  const source = createPlatformSource({ registry: [entry], meta: parts.meta, vault: parts.vault, keyInfo: (keyref) => store.keyInfo(keyref) });
  for (const keyref of [BOX_REF, 'google/p/MAPS_KEY']) {
    parts.meta.putKey({ ...googleRow(keyref, keyref === BOX_REF ? 'master' : 'admin'), projects: [] });
    store.putKeyInfo(keyref, { scopeItems: [], location: {}, rotatedAt: NOW, markAdmin: false });
    for (const [gen, status] of [[1, 'current'], [2, 'pending']] as const) {
      parts.vault.put(keyref, gen, Buffer.from(scalarText(`${keyref}-${gen}`), 'latin1'));
      store.putGen({ keyref, gen, status, platformKeyId: null, location: {} });
    }
  }
  const share = createMetaShareSource({
    meta: parts.meta,
    values: parts.share.values,
    shapeOf: (platform, keyref) => kitFor(source, { platform, keyref })?.shape,
    boxMade: (platform, keyref) => kitFor(source, { platform, keyref })?.boxKey !== undefined,
    generations: (keyref) => store.gens(keyref),
  });
  const listed = (await share.keys()).map((k) => ({ name: k.name, gen: k.gen, retired: k.retired, watched: k.value !== '' }));
  assert.deepEqual(listed, [
    { name: 'MAPS_KEY', gen: 1, retired: false, watched: true },
    { name: 'OIDC_SIGNING_KEY', gen: 1, retired: false, watched: true },
    { name: 'OIDC_SIGNING_KEY', gen: 2, retired: false, watched: true },
  ]);
});

// --- no API-key call reaches the box key ---------------------------------------------------------------------------------------------

test('KBOX-55 negative control through the real orchestrator and reconcile: a run and a reconcile of the box key make no issue, revoke, listAt, verify or retire call for it, though the platform has all of them', async (t) => {
  const { entry, calls } = googleWithApiKeys(new FakePlatformWorld(seededRandom(6)));
  // The world's stores exist only once it is built: the registry's source is made over them right after, and the world built again.
  let real: PlatformSource | undefined;
  const now = (): PlatformSource => {
    if (real === undefined) throw new RangeError('kbox-test: the source is read before the world is built');
    return real;
  };
  const w = await rotationWorld(t, {
    source: () => ({
      platform: (id) => now().platform(id),
      destination: (kind) => now().destination(kind),
      master: (platform, at, items) => now().master(platform, at, items),
      masters: (platform) => now().masters(platform),
    }),
  });
  real = createPlatformSource({ registry: [entry], meta: w.parts.meta, vault: w.parts.vault, keyInfo: (keyref) => w.store.keyInfo(keyref) });
  ensureBoxKeys({ registry: [entry], meta: w.parts.meta, vault: w.parts.vault, store: w.store, random: seededRandom(7), clock: w.clock, audit: w.parts.audit });
  w.build();
  assert.deepEqual(gensOf(w.store, BOX_REF), [{ gen: 1, status: 'current' }]);
  w.orch.start({ keyref: BOX_REF, origin: 'approval' });
  await w.settle();
  await w.reconciler.run();
  await w.settle(DAY);
  // `list` is left out: reconcile lists the platform once per master row, and the box key is the platform's master for its API keys.
  const { list: _list, ...forTheBoxKey } = calls;
  assert.deepEqual(forTheBoxKey, { issue: 0, revoke: 0, listAt: 0, verify: 0, retire: 0 });
});
