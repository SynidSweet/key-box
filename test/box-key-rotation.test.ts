// KBOX-55 (the run): the box's own Google signing key is rotated by publish, wait, prove, switch. The new generation is published in the JWKS
// at once (pending), the run waits the publish lead, proves Google has taken it with one STS exchange signed with it (retried with the KBOX-17
// backoff until opened_at + 2 x lead), and only then switches; the old generation stays listed through grace and its value is then deleted.
// A failure keeps the old key current and deletes the new value. No step, rollback included, ever asks for the platform's master (each test
// reads the `masterAsked` spy). The real google entry runs against a fake Google; the FakeClock drives every wait.
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { MintedSink } from '../src/ports/minted.ts';
import type { BoxIdentity, BoxMadeKey, PlatformEntry } from '../src/ports/platform.ts';
import type { KeyRow } from '../src/ports/meta.ts';
import { ApiError, VaultError } from '../src/pure/errors.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { BOX_SUBJECT, signAssertion } from '../src/platforms/google/oidc.ts';
import { ensureBoxKeys } from '../src/shell/box-keys.ts';
import { identityRoutes } from '../src/shell/identity-routes.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import type { GenRow } from '../src/shell/rotation-store.ts';
import { fakeGoogle } from './fakes/google.ts';
import type { FakeGoogle, TrustedJwk } from './fakes/google.ts';
import { rotationWorld } from './support/rotation-world.ts';
import type { RotationWorld } from './support/rotation-world.ts';
import { adapterHttpTo, seededRandom } from './kit/index.ts';

const BOX_REF = 'google/p/OIDC_SIGNING_KEY';
const OTHER_MASTER = 'google/shop/OTHER_MASTER';
const AUDIENCE = '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-prov';
const IDENTITY: BoxIdentity = { issuer: 'https://keys.box.example', audience: AUDIENCE };
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
/** KBOX-55 "The lead": JWKS_PUBLISH_LEAD_MS is 24 hours. */
const LEAD = 24 * HOUR;
/** The box key's grace (KBOX-55 creation: `grace_hours` 1). */
const GRACE = HOUR;

interface PublicJwk extends TrustedJwk {
  readonly alg: 'ES256';
  readonly use: 'sig';
}

/** The public JWK of a scalar given as 43 base64url characters, computed here (RFC 7638 thumbprint as kid), independent of src. */
function jwkOf(text: string): PublicJwk {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(text, 'base64url'));
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  const kid = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url');
  return { kty: 'EC', crv: 'P-256', x, y, kid, alg: 'ES256', use: 'sig' };
}

/** An independent check of a compact ES256 JWT (WebCrypto) against a JWKS: the key its kid names exists there and verifies the signature. */
async function verifies(jwt: string, jwks: { readonly keys: readonly PublicJwk[] }): Promise<boolean> {
  const [h, p, s] = jwt.split('.');
  if (h === undefined || p === undefined || s === undefined) return false;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as { kid?: unknown };
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (jwk === undefined) return false;
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(s, 'base64url'), Buffer.from(`${h}.${p}`));
}

const masterRow = (keyref: string): KeyRow => ({
  keyref,
  platform: 'google',
  name: keyref.split('/')[2] ?? 'X',
  projects: ['shop'],
  class: 'master',
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

interface BoxWorld {
  readonly w: RotationWorld;
  readonly google: FakeGoogle;
  readonly box: BoxMadeKey;
  /** Every platform the run asked the source for a master of (KBOX-55: never, for a box key). */
  readonly masterAsked: readonly string[];
  /** The source the orchestrator reads, as built from the registry: its own answer for a google master. */
  readonly real: PlatformSource;
  /** The JWKS core serves now (the identity route). */
  jwks(): Promise<{ readonly keys: readonly PublicJwk[] }>;
  /** Google fetches the JWKS now: from here its STS takes exactly those keys. */
  googleFetches(): Promise<void>;
  stsCalls(): number;
  /** The text of a generation's value, or undefined once the vault holds it no more. */
  valueOf(gen: number): Promise<string | undefined>;
  gens(): readonly Pick<GenRow, 'gen' | 'status'>[];
  /** Moves the clock forward a minute at a time, letting every run work at each step. */
  pass(ms: number): Promise<void>;
}

/**
 * The rotation world with the real google entry (over a fake Google that trusts nothing yet) as its platform source, the box key made as
 * core makes it at start (generation 1 current), and, unless `secondMaster` is false, a second google master row left from old data.
 */
async function boxWorld(t: TestContext, o: { readonly federation?: boolean; readonly secondMaster?: boolean } = {}): Promise<BoxWorld> {
  const google = await fakeGoogle(t, { audience: AUDIENCE, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  const sink: MintedSink = { add: () => undefined };
  const masterAsked: string[] = [];
  let real: PlatformSource | undefined;
  const now = (): PlatformSource => {
    if (real === undefined) throw new RangeError('kbox-test: the source is read before the world is built');
    return real;
  };
  const w = await rotationWorld(t, {
    ...(o.federation === false ? {} : { federation: { identity: IDENTITY, minted: sink } }),
    source: () => ({
      platform: (id) => now().platform(id),
      destination: (kind) => now().destination(kind),
      master: (platform, at, items) => {
        masterAsked.push(platform);
        return now().master(platform, at, items);
      },
      masters: (platform) => now().masters(platform),
    }),
  });
  const entry: PlatformEntry = createGoogleEntry({ http: adapterHttpTo(google), clock: w.clock });
  const box = entry.boxKey;
  assert.ok(box !== undefined);
  const built = createPlatformSource({ registry: [entry], meta: w.parts.meta, vault: w.parts.vault, keyInfo: (keyref) => w.store.keyInfo(keyref) });
  real = built;
  ensureBoxKeys({ registry: [entry], meta: w.parts.meta, vault: w.parts.vault, store: w.store, random: seededRandom(7), clock: w.clock, audit: w.parts.audit });
  if (o.secondMaster !== false) {
    // Added after creation (which it would stop): a P-256 scalar under another google master row, so the platform has two masters.
    w.parts.meta.putKey(masterRow(OTHER_MASTER));
    w.store.putKeyInfo(OTHER_MASTER, { scopeItems: [], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
    w.parts.vault.put(OTHER_MASTER, 1, Buffer.from(createHash('sha256').update('kbox-test-other-master').digest().toString('base64url'), 'latin1'));
    w.store.putGen({ keyref: OTHER_MASTER, gen: 1, status: 'current', platformKeyId: null, location: {} });
  }
  w.build();
  const [, jwksRoute] = identityRoutes({ registry: [entry], source: built, meta: w.parts.meta, vault: w.parts.vault, generations: (keyref) => w.store.gens(keyref), issuer: IDENTITY.issuer });
  assert.ok(jwksRoute !== undefined);
  const jwks = async (): Promise<{ readonly keys: readonly PublicJwk[] }> => {
    const reply = await jwksRoute.run({ actor: 'box', source: { address: '203.0.113.9', network: '203.0.113.0/24' }, abort: new AbortController().signal, query: new URLSearchParams(), body: undefined, params: {}, cookie: undefined });
    assert.ok('json' in reply);
    return reply.json as { keys: PublicJwk[] };
  };
  return {
    w,
    google,
    box,
    masterAsked,
    real: built,
    jwks,
    googleFetches: async () => google.trust((await jwks()).keys),
    stsCalls: () => google.requests.filter((r) => r.path === '/v1/token').length,
    valueOf: async (gen) => {
      try {
        return await w.valueOf(BOX_REF, gen);
      } catch (error) {
        if (error instanceof VaultError && error.failure === 'unknown_key') return undefined;
        throw error;
      }
    },
    gens: () => w.store.gens(BOX_REF).map(({ gen, status }) => ({ gen, status })),
    async pass(ms) {
      const end = w.clock.now() + ms;
      while (w.clock.now() < end) {
        w.clock.advance(Math.min(MINUTE, end - w.clock.now()));
        await w.orch.idle();
      }
    },
  };
}

/** Starts a run of the box key as an approved request would, and lets it work until it waits. */
async function rotate(b: BoxWorld): Promise<string> {
  const run = b.w.orch.start({ keyref: BOX_REF, origin: 'approval' });
  await b.w.orch.idle();
  return run.runId;
}

const runOf = (b: BoxWorld, runId: string) => {
  const run = b.w.store.run(runId);
  assert.ok(run !== undefined);
  return run;
};

test('KBOX-55 KBOX-59 as of the API-key issuer a left-over google row labelled master is no second master: it classifies every key but the box key ordinary, so the platform source still answers the box key', async (t) => {
  const b = await boxWorld(t);
  assert.equal(b.real.master('google', {}, []).ok, true);
});

test('KBOX-55 happy path, STS refusing twice then accepting: the new key is listed at once, nothing is asked of STS before the lead, the switch waits for the proof, grace keeps the old key listed, then its value is gone; no master is ever asked and no other Google call is made', async (t) => {
  const b = await boxWorld(t);
  await b.googleFetches();
  const old = await b.valueOf(1);
  assert.ok(old !== undefined);
  const runId = await rotate(b);
  const fresh = await b.valueOf(2);
  assert.ok(fresh !== undefined);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'pending' }]);
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(fresh), jwkOf(old)] }, 'the JWKS lists the new key at once, newest first');
  await b.pass(LEAD - MINUTE);
  assert.equal(b.stsCalls(), 0, 'no proof before the lead');
  // Google still holds the JWKS it fetched before the run: the first two proofs are refused, the first retry a minute after the first.
  await b.pass(MINUTE);
  assert.equal(b.stsCalls(), 1);
  await b.pass(MINUTE);
  assert.equal(b.stsCalls(), 2);
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 1, 'no switch while Google refuses the new key');
  assert.equal(runOf(b, runId).state, 'checking');
  await b.googleFetches();
  // The second retry comes 2 minutes after the second refusal.
  await b.pass(MINUTE);
  assert.equal(b.stsCalls(), 2);
  await b.pass(MINUTE);
  assert.equal(b.stsCalls(), 3);
  const switchedAt = b.w.clock.now();
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 2);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'grace' }, { gen: 2, status: 'current' }]);
  assert.equal(b.w.store.gen(BOX_REF, 2)?.provedAt, switchedAt, 'the generation is marked proven by its proof');
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(fresh), jwkOf(old)] }, 'grace keeps the old key listed');
  await b.pass(GRACE - MINUTE);
  assert.equal(await b.valueOf(1), old, 'the old value is kept through grace');
  await b.pass(MINUTE);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'retired' }, { gen: 2, status: 'current' }]);
  assert.equal(await b.valueOf(1), undefined, 'revoking deletes the old value: its death (KBOX-51 step 10 exception)');
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(fresh)] });
  assert.equal(runOf(b, runId).state, 'done');
  assert.equal(b.w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.completed').length, 1);
  assert.deepEqual(b.w.events('rotation.failed'), []);
  assert.deepEqual(b.masterAsked, [], 'no step asked for a master');
  assert.ok(b.google.requests.every((r) => r.path === '/v1/token'), 'the STS proof is the only Google call');
});

test('KBOX-55 STS refusing until opened_at + 2 x lead fails the run jwks_not_taken: the new key failed and its value deleted, the JWKS shows the old key only, which Google still takes, one notice, the old generation unproven again, no master asked', async (t) => {
  const b = await boxWorld(t);
  await b.googleFetches();
  b.w.store.markProved(BOX_REF, 1, b.w.clock.now());
  const old = await b.valueOf(1);
  assert.ok(old !== undefined);
  const runId = await rotate(b);
  await b.pass(2 * LEAD - MINUTE);
  assert.equal(runOf(b, runId).state, 'checking', 'still trying a minute before the deadline');
  await b.pass(MINUTE);
  const run = runOf(b, runId);
  assert.deepEqual([run.state, run.failedStep, run.reasonCode], ['failed', 'checking', 'jwks_not_taken']);
  assert.ok(b.stsCalls() > 2, 'retried with the backoff');
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'failed' }]);
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 1);
  assert.equal(await b.valueOf(2), undefined);
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(old)] });
  assert.equal(b.w.events('rotation.failed').length, 1);
  assert.equal(b.w.push.sent.filter((m) => m.kind === 'rotation_failed').length, 1);
  assert.equal(b.w.store.gen(BOX_REF, 1)?.provedAt, null, 'clearProved: no daily approval for a provider that no longer trusts the box');
  assert.equal(await b.box.prove(b.w.parts.vault.lend(BOX_REF, 1), IDENTITY, { add: () => undefined }), 'ok', 'the old key still signs');
  assert.deepEqual(b.masterAsked, [], 'no master asked, rollback included');
});

test('KBOX-55 after a failed run (N+1 failed) the next run lists N+2 with N during the lead, and N in grace after the switch', async (t) => {
  const b = await boxWorld(t);
  await b.googleFetches();
  const old = await b.valueOf(1);
  assert.ok(old !== undefined);
  await rotate(b);
  await b.pass(2 * LEAD);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'failed' }]);
  await rotate(b);
  const third = await b.valueOf(3);
  assert.ok(third !== undefined);
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(third), jwkOf(old)] });
  await b.googleFetches();
  await b.pass(LEAD);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'grace' }, { gen: 2, status: 'failed' }, { gen: 3, status: 'current' }]);
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(third), jwkOf(old)] });
});

test('KBOX-55 STS never answering usably until opened_at + 2 x lead fails the run sts_unreachable: the old key stays current and keeps its proof, one notice, no master asked', async (t) => {
  const b = await boxWorld(t);
  await b.googleFetches();
  b.w.store.markProved(BOX_REF, 1, b.w.clock.now());
  const old = await b.valueOf(1);
  assert.ok(old !== undefined);
  b.google.override('sts', { kind: 'status', status: 503, body: '{}' });
  const runId = await rotate(b);
  await b.pass(2 * LEAD);
  const run = runOf(b, runId);
  assert.deepEqual([run.state, run.failedStep, run.reasonCode], ['failed', 'checking', 'sts_unreachable']);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'failed' }]);
  assert.equal(await b.valueOf(2), undefined);
  assert.deepEqual(await b.jwks(), { keys: [jwkOf(old)] });
  assert.equal(b.w.events('rotation.failed').length, 1);
  assert.equal(b.w.store.gen(BOX_REF, 1)?.provedAt, b.w.clock.now() - 2 * LEAD, 'only jwks_not_taken clears the proof');
  assert.deepEqual(b.masterAsked, []);
});

test('KBOX-55 a process stopped after verifying and started again at half the lead does not switch early; the stored wait time re-arms and the run proves and switches at opened_at + lead, with no second new generation', async (t) => {
  const b = await boxWorld(t);
  b.w.checkpoints.arm('verifying');
  const openedAt = b.w.clock.now();
  const runId = await rotate(b);
  assert.equal(runOf(b, runId).state, 'checking');
  await b.googleFetches();
  b.w.build();
  await b.pass(LEAD / 2);
  await b.w.orch.resume();
  assert.equal(b.stsCalls(), 0, 'no proof at the restart');
  await b.pass(LEAD / 2 - MINUTE);
  assert.equal(b.stsCalls(), 0, 'no proof before the lead');
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 1);
  await b.pass(MINUTE);
  assert.equal(b.w.clock.now(), openedAt + LEAD);
  assert.equal(b.stsCalls(), 1);
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 2, 'switched at the stored wait time');
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'grace' }, { gen: 2, status: 'current' }]);
});

test('KBOX-55 N\' gone from the vault after checking: the run fails pending_missing at promoting, gen_current never moves, one notice, no master asked', async (t) => {
  const b = await boxWorld(t);
  await b.googleFetches();
  b.w.checkpoints.hook = (point) => {
    if (point === 'checking') b.w.parts.vault.retire(BOX_REF, 2);
    return Promise.resolve();
  };
  const runId = await rotate(b);
  await b.googleFetches();
  await b.pass(LEAD);
  const run = runOf(b, runId);
  assert.deepEqual([run.state, run.failedStep, run.reasonCode], ['failed', 'promoting', 'pending_missing']);
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 1);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'failed' }]);
  assert.equal(b.w.events('rotation.failed').length, 1);
  assert.deepEqual(b.masterAsked, []);
});

test('KBOX-55 a JWT minted just before promote verifies against the JWKS served just after, and one minted just after promote against the JWKS served just before', async (t) => {
  const b = await boxWorld(t);
  const signed: { before?: string; jwks?: { readonly keys: readonly PublicJwk[] } } = {};
  b.w.checkpoints.hook = async (point) => {
    // `checking` is persisted: the run is about to promote. Minting reads gen_current once.
    if (point !== 'checking') return;
    const current = b.w.store.key(BOX_REF)?.genCurrent ?? 0;
    signed.before = await signAssertion(IDENTITY, b.w.parts.vault.lend(BOX_REF, current), b.w.clock.now());
    signed.jwks = await b.jwks();
  };
  await rotate(b);
  await b.googleFetches();
  await b.pass(LEAD);
  assert.equal(b.w.store.key(BOX_REF)?.genCurrent, 2);
  assert.ok(signed.before !== undefined && signed.jwks !== undefined);
  assert.equal(await verifies(signed.before, await b.jwks()), true, 'signed with N, verified after the switch');
  const after = await signAssertion(IDENTITY, b.w.parts.vault.lend(BOX_REF, 2), b.w.clock.now());
  assert.equal(await verifies(after, signed.jwks), true, 'signed with N\', verified against the JWKS before the switch');
});

test('KBOX-55 a second run of the box key while one is open is refused run_exists, and makes no new generation', async (t) => {
  const b = await boxWorld(t);
  await rotate(b);
  assert.throws(() => b.w.orch.start({ keyref: BOX_REF, origin: 'approval' }), (e: unknown) => e instanceof ApiError && e.code === 'conflict' && e.detail !== undefined && 'code' in e.detail && e.detail.code === 'run_exists');
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'pending' }]);
});

test('KBOX-55 with no audience configured the run fails identity_unconfigured once the lead has passed, with no Google call and the old key current', async (t) => {
  const b = await boxWorld(t, { federation: false });
  const runId = await rotate(b);
  await b.pass(LEAD);
  const run = runOf(b, runId);
  assert.deepEqual([run.state, run.reasonCode], ['failed', 'identity_unconfigured']);
  assert.equal(b.google.requests.length, 0);
  assert.deepEqual(b.gens(), [{ gen: 1, status: 'current' }, { gen: 2, status: 'failed' }]);
});
