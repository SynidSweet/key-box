// KBOX-63 (host-model): the start-up and daily grant checks, the discovery document and the signing key's proof, with core's issuer at the tailnet
// origin https://<host> (the fake Google's issuer is oidcIssuer(DOMAIN)). These are the scenarios of test/grant-check.test.ts that started core
// against the old issuer, written again at the new one; the discovery document names the new issuer and jwks_uri.
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { AdapterHttp } from '../src/ports/http.ts';
import type { KeyRow } from '../src/ports/meta.ts';
import type { BoxIdentity, PlatformEntry, RegistryDeps } from '../src/ports/platform.ts';
import type { KeyLocation } from '../src/ports/types.ts';
import { oidcIssuer } from '../src/pure/box-origins.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { startCore } from '../src/main-core.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { BOX_SUBJECT } from '../src/platforms/google/oidc.ts';
import { openCore } from '../src/shell/core.ts';
import type { CoreParts } from '../src/shell/core.ts';
import { createGrantChecks } from '../src/shell/grant-checks.ts';
import type { GrantChecks } from '../src/shell/grant-checks.ts';
import { createMintedValues } from '../src/shell/minted-values.ts';
import { createPlatformSource } from '../src/shell/platform-source.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import { createRotationStore, readKeyInfo } from '../src/shell/rotation-store.ts';
import { fakeGoogle } from './fakes/google.ts';
import type { FakeGoogle } from './fakes/google.ts';
import { TimedClock, adapterHttpTo, canary, drive, seededRandom, settle, tempDir, waitUntil } from './kit/index.ts';
import type { FakeAdapterHttp } from './kit/index.ts';

const NOW = 1_700_000_000_000;
const DAY = 24 * 3600_000;
const PROVIDER = '//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-oidc';
const DOMAIN = 'box.example';
const IDENTITY: BoxIdentity = { issuer: oidcIssuer(DOMAIN), audience: PROVIDER };
const SA = 'kbox-test-relay@kbox-test-proj.iam.gserviceaccount.com';
const SA_ITEM = 'sa:kbox-test-proj/kbox-test-relay';
const OTHER_SA = 'kbox-test-other@kbox-test-two.iam.gserviceaccount.com';
const OTHER_ITEM = 'sa:kbox-test-two/kbox-test-other';
const API_ITEM = 'api:firestore.googleapis.com';
const KEYREF = 'google/kbox-test-proj/FIRESTORE';
/** KBOX-55: the box's signing key is keyrefOf('google', [], 'OIDC_SIGNING_KEY'); any other google master row stops its creation. */
const MASTER_REF = 'google/p/OIDC_SIGNING_KEY';
const SECOND_MASTER_REF = 'google/box/KBOX_SIGNING_KEY_2';
const READ_ONLY = 'https://www.googleapis.com/auth/cloud-platform.read-only';
const CRM = 'cloudresourcemanager.googleapis.com';

/** KBOX-24's list, in the spec's order. */
const NINE = [
  'iam.serviceAccountKeys.create',
  'iam.serviceAccounts.getAccessToken',
  'iam.serviceAccounts.signBlob',
  'iam.serviceAccounts.signJwt',
  'iam.serviceAccounts.actAs',
  'iam.serviceAccounts.implicitDelegation',
  'resourcemanager.projects.setIamPolicy',
  'storage.hmacKeys.create',
  'secretmanager.versions.access',
];
/** The refusal code that names a permission: `holds_` and the permission, lower case, dots as underscores. */
const named = (permission: string): string => `holds_${permission.toLowerCase().replaceAll('.', '_')}`;

const D = createHash('sha256').update('kbox-test-signing-1').digest();
const SIGNING_VALUE = D.toString('base64url');
const SIGNING = (() => {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(D);
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  return { x, y, kid: createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url') };
})();

const row = (keyref: string, cls: KeyRow['class'], projects: readonly string[]): KeyRow => ({
  keyref,
  platform: 'google',
  name: keyref.split('/')[2] ?? 'X',
  projects,
  class: cls,
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

async function google(t: TestContext): Promise<FakeGoogle> {
  const g = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  g.trust([{ kty: 'EC', crv: 'P-256', ...SIGNING }]);
  g.creatorOn([SA, OTHER_SA]);
  return g;
}

interface Seed {
  /** The granted key's stored scope items (KBOX-41: the `sa:` item is its target). */
  readonly scope?: readonly string[] | null;
  /** The granted key's `projects`, which the check never reads. */
  readonly projects?: readonly string[];
  /** How many signing-key master rows the store holds. */
  readonly masters?: 0 | 1 | 2;
}

/** The box's signing key(s) as master rows with their stored record, and one granted Google key with its stored scope. */
function seed(parts: Pick<CoreParts, 'meta' | 'vault' | 'db' | 'hub'>, clock: TimedClock, options: Seed = {}): void {
  const rotation = createRotationStore(parts.db, clock, parts.hub);
  for (const ref of [MASTER_REF, SECOND_MASTER_REF].slice(0, options.masters ?? 1)) {
    parts.meta.putKey(row(ref, 'master', ref === MASTER_REF ? [] : ['box']));
    parts.vault.put(ref, 1, Buffer.from(SIGNING_VALUE));
    rotation.putKeyInfo(ref, { scopeItems: [], location: {}, rotatedAt: clock.now(), markAdmin: false });
    // The generation row the box key's creation at start finds, so a restart makes no second key (KBOX-55).
    rotation.putGen({ keyref: ref, gen: 1, status: 'current', platformKeyId: null, location: {} });
  }
  parts.meta.putKey(row(KEYREF, 'admin', options.projects ?? ['kbox-test-proj']));
  if (options.scope !== null) rotation.putKeyInfo(KEYREF, { scopeItems: options.scope ?? [SA_ITEM], location: {}, rotatedAt: clock.now(), markAdmin: false });
  parts.meta.addMachine({ label: 'ci', scope: 'relay', tokenSha256: 'a'.repeat(64), enrolledAt: NOW });
  parts.meta.putGrant(KEYREF, 'ci');
}

interface Core {
  readonly google: FakeGoogle;
  readonly clock: TimedClock;
  readonly stateDir: string;
  readonly journal: readonly string[];
  readonly closed: Promise<void>;
  /** testIamPermissions answers core has received (not just requests the fake has seen): a check counted here is no longer in flight. */
  crmAnswered(): number;
  call(path: string, o?: { readonly body?: unknown; readonly phone?: true }): Promise<{ status: number; body: string }>;
  stop(): Promise<void>;
}

interface CoreOptions {
  readonly beforeStart?: (parts: CoreParts) => void;
  /** Runs before each testIamPermissions request goes out (a test holds it here). */
  readonly beforeCrm?: () => Promise<void>;
  readonly platforms?: PlatformSource;
}

async function core(t: TestContext, options: CoreOptions = {}): Promise<Core> {
  const g = await google(t);
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const socket = join(dir, 'http.sock');
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(NOW);
  const random = seededRandom(5);
  const token = newToken(random);
  const prepared = openCore({ stateDir, clock, scheduler: clock, random });
  prepared.meta.addMachine({ label: 'mc', scope: 'control', tokenSha256: hashToken(token), enrolledAt: NOW });
  // Its projects name another valid service account: a target read from them would check the wrong one (negative control).
  seed(prepared, clock, { projects: [OTHER_SA] });
  options.beforeStart?.(prepared);
  prepared.close();
  const env = { KB_STATE_DIR: stateDir, KB_SOCKET: socket, KB_INSTALL_RESULTS: join(dir, 'results'), KB_CURRENT: join(dir, 'current'), KB_DOMAIN: DOMAIN, KB_OIDC_AUDIENCE: PROVIDER };
  const fake = adapterHttpTo(g);
  let crmAnswered = 0;
  const http: AdapterHttp = {
    request: async (req) => {
      const crm = req.url.endsWith(':testIamPermissions');
      if (crm) await options.beforeCrm?.();
      const response = await fake.request(req);
      if (crm) crmAnswered += 1;
      return response;
    },
  };
  const journal: string[] = [];
  // Core hands the entry its own identity, scanner sink and stored-record reader; the test swaps in only the client.
  const started = await startCore(env, {
    clock,
    scheduler: clock,
    random,
    journal: (code) => void journal.push(code),
    registry: (deps) => [createGoogleEntry({ ...deps, http })],
    ...(options.platforms === undefined ? {} : { platforms: options.platforms }),
  });
  t.after(() => started.stop());
  const driver = drive(socket);
  return {
    google: g,
    clock,
    stateDir,
    journal,
    closed: started.closed,
    crmAnswered: () => crmAnswered,
    stop: () => started.stop(),
    call: async (path, o = {}) => {
      const headers: Record<string, string> = { 'x-kb-client-ip': '203.0.113.9', ...(o.phone === true ? {} : { authorization: `Bearer ${token}` }), ...(o.body === undefined ? {} : { 'content-type': 'application/json' }) };
      const reply = await driver.request({ path, method: o.body === undefined ? 'GET' : 'POST', headers, ...(o.body === undefined ? {} : { body: JSON.stringify(o.body) }) });
      return { status: reply.status, body: reply.body };
    },
  };
}

const crmCalls = (g: FakeGoogle): number => g.requests.filter((r) => r.path.endsWith(':testIamPermissions')).length;

/** The grants of the key as a fresh opening of the stopped core's store reads them, and its audit actions. */
function afterStop(stateDir: string): { readonly grants: readonly string[]; readonly actions: readonly string[] } {
  const clock = new TimedClock(NOW);
  const parts = openCore({ stateDir, clock, scheduler: clock, random: seededRandom(6) });
  try {
    return { grants: parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.grants.map((g) => g.machine) ?? [], actions: parts.audit.read(0).entries.map((e) => e.action) };
  } finally {
    parts.close();
  }
}

test('KBOX-41 the discovery document names issuer https://<host> and jwks_uri https://<host>/.well-known/jwks.json', async (t) => {
  const c = await core(t);
  const discovery = await c.call('/.well-known/openid-configuration', { phone: true });
  assert.equal(discovery.status, 200, discovery.body);
  const doc = JSON.parse(discovery.body) as Record<string, unknown>;
  assert.equal(doc['issuer'], 'https://box.example');
  assert.equal(doc['jwks_uri'], 'https://box.example/.well-known/jwks.json');
  const jwks = await c.call('/.well-known/jwks.json', { phone: true });
  assert.equal(jwks.status, 200, jwks.body);
  assert.deepEqual(JSON.parse(jwks.body), { keys: [{ kty: 'EC', crv: 'P-256', x: SIGNING.x, y: SIGNING.y, kid: SIGNING.kid, alg: 'ES256', use: 'sig' }] });
  assert.equal(jwks.body.includes(SIGNING_VALUE), false);
});

test('KBOX-24 KBOX-41 a grant proposed through core\'s proposal route is checked with core\'s own identity, sink and stored record: refused with 422 naming the permission, and a clean one opens an approval at the tailnet issuer', async (t) => {
  const c = await core(t);
  await waitUntil(() => c.crmAnswered() === 1, 'the start-up grant check answered');
  c.google.holds(SA, ['iam.serviceAccounts.actAs']);
  const refused = await c.call('/api/proposals', { body: { action: { kind: 'grant', keyref: KEYREF, machine: 'ci' } } });
  assert.equal(refused.status, 422, refused.body);
  assert.deepEqual((JSON.parse(refused.body) as { error: { detail: unknown } }).error.detail, { code: named('iam.serviceAccounts.actAs') });
  c.google.holds(SA, []);
  const opened = await c.call('/api/proposals', { body: { action: { kind: 'grant', keyref: KEYREF, machine: 'ci' } } });
  assert.equal(opened.status, 201, opened.body);
});

/** A rotation store over a stopped core's state directory, closed when the test ends. */
function storeAfterStop(t: TestContext, stateDir: string): ReturnType<typeof createRotationStore> {
  const clock = new TimedClock(NOW);
  const parts = openCore({ stateDir, clock, scheduler: clock, random: seededRandom(6) });
  t.after(() => parts.close());
  return createRotationStore(parts.db, clock, parts.hub);
}

test('KBOX-55 a successful mint exchange through core (the start-up grant check) marks the signing key\'s current generation proven, never its pending one at the tailnet issuer', async (t) => {
  const c = await core(t, {
    beforeStart: (parts) => {
      // A rotation in flight: generation 2 is published (pending) and Google trusts it too, but nothing has signed with it.
      const pending = createHash('sha256').update('kbox-test-signing-2').digest().toString('base64url');
      parts.vault.put(MASTER_REF, 2, Buffer.from(pending));
      createRotationStore(parts.db, new TimedClock(NOW), parts.hub).putGen({ keyref: MASTER_REF, gen: 2, status: 'pending', platformKeyId: null, location: {} });
    },
  });
  await waitUntil(() => c.crmAnswered() === 1, 'the start-up grant check answered');
  await c.stop();
  await c.closed;
  const store = storeAfterStop(t, c.stateDir);
  assert.deepEqual(store.gens(MASTER_REF).map((g) => [g.gen, g.status, g.provedAt]), [
    [1, 'current', NOW],
    [2, 'pending', null],
  ]);
});

test('KBOX-24 core checks granted keys at start and then every day: a permission found a day later suspends the grant at the tailnet issuer', async (t) => {
  const c = await core(t);
  // Waits for core to have the start-up check's answer, not only for the request: advancing a day runs every timer at once and holds the
  // event loop, and an answer still in flight then could time out and fail closed for a reason this test is not about.
  await waitUntil(() => c.crmAnswered() === 1, 'the start-up grant check answered');
  c.google.holds(SA, ['secretmanager.versions.access']);
  c.clock.advance(DAY - 1);
  assert.equal(crmCalls(c.google), 1, 'not before a day has passed');
  c.clock.advance(1);
  const meta = async (): Promise<{ keys: { keyref: string; grants: unknown[] }[] }> => JSON.parse((await c.call('/api/meta')).body) as { keys: { keyref: string; grants: unknown[] }[] };
  let grants: unknown[] = ['ci'];
  for (let i = 0; i < 200 && grants.length > 0; i += 1) grants = (await meta()).keys.find((k) => k.keyref === KEYREF)?.grants ?? [];
  assert.deepEqual(grants, []);
  assert.equal(crmCalls(c.google), 2);
});

test('KBOX-24 stop waits for the grant check in flight before closing the stores: its suspension is written, nothing fails on a closed store at the tailnet issuer', async (t) => {
  let release = (): void => undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let crmAsked = false;
  const c = await core(t, {
    beforeCrm: async () => {
      crmAsked = true;
      await held;
    },
  });
  c.google.holds(SA, ['storage.hmacKeys.create']);
  await waitUntil(() => crmAsked, 'the start-up grant check asked testIamPermissions');
  let closed = false;
  void c.closed.then(() => {
    closed = true;
  });
  await c.stop();
  await settle();
  assert.equal(closed, false, 'the stores stay open while the check is in flight');
  release();
  await c.closed;
  assert.deepEqual(c.journal.filter((j) => j.startsWith('audit_failed')), []);
  const after = afterStop(c.stateDir);
  assert.deepEqual(after.grants, []);
  assert.equal(after.actions.includes('grant.suspended'), true);
});
