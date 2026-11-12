// KBOX-24: the service-account grant check. When a grant of a Google key that acts as a service account (its stored scope holds an `sa:`
// item, KBOX-41) is proposed, and again daily, core impersonates that key's stored target and calls testIamPermissions on the target's
// project for the nine permissions; one held refuses the grant naming it (or suspends a granted key with exactly one notice), none passes, a
// key with no `sa:` item is never checked or suspended, and a check that cannot be made fails closed. Also core's wiring of it (the proposal
// route, the start-up and daily runs, stop) and of the two OIDC documents (KBOX-41) on the phone side of keys.<domain>.
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
import { ApiError } from '../src/pure/errors.ts';
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
const IDENTITY: BoxIdentity = { issuer: `https://keys.${DOMAIN}`, audience: PROVIDER };
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

interface Shell {
  readonly google: FakeGoogle;
  readonly http: FakeAdapterHttp;
  readonly parts: CoreParts;
  readonly checks: GrantChecks;
  notices(): readonly Readonly<Record<string, unknown>>[];
  suspended(): readonly (readonly [string, unknown])[];
  grants(): readonly string[];
}

interface ShellOptions extends Seed {
  readonly identity?: BoxIdentity | null;
  /** In place of the real google entry (built over the same deps). */
  readonly entry?: (deps: RegistryDeps) => PlatformEntry;
}

/** createGrantChecks over a real store, the real platform source and the real google entry, as core builds them. */
async function shell(t: TestContext, options: ShellOptions = {}): Promise<Shell> {
  const g = await google(t);
  const http = adapterHttpTo(g);
  const clock = new TimedClock(NOW);
  const parts = openCore({ stateDir: join(await tempDir(t), 'state'), clock, scheduler: clock, random: seededRandom(3) });
  t.after(() => parts.close());
  seed(parts, clock, options);
  const keyInfo = (keyref: string): ReturnType<typeof readKeyInfo> => readKeyInfo(parts.db, keyref);
  const identity = options.identity === null ? {} : { identity: options.identity ?? IDENTITY };
  const deps: RegistryDeps = { http, clock, ...identity, minted: createMintedValues(clock), keyInfo };
  const registry: readonly PlatformEntry[] = [options.entry?.(deps) ?? createGoogleEntry(deps)];
  const source = createPlatformSource({ registry, meta: parts.meta, vault: parts.vault, keyInfo });
  const checks = createGrantChecks({ registry, meta: parts.meta, keyInfo, master: (platform, at, items) => source.master(platform, at, items), audit: parts.audit, events: parts.events, clock });
  return {
    google: g,
    http,
    parts,
    checks,
    notices: () => parts.events.after(0).filter((e) => e.kind === 'box.notice').map((e) => e.data),
    suspended: () => parts.audit.read(0).entries.filter((e) => e.action === 'grant.suspended').map((e) => [e.ref, e.detail] as const),
    grants: () => parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.grants.map((x) => x.machine) ?? [],
  };
}

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ApiError && error.code === 'rejected', `a rejected ApiError, got ${String(error)}`);
    return error.detail !== undefined && 'code' in error.detail ? error.detail.code : '';
  }
  throw new assert.AssertionError({ message: 'expected the grant to be refused' });
}

const grantOf = (keyref = KEYREF) => ({ kind: 'grant', keyref, machine: 'ci2' }) as const;
const testedProjects = (http: FakeAdapterHttp): string[] => http.sent.filter((r) => r.originalHost === CRM).map((r) => r.target);

// --- the check -----------------------------------------------------------------------------------------------------------------------

test('KBOX-24 a proposed grant of an sa: key impersonates its stored target read-only and asks testIamPermissions on the target\'s project for exactly the nine permissions', async (t) => {
  const s = await shell(t);
  await s.checks.atProposal(grantOf());
  const crm = s.http.sent.find((r) => r.originalHost === CRM);
  assert.ok(crm !== undefined);
  assert.equal(`${crm.method} ${crm.target}`, 'POST /v1/projects/kbox-test-proj:testIamPermissions');
  assert.deepEqual(JSON.parse(Buffer.from(crm.body).toString('utf8')), { permissions: NINE });
  const impersonate = s.http.sent.find((r) => r.originalHost === 'iamcredentials.googleapis.com');
  assert.ok(impersonate !== undefined);
  assert.equal(impersonate.target, `/v1/projects/-/serviceAccounts/${SA}:generateAccessToken`);
  assert.deepEqual((JSON.parse(Buffer.from(impersonate.body).toString('utf8')) as { scope: unknown }).scope, [READ_ONLY]);
  assert.match(crm.headers['authorization'] ?? '', /^Bearer ya29\.kbox-test-sa-/, 'asked as the service account itself');
});

test('KBOX-24 a service account holding any one of the nine permissions refuses the grant, naming that permission', async (t) => {
  const s = await shell(t);
  for (const permission of NINE) {
    s.google.holds(SA, [permission]);
    assert.equal(await rejection(s.checks.atProposal(grantOf())), named(permission), permission);
  }
});

test('KBOX-24 a service account holding none of the nine permissions passes, and so does one holding only harmless permissions', async (t) => {
  const s = await shell(t);
  s.google.holds(SA, ['datastore.entities.get', 'storage.objects.get']);
  await s.checks.atProposal(grantOf());
});

test('KBOX-24 KBOX-41 the key is checked as its stored sa: target, never as a service account its projects name (negative control: that one holds a permission)', async (t) => {
  const s = await shell(t, { projects: [OTHER_SA, 'kbox-test-two'] });
  s.google.holds(OTHER_SA, ['iam.serviceAccounts.actAs']);
  await s.checks.atProposal(grantOf());
  assert.deepEqual(testedProjects(s.http), ['/v1/projects/kbox-test-proj:testIamPermissions']);
  assert.equal(s.http.sent.some((r) => r.target.includes(OTHER_SA)), false);
  s.google.holds(SA, ['iam.serviceAccounts.actAs']);
  assert.equal(await rejection(s.checks.atProposal(grantOf())), named('iam.serviceAccounts.actAs'), 'the stored target holding it refuses');
});

test('KBOX-24 a grant of a Google key with no sa: item (an API key) passes at proposal with no call and is never suspended daily, even with no master', async (t) => {
  for (const masters of [1, 0] as const) {
    const s = await shell(t, { scope: [API_ITEM], masters });
    s.google.holds(SA, ['iam.serviceAccounts.actAs']);
    await s.checks.atProposal(grantOf());
    await s.checks.daily();
    assert.equal(s.http.sent.length, 0);
    assert.deepEqual(s.grants(), ['ci']);
    assert.deepEqual(s.notices(), []);
    assert.deepEqual(s.suspended(), []);
  }
});

test('KBOX-24 KBOX-41 a key whose stored scope holds two sa: items is refused at proposal and suspended daily with one notice (target_count), with no call', async (t) => {
  const s = await shell(t, { scope: [SA_ITEM, OTHER_ITEM] });
  assert.equal(await rejection(s.checks.atProposal(grantOf())), 'target_count');
  await s.checks.daily();
  assert.deepEqual(s.grants(), []);
  assert.deepEqual(s.suspended(), [[KEYREF, { code: 'target_count' }]]);
  assert.equal(s.notices().length, 1);
  assert.equal(s.http.sent.length, 0);
});

test('KBOX-24 an unreachable or failing check fails closed: the grant is refused, never allowed', async (t) => {
  const s = await shell(t);
  const cases: [Parameters<FakeGoogle['override']>, string][] = [
    [['test-permissions', { kind: 'cut' }], 'grant_check_unreachable'],
    [['sts', { kind: 'cut' }], 'grant_check_unreachable'],
    [['sts', { kind: 'status', status: 400, body: '{}' }], 'grant_check_failed'],
    [['sts', { kind: 'status', status: 503, body: '{}' }], 'grant_check_failed'],
    [['impersonate', { kind: 'status', status: 403, body: '{}' }], 'grant_check_failed'],
    [['impersonate', { kind: 'status', status: 500, body: '{}' }], 'grant_check_failed'],
    [['test-permissions', { kind: 'status', status: 503, body: '{}' }], 'grant_check_failed'],
    [['test-permissions', { kind: 'status', status: 403, body: '{}' }], 'grant_check_failed'],
    [['test-permissions', { kind: 'status', status: 200, body: 'not json' }], 'grant_check_failed'],
    [['test-permissions', { kind: 'status', status: 200, body: '{"permissions":["iam.roles.create"]}' }], 'grant_check_failed'],
    [['test-permissions', { kind: 'status', status: 200, body: '{"permissions":"all"}' }], 'grant_check_failed'],
  ];
  for (const [[route, override], code] of cases) {
    s.google.override(route, override);
    assert.equal(await rejection(s.checks.atProposal(grantOf())), code, `${route} ${JSON.stringify(override)}`);
    s.google.override(route, undefined);
  }
});

test('KBOX-24 without the box\'s identity, without a stored record, or with no or two signing keys, an sa: grant is refused before any call and suspended daily with one notice', async (t) => {
  const cases: [ShellOptions, string][] = [
    [{ identity: null }, 'grant_check_no_identity'],
    [{ scope: null }, 'grant_check_no_key_info'],
    [{ masters: 0 }, 'grant_check_no_master'],
    [{ masters: 2 }, 'grant_check_master_ambiguous'],
  ];
  for (const [options, code] of cases) {
    const s = await shell(t, options);
    assert.equal(await rejection(s.checks.atProposal(grantOf())), code, code);
    await s.checks.daily();
    assert.deepEqual(s.grants(), [], code);
    assert.deepEqual(s.suspended(), [[KEYREF, { code }]]);
    assert.deepEqual(s.notices(), [{ code: 'grant_suspended', text: 'grant suspended' }], code);
    assert.equal(s.http.sent.length, 0, code);
  }
});

test('KBOX-24 a platform\'s appliesTo that throws counts as applies (fail closed): the check is asked with the key and its stored location', async (t) => {
  const asked: { readonly keyref: string; readonly at: KeyLocation }[] = [];
  const s = await shell(t, {
    scope: [API_ITEM],
    entry: (deps) => ({
      ...createGoogleEntry(deps),
      grantCheck: {
        appliesTo: () => {
          throw new RangeError('kbox-test appliesTo broke');
        },
        check: (subject) => {
          asked.push(subject);
          return Promise.resolve({ verdict: 'refused', code: 'holds_kbox_test' });
        },
      },
    }),
  });
  assert.equal(await rejection(s.checks.atProposal(grantOf())), 'holds_kbox_test');
  assert.deepEqual(asked, [{ keyref: KEYREF, at: {} }]);
});

test('KBOX-24 a grant of a key of another platform, of an unknown key, or another kind of action makes no Google call', async (t) => {
  const s = await shell(t);
  s.parts.meta.putKey({ ...row('openai/shop/OPENAI_KEY', 'admin', ['shop']), platform: 'openai' });
  await s.checks.atProposal(grantOf('openai/shop/OPENAI_KEY'));
  await s.checks.atProposal(grantOf('google/kbox-test-proj/NOPE'));
  await s.checks.atProposal({ kind: 'rotate_key', keyref: KEYREF });
  assert.equal(s.http.sent.length, 0);
});

// --- the daily check -----------------------------------------------------------------------------------------------------------------

test('KBOX-24 the daily check suspends a granted key whose service account now holds a permission and raises exactly one notice', async (t) => {
  const s = await shell(t);
  s.parts.meta.addMachine({ label: 'ci2', scope: 'relay', tokenSha256: 'b'.repeat(64), enrolledAt: NOW });
  s.parts.meta.putGrant(KEYREF, 'ci2');
  s.google.holds(SA, ['iam.serviceAccounts.signJwt']);
  await s.checks.daily();
  assert.deepEqual(s.grants(), []);
  assert.deepEqual(s.notices(), [{ code: 'grant_suspended', text: 'grant suspended' }]);
  assert.deepEqual(s.suspended(), [[KEYREF, { code: named('iam.serviceAccounts.signJwt') }]]);
  await s.checks.daily();
  assert.equal(s.notices().length, 1, 'the next day finds nothing granted, so no second notice');
});

test('KBOX-24 the daily check leaves a clean grant alone and raises nothing', async (t) => {
  const s = await shell(t);
  await s.checks.daily();
  assert.deepEqual(s.grants(), ['ci']);
  assert.deepEqual(s.notices(), []);
});

test('KBOX-24 a daily check that cannot reach Google suspends the grant (fail closed), with one notice', async (t) => {
  const s = await shell(t);
  s.google.override('test-permissions', { kind: 'cut' });
  await s.checks.daily();
  assert.deepEqual(s.grants(), []);
  assert.equal(s.notices().length, 1);
});

test('KBOX-14 KBOX-24 a minted token planted as a canary and echoed in an error body reaches no refusal, audit row or event', async (t) => {
  const s = await shell(t);
  const planted = canary();
  const token = `ya29.${Buffer.from(planted.bytes).toString('base64url')}`;
  s.google.nextAccessToken(token);
  s.google.override('test-permissions', { kind: 'status', status: 500, body: JSON.stringify({ error: { message: `bad credentials ${token}` } }) });
  const code = await rejection(s.checks.atProposal(grantOf()));
  s.google.nextAccessToken(token);
  await s.checks.daily();
  planted.assertAbsent({ code, audit: JSON.stringify(s.parts.audit.read(0).entries), events: JSON.stringify(s.parts.events.after(0)) });
});

// --- core's wiring ---------------------------------------------------------------------------------------------------------------------

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

test('KBOX-41 core serves the discovery document and the JWKS of the box\'s signing key on keys.<domain>, to anyone', async (t) => {
  const c = await core(t);
  const discovery = await c.call('/.well-known/openid-configuration', { phone: true });
  assert.equal(discovery.status, 200, discovery.body);
  const doc = JSON.parse(discovery.body) as Record<string, unknown>;
  assert.equal(doc['issuer'], 'https://keys.box.example');
  assert.equal(doc['jwks_uri'], 'https://keys.box.example/.well-known/jwks.json');
  const jwks = await c.call('/.well-known/jwks.json', { phone: true });
  assert.equal(jwks.status, 200, jwks.body);
  assert.deepEqual(JSON.parse(jwks.body), { keys: [{ kty: 'EC', crv: 'P-256', x: SIGNING.x, y: SIGNING.y, kid: SIGNING.kid, alg: 'ES256', use: 'sig' }] });
  assert.equal(jwks.body.includes(SIGNING_VALUE), false);
});

test('KBOX-24 KBOX-41 a grant proposed through core\'s proposal route is checked with core\'s own identity, sink and stored record: refused with 422 naming the permission, and a clean one opens an approval', async (t) => {
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

test('KBOX-24 core checks granted keys at start and then every day: a permission found a day later suspends the grant', async (t) => {
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

test('KBOX-24 a daily run that throws is audited as grants.check_failed, leaves the grants as they are, and the next day\'s run is still armed', async (t) => {
  let asked = 0;
  const broken: PlatformSource = {
    platform: () => undefined,
    destination: () => undefined,
    master: () => {
      asked += 1;
      throw new RangeError('kbox-test platform source broke');
    },
    masters: () => [],
  };
  const c = await core(t, { platforms: broken });
  await waitUntil(() => asked === 1, 'the start-up grant check reached the master');
  c.clock.advance(DAY);
  await waitUntil(() => asked === 2, 'the next day\'s grant check reached the master');
  await c.stop();
  await c.closed;
  const after = afterStop(c.stateDir);
  assert.deepEqual(after.actions.filter((a) => a === 'grants.check_failed'), ['grants.check_failed', 'grants.check_failed']);
  assert.deepEqual(after.grants, ['ci']);
  assert.equal(crmCalls(c.google), 0);
});

test('KBOX-24 stop waits for the grant check in flight before closing the stores: its suspension is written, nothing fails on a closed store', async (t) => {
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
