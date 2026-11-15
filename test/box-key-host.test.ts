// KBOX-63 (host-model): the box key's rotation proves at Google with the box's issuer at the tailnet origin https://<host>. The scenario of
// test/box-key.test.ts that ran against the old issuer, written again at the new one.
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { refusingAdapterHttp } from '../src/ports/http.ts';
import type { KeyRow } from '../src/ports/meta.ts';
import type { PlatformEntry, RegistryDeps } from '../src/ports/platform.ts';
import { oidcIssuer } from '../src/pure/box-origins.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { startCore } from '../src/main-core.ts';
import type { StartedCore } from '../src/main-core.ts';
import { createGoogleEntry } from '../src/platforms/google/index.ts';
import { BOX_SUBJECT } from '../src/platforms/google/oidc.ts';
import { openCore } from '../src/shell/core.ts';
import type { CoreParts } from '../src/shell/core.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import type { GenRow, RotationStore } from '../src/shell/rotation-store.ts';
import { fakeGoogle } from './fakes/google.ts';
import { TimedClock, adapterHttpTo, bytesOf, drive, seededRandom, tempDir } from './kit/index.ts';

const BOX_REF = 'google/p/OIDC_SIGNING_KEY';
const DOMAIN = 'box.example';
const AUDIENCE = '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-prov';
const NOW = 1_700_000_000_000;

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
  /** A control request with a JSON body to the running core. */
  post(path: string, json: unknown): Promise<{ status: number; body: string }>;
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
    async post(path, json) {
      const headers = { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}`, 'content-type': 'application/json' };
      const reply = await driver.request({ path, method: 'POST', headers, body: Buffer.from(JSON.stringify(json)) });
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

const gensOf = (store: RotationStore, keyref: string): readonly Pick<GenRow, 'gen' | 'status'>[] => store.gens(keyref).map(({ gen, status }) => ({ gen, status }));

test('KBOX-55 a box run stopped in checking past its lead resumes at start, proves at Google with the new key and switches, with issuer https://<host>', async (t) => {
  const google = await fakeGoogle(t, { audience: AUDIENCE, issuer: oidcIssuer(DOMAIN), subject: BOX_SUBJECT });
  const registry = (deps: RegistryDeps): readonly PlatformEntry[] => [createGoogleEntry({ ...deps, http: adapterHttpTo(google) })];
  const box = await boxCore(t);
  await box.start({ registry });
  const next = scalarText('next');
  box.seed(({ parts, store }) => {
    parts.vault.put(BOX_REF, 2, Buffer.from(next, 'latin1'));
    store.putGen({ keyref: BOX_REF, gen: 2, status: 'pending', platformKeyId: null, location: {} });
    const run = store.openRun({ runId: 'run_00000000000000aa', keyref: BOX_REF, state: 'checking', genOld: 1, genNew: 2, intentName: 'kbox_google_p_oidc_signing_key_g2_00000000', origin: 'approval' });
    store.update(run.runId, { waitUntil: box.clock.now() });
  });
  google.trust([jwkOf(next)]);
  await box.start({ registry });
  const current = async (): Promise<number | undefined> => (JSON.parse((await box.call('/api/meta')).body) as { keys: KeyRow[] }).keys.find((k) => k.keyref === BOX_REF)?.gen_current;
  let gen = await current();
  for (let i = 0; i < 200 && gen !== 2; i += 1) gen = await current();
  assert.equal(gen, 2);
  assert.equal(google.lastHeader?.['kid'], jwkOf(next).kid, 'the proof was signed with the new key');
  const { store } = await box.read();
  assert.deepEqual(gensOf(store, BOX_REF), [{ gen: 1, status: 'grace' }, { gen: 2, status: 'current' }]);
});
