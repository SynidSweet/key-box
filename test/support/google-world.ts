// The Google adapters over the fake Google (test/fakes/google.ts), built the way the entry builds them: the real minter, so every admin call
// goes through STS and IAM Credentials against the fake and the fake can tell which project's `kbox-keys` made it. The box's signing key is the
// master; a stranger's key is the one Google does not trust. Time stands still unless the adapters pause: `pause` advances the clock.
import { createECDH, createHash } from 'node:crypto';
import type { BoxIdentity } from '../../src/ports/platform.ts';
import type { Lent } from '../../src/ports/types.ts';
import { createMinter } from '../../src/platforms/google/minter.ts';
import type { Minter } from '../../src/platforms/google/minter.ts';
import { BOX_SUBJECT } from '../../src/platforms/google/oidc.ts';
import { fakeGoogle } from '../fakes/google.ts';
import type { Cleanups, FakeGoogle } from '../fakes/google.ts';
import { FakeClock, adapterHttpTo, lent } from '../kit/index.ts';
import type { FakeAdapterHttp } from '../kit/index.ts';

export const NOW = 1_700_000_000_000;
const PROVIDER = '//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/kbox-pool/providers/kbox-oidc';
export const IDENTITY: BoxIdentity = { issuer: 'https://keys.box.example', audience: PROVIDER };

/** The two projects the tests store keys in. */
export const P1 = 'p-proj1';
export const P2 = 'p-proj2';
export const adminOf = (project: string): string => `kbox-keys@${project}.iam.gserviceaccount.com`;

/** A P-256 signing key as the vault holds it (the private scalar, 43 base64url characters), derived from a fixed test seed. */
function testKey(seed: string): { readonly lent: Lent; readonly jwk: { readonly kid: string; readonly kty: string; readonly crv: string; readonly x: string; readonly y: string } } {
  const d = createHash('sha256').update(`kbox-test-signing-${seed}`).digest();
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey();
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  const kid = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest('base64url');
  return { lent: lent(Buffer.from(d.toString('base64url')), `google/box/SIGNING:${seed}`), jwk: { kid, kty: 'EC', crv: 'P-256', x, y } };
}

export interface GoogleWorld {
  readonly fake: FakeGoogle;
  readonly http: FakeAdapterHttp;
  readonly clock: FakeClock;
  readonly minter: Minter;
  /** The box's signing key: the platform's master. */
  readonly master: Lent;
  /** A key Google never took. */
  readonly wrongMaster: Lent;
  /** Every wait an adapter asked for, in order; each moves the clock. */
  readonly pauses: number[];
  pause(ms: number): Promise<void>;
  /** The service accounts the minter impersonated, in order (read off the fake's IAM Credentials calls). */
  minted(): string[];
  /** Every request the adapters sent since the last reset, as the fake received it. */
  sent(): FakeAdapterHttp['sent'];
  /** The hosts the adapters called, in order, with method and target. */
  calls(host?: string): { readonly host: string; readonly method: string; readonly target: string }[];
  /** A fresh run: the fake forgets everything its tests changed, and so does the record of calls. */
  reset(): void;
  /** Forgets the record of calls (and what the clock was told to wait), and nothing the fake holds. */
  forgetCalls(): void;
}

export async function googleWorld(t: Cleanups, projects: readonly string[]): Promise<GoogleWorld> {
  const box = testKey('1');
  const stranger = testKey('stranger');
  const fake = await fakeGoogle(t, { audience: PROVIDER, issuer: IDENTITY.issuer, subject: BOX_SUBJECT });
  fake.trust([box.jwk]);
  fake.creatorOn(projects.map(adminOf));
  const http = adapterHttpTo(fake);
  const clock = new FakeClock(NOW);
  const pauses: number[] = [];
  let from = 0;
  const minter = createMinter({ http, clock, identity: IDENTITY, minted: { add: () => undefined }, keyInfo: () => undefined });
  return {
    fake,
    http,
    clock,
    minter,
    master: box.lent,
    wrongMaster: stranger.lent,
    pauses,
    pause: (ms) => {
      pauses.push(ms);
      clock.advance(ms);
      return Promise.resolve();
    },
    minted: () => fake.requests.flatMap((r) => /^\/v1\/projects\/-\/serviceAccounts\/([^/:]+):generateAccessToken$/.exec(r.path)?.[1] ?? []).map(decodeURIComponent),
    sent: () => http.sent.slice(from),
    calls: (host) => http.sent.slice(from).filter((s) => host === undefined || s.originalHost === host).map((s) => ({ host: s.originalHost, method: s.method, target: s.target })),
    forgetCalls: () => {
      fake.clearRequests();
      from = http.sent.length;
      pauses.length = 0;
    },
    reset: () => {
      fake.reset();
      from = http.sent.length;
      pauses.length = 0;
    },
  };
}
