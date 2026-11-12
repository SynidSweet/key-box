// The Vercel adapter over a stateful fake of api.vercel.com (test/fakes/vercel.ts): one server per test file, state reset per test.
import { after } from 'node:test';
import type { DestinationKit } from '../../src/ports/destination.ts';
import type { PlatformEntry } from '../../src/ports/platform.ts';
import type { Lent } from '../../src/ports/types.ts';
import { createVercelEntry } from '../../src/platforms/vercel/index.ts';
import { startFakeVercel } from '../fakes/vercel.ts';
import type { FakeVercel, FakeVercelOptions } from '../fakes/vercel.ts';
import { FakeClock, adapterHttpTo, lent } from '../kit/index.ts';
import type { FakeAdapterHttp } from '../kit/index.ts';
import type { Issuer, KeyLister, Verifier } from '../../src/ports/issuer.ts';

export const MASTER_TEXT = `vcp_KboxTestFakeMaster${'M'.repeat(20)}`;
export const WRONG_TEXT = `vcp_KboxTestFakeWrong${'W'.repeat(20)}`;
export const PROJECT = 'prj_fake1';
export const OTHER_PROJECT = 'prj_fake2';

export const lentText = (text: string, label = 'test:1'): Lent => lent(Buffer.from(text), label);
export const master = (): Lent => lentText(MASTER_TEXT, 'master:1');

export interface VercelWorld {
  readonly fake: FakeVercel;
  readonly http: FakeAdapterHttp;
  readonly clock: FakeClock;
  readonly entry: PlatformEntry;
  readonly issuer: Issuer;
  readonly lister: KeyLister;
  readonly verifier: Verifier;
  readonly kit: DestinationKit;
  /** Every pause the redeployer asked for, in order; each moves the clock by that much and nothing else. */
  readonly pauses: readonly number[];
  /** A fresh entry over `http` (a wrapper that fails or answers its own way), sharing this world's clock and pause. */
  entryOver(http: FakeAdapterHttp): PlatformEntry;
}

export async function vercelWorld(options: Partial<FakeVercelOptions> = {}): Promise<VercelWorld> {
  const fake = await startFakeVercel({ after }, { master: MASTER_TEXT, projects: [PROJECT, OTHER_PROJECT], pageSize: 2, ...options });
  const http = adapterHttpTo(fake);
  const clock = new FakeClock(0);
  const pauses: number[] = [];
  const pause = (ms: number): Promise<void> => {
    pauses.push(ms);
    clock.advance(ms);
    return Promise.resolve();
  };
  const build = (over: FakeAdapterHttp): PlatformEntry => createVercelEntry({ http: over, clock, pause });
  const entry = build(http);
  const need = <T>(value: T | undefined, what: string): T => {
    if (value === undefined) throw new Error(`the vercel entry has no ${what}`);
    return value;
  };
  return {
    fake,
    http,
    clock,
    entry,
    issuer: need(entry.issuer, 'issuer'),
    lister: need(entry.lister, 'lister'),
    verifier: need(entry.verifier, 'verifier'),
    kit: need(entry.destinations?.[0], 'destination'),
    pauses,
    entryOver: build,
  };
}
