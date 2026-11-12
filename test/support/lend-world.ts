// Core's half of the relay: the real core parts in a temp state directory, the lend handler over them with the test
// profiles registered, and its lend socket. Tests add keys, grants and passes through the real ports.
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import type { PlatformEntry } from '../../src/ports/platform.ts';
import type { Random } from '../../src/ports/random.ts';
import type { KeyClass, KeyLocation } from '../../src/ports/types.ts';
import { hashToken, newToken } from '../../src/pure/tokens.ts';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { createLendHandler, loadCredentialShapes } from '../../src/shell/lend-core.ts';
import { createMintedValues } from '../../src/shell/minted-values.ts';
import { createRotationStore, readKeyInfo } from '../../src/shell/rotation-store.ts';
import type { MintedValues } from '../../src/shell/minted-values.ts';
import { createLendClient, createLendServer } from '../../src/shell/lend-socket.ts';
import type { LendClient, LendServer } from '../../src/shell/lend-socket.ts';
import { TimedClock, seededRandom, tempDir } from '../kit/index.ts';
import { TEST_REGISTRY } from '../fixtures/profiles.ts';

export interface NewKey {
  readonly keyref: string;
  readonly value: Uint8Array;
  readonly platform?: string;
  readonly cls?: KeyClass;
  readonly grants?: readonly string[];
  readonly gen?: number;
  /** The key's projects (default `['shop']`): names for people, never placement (KBOX-57). */
  readonly projects?: readonly string[];
  /** The key's stored location (its `rotation_keys` record); absent stores none. */
  readonly at?: KeyLocation;
}

export interface LendWorld {
  readonly core: CoreParts;
  readonly clock: TimedClock;
  readonly dir: string;
  readonly socket: string;
  readonly server: LendServer;
  readonly client: LendClient;
  /** The fixed codes core's lend handler journalled. */
  readonly journal: readonly string[];
  /** Core's registry of live minted values: what a platform adapter calls (KBOX-14). */
  readonly minted: MintedValues;
  /** Enrols a machine and returns its pass. */
  enrol(label: string, scope?: 'relay' | 'control'): string;
  addKey(key: NewKey): void;
  /** The key's record is deleted and made again at `at` (a key elsewhere is a new key, KBOX-57); its meta row and value stay. */
  readdAt(keyref: string, at: KeyLocation): void;
}

export async function lendWorld(t: TestContext, registry: readonly PlatformEntry[] = TEST_REGISTRY): Promise<LendWorld> {
  const dir = await tempDir(t);
  const clock = new TimedClock(1_000_000);
  const random = seededRandom(11);
  const core = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random });
  const minted = createMintedValues(clock);
  const journal: string[] = [];
  const handler = createLendHandler({
    meta: core.meta,
    tokens: core.meta,
    vault: core.vault,
    audit: core.audit,
    events: core.events,
    registry,
    shapes: loadCredentialShapes(),
    clock,
    minted,
    journal: (code) => void journal.push(code),
    locationOf: (keyref) => readKeyInfo(core.db, keyref)?.location,
  });
  const server = createLendServer(handler);
  const socket = join(dir, 'lend.sock');
  await server.listen(socket);
  t.after(async () => {
    await server.stop();
    core.close();
  });
  return {
    core,
    clock,
    dir,
    socket,
    server,
    client: createLendClient(socket),
    journal,
    minted,
    enrol: (label, scope = 'relay') => seedPass(core, label, scope, random, clock.now()),
    addKey: (key) => {
      seedKey(core, key);
      if (key.at !== undefined) storeKeyInfo(core, clock, key.keyref, key.at);
    },
    readdAt: (keyref, at) => {
      core.db.prepare('DELETE FROM rotation_keys WHERE keyref = ?').run(keyref);
      storeKeyInfo(core, clock, keyref, at);
    },
  };
}

/** Enrols a machine in `core` and returns its pass. */
export function seedPass(core: CoreParts, label: string, scope: 'relay' | 'control', random: Random, now: number): string {
  const token = newToken(random);
  core.meta.addMachine({ label, scope, tokenSha256: hashToken(token), enrolledAt: now });
  return token;
}

/** Stores a key in `core` (meta row, vault value, grants); an admin key of the path profile unless told otherwise. */
export function seedKey(core: CoreParts, key: NewKey): void {
  const gen = key.gen ?? 1;
  core.meta.putKey({
    keyref: key.keyref,
    platform: key.platform ?? 'pathplat',
    name: `KEY_${key.keyref.toUpperCase()}`,
    projects: key.projects ?? ['shop'],
    class: key.cls ?? 'admin',
    status: 'works',
    gen_current: gen,
    schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
    coverage: null,
    last_use_at: null,
  });
  core.vault.put(key.keyref, gen, key.value);
  for (const machine of key.grants ?? []) core.meta.putGrant(key.keyref, machine);
}

/** Writes the key's rotation record at `at` through the real rotation store. */
function storeKeyInfo(core: CoreParts, clock: TimedClock, keyref: string, at: KeyLocation): void {
  createRotationStore(core.db, clock, core.hub).putKeyInfo(keyref, { scopeItems: [], location: at, rotatedAt: clock.now(), markAdmin: false });
}
