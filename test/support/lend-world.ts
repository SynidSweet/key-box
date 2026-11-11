// Core's half of the relay: the real core parts in a temp state directory, the lend handler over them with the test
// profiles registered, and its lend socket. Tests add keys, grants and passes through the real ports.
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import type { PlatformEntry } from '../../src/ports/platform.ts';
import type { KeyClass } from '../../src/ports/types.ts';
import { parseCredentialShapes } from '../../src/pure/scanner.ts';
import type { CredentialShapes } from '../../src/pure/scanner.ts';
import { hashToken, newToken } from '../../src/pure/tokens.ts';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { createLendHandler } from '../../src/shell/lend-core.ts';
import { createLendClient, createLendServer } from '../../src/shell/lend-socket.ts';
import type { LendClient, LendServer } from '../../src/shell/lend-socket.ts';
import { TimedClock, seededRandom, tempDir } from '../kit/index.ts';
import { hostProfile, pathProfile } from '../fixtures/profiles.ts';
import { readFileSync } from 'node:fs';

export const TEST_REGISTRY: readonly PlatformEntry[] = [
  { id: 'pathplat', relay: pathProfile },
  { id: 'hostplat', relay: hostProfile },
  { id: 'plain' },
];

export function loadShapes(): CredentialShapes {
  const parsed = parseCredentialShapes(JSON.parse(readFileSync(new URL('../../src/data/credential-shapes.json', import.meta.url), 'utf8')) as unknown);
  if (!parsed.ok) throw new Error('credential-shapes.json does not parse');
  return parsed.value;
}

export interface NewKey {
  readonly keyref: string;
  readonly value: Uint8Array;
  readonly platform?: string;
  readonly cls?: KeyClass;
  readonly grants?: readonly string[];
  readonly gen?: number;
}

export interface LendWorld {
  readonly core: CoreParts;
  readonly clock: TimedClock;
  readonly dir: string;
  readonly socket: string;
  readonly server: LendServer;
  readonly client: LendClient;
  /** Enrols a machine and returns its pass. */
  enrol(label: string, scope?: 'relay' | 'control'): string;
  addKey(key: NewKey): void;
}

export async function lendWorld(t: TestContext, registry: readonly PlatformEntry[] = TEST_REGISTRY): Promise<LendWorld> {
  const dir = await tempDir(t);
  const clock = new TimedClock(1_000_000);
  const random = seededRandom(11);
  const core = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random });
  const handler = createLendHandler({ meta: core.meta, tokens: core.meta, vault: core.vault, audit: core.audit, events: core.events, registry, shapes: loadShapes(), clock });
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
    enrol(label, scope = 'relay') {
      const token = newToken(random);
      core.meta.addMachine({ label, scope, tokenSha256: hashToken(token), enrolledAt: clock.now() });
      return token;
    },
    addKey(key) {
      const gen = key.gen ?? 1;
      core.meta.putKey({
        keyref: key.keyref,
        platform: key.platform ?? 'pathplat',
        name: `KEY_${key.keyref.toUpperCase()}`,
        projects: ['shop'],
        class: key.cls ?? 'admin',
        status: 'works',
        gen_current: gen,
        schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
        coverage: null,
        last_use_at: null,
      });
      core.vault.put(key.keyref, gen, key.value);
      for (const machine of key.grants ?? []) core.meta.putGrant(key.keyref, machine);
    },
  };
}
