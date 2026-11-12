// A registry entry over the in-memory platform (KBOX-23): what an adapter unit registers, built for a test.
import type { Issuer, IssuerCapabilities } from '../../src/ports/issuer.ts';
import type { PlatformEntry } from '../../src/ports/platform.ts';
import type { KeyShape, LocationSchema } from '../../src/ports/types.ts';
import type { PlatformSource } from '../../src/shell/rotation-ports.ts';
import { createPlatformSource } from '../../src/shell/platform-source.ts';
import type { FakePlatformWorld } from './platform.ts';

export const FAKE_KEY_PAGE = 'https://fake.example/keys';

/** The fake platform's one location field (KBOX-57): a `region` (any lower-case name) that no class must name, as the tests' `eu` keys carry. */
export const FAKE_LOCATION: LocationSchema = { region: { pattern: /[a-z]{2,16}/, requiredFor: [] } };


/** An entry with the fake platform's issuer, lister, verifier and location field; `patch` replaces any field. */
export const fakeEntry = (world: FakePlatformWorld, patch: Partial<PlatformEntry> = {}): PlatformEntry => ({
  id: 'fake',
  issuer: world.issuer,
  lister: world.lister,
  location: FAKE_LOCATION,
  verifier: world.verifier,
  keyPageUrl: FAKE_KEY_PAGE,
  unverified: [],
  ...patch,
});

/** The same issuer with its capabilities patched (a paste platform, another classification). */
export const issuerWith = (base: Issuer, caps: Partial<IssuerCapabilities>): Issuer => ({
  ...base,
  capabilities: () => ({ ...base.capabilities(), ...caps }),
});

/** A paste-only entry: no issuer, so it states its own key shape and class (KBOX-40). */
export const pasteOnlyEntry = (world: FakePlatformWorld, shape: KeyShape, patch: Partial<PlatformEntry> = {}): PlatformEntry => ({
  id: 'pasteonly',
  verifier: world.verifier,
  keyPageUrl: FAKE_KEY_PAGE,
  shape,
  classify: () => 'admin',
  unverified: [],
  ...patch,
});

const noMeta = { snapshot: (): never => { throw new Error('this test reads no master key'); } };
const noVault = { lend: (): never => { throw new Error('this test reads no master key'); } };

/** The platform source of a registry, for a test that never asks for a master key. */
export const sourceOf = (registry: readonly PlatformEntry[]): PlatformSource => createPlatformSource({ registry, meta: noMeta, vault: noVault });
