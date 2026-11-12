// The parts of the core process, opened from a state directory: meta.db, the audit log, the event log and poller, the vault and
// the control routes. main-core.ts and the tests wire the same parts, so a test runs what the service runs.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { AuditLog } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { EventLog, EventSignal } from '../ports/events.ts';
import type { MetaStore, TokenStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { ShareSigningKey, ShareValues } from '../ports/share.ts';
import type { Vault } from '../ports/vault.ts';
import { ShareError, VaultError } from '../pure/errors.ts';
import { createAuditLog } from './audit.ts';
import { openMetaDatabase } from './db.ts';
import { createEventHub, createEventLog, createEventPoller } from './events.ts';
import type { EventPoller } from './events.ts';
import type { Route } from './http.ts';
import { createMetaStore } from './meta.ts';
import { controlRoutes } from './routes-control.ts';
import { createFileVault, sweepOrphanTemps } from './vault-fs.ts';

/** The share writer's signing key is a master value: generation 1 of this one ref. */
const SHARE_SIGNING_REF = 'keybox/share-signing';
const SHARE_SIGNING_GEN = 1;

/** KBOX-33: the signing seed of the share writer, kept as a value of its own. A seed that cannot be read is a fixed error. */
function shareSigningKeyIn(vault: Vault): ShareSigningKey {
  return {
    async read() {
      try {
        return await vault.lend(SHARE_SIGNING_REF, SHARE_SIGNING_GEN).use((bytes) => Promise.resolve(Uint8Array.from(bytes)));
      } catch (error) {
        if (error instanceof VaultError && error.failure === 'unknown_key') return null;
        throw new ShareError('signing_key_unreadable');
      }
    },
    create(seed) {
      vault.put(SHARE_SIGNING_REF, SHARE_SIGNING_GEN, seed);
    },
  };
}

/** KBOX-33: a stored value as text for the share source; '' for none or for bytes that are not UTF-8 text. */
function shareValuesIn(vault: Vault): ShareValues {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const decode = (bytes: Uint8Array): string => {
    try {
      return decoder.decode(bytes);
    } catch {
      return '';
    }
  };
  return {
    async text(keyref, gen) {
      try {
        return await vault.lend(keyref, gen).use((bytes) => Promise.resolve(decode(bytes)));
      } catch (error) {
        if (error instanceof VaultError && error.failure === 'unknown_key') return '';
        throw error;
      }
    },
  };
}

/** The long poll holds a request this long before it answers an empty batch (KBOX-31). */
const POLL_HOLD_MS = 25_000;

export interface CoreDeps {
  readonly stateDir: string;
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly random: Random;
  /** Where the schema codes of KBOX-56 go (`schema_newer`, `schema_migration_failed`); a test over a scratch directory may leave it out. */
  readonly journal?: (code: string) => void;
}

export interface CoreParts {
  readonly db: DatabaseSync;
  readonly meta: MetaStore & TokenStore;
  readonly audit: AuditLog;
  readonly events: EventLog;
  readonly hub: EventSignal;
  readonly poller: EventPoller;
  readonly vault: Vault;
  /** What the share writer reads from the key store (KBOX-33). */
  readonly share: { readonly signingKey: ShareSigningKey; readonly values: ShareValues };
  readonly routes: readonly Route[];
  close(): void;
}

export function openCore(deps: CoreDeps): CoreParts {
  mkdirSync(deps.stateDir, { recursive: true, mode: 0o700 });
  const db = openMetaDatabase(join(deps.stateDir, 'meta.db'), deps.random, deps.journal);
  const hub = createEventHub();
  const events = createEventLog(db, deps.clock, hub);
  const poller = createEventPoller(events, hub, deps.scheduler, POLL_HOLD_MS);
  const meta = createMetaStore(db, deps.clock, hub);
  const audit = createAuditLog(db);
  const vaultRoot = join(deps.stateDir, 'vault');
  for (const ref of sweepOrphanTemps(vaultRoot)) audit.append({ action: 'vault.temp_swept', subject: ref, at: deps.clock.now() });
  const vault = createFileVault(vaultRoot);
  return { db, meta, audit, events, hub, poller, vault, share: { signingKey: shareSigningKeyIn(vault), values: shareValuesIn(vault) }, routes: controlRoutes({ bootstrapFactsPath: join(deps.stateDir, 'bootstrap-facts.json'), meta, audit, events, poller }), close: () => db.close() };
}
