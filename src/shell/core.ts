// The parts of the core process, opened from a state directory: meta.db, the audit log, the event log and poller, the vault and
// the control routes. main-core.ts and the tests wire the same parts, so a test runs what the service runs.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { AuditLog } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore, TokenStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { Vault } from '../ports/vault.ts';
import { createAuditLog } from './audit.ts';
import { openMetaDatabase } from './db.ts';
import { createEventHub, createEventLog, createEventPoller } from './events.ts';
import type { EventPoller } from './events.ts';
import type { Route } from './http.ts';
import { createMetaStore } from './meta.ts';
import { controlRoutes } from './routes-control.ts';
import { createFileVault, sweepOrphanTemps } from './vault-fs.ts';

/** The long poll holds a request this long before it answers an empty batch (KBOX-31). */
const POLL_HOLD_MS = 25_000;

export interface CoreDeps {
  readonly stateDir: string;
  readonly clock: Clock;
  readonly scheduler: Scheduler;
  readonly random: Random;
}

export interface CoreParts {
  readonly db: DatabaseSync;
  readonly meta: MetaStore & TokenStore;
  readonly audit: AuditLog;
  readonly events: EventLog;
  readonly poller: EventPoller;
  readonly vault: Vault;
  readonly routes: readonly Route[];
  close(): void;
}

export function openCore(deps: CoreDeps): CoreParts {
  mkdirSync(deps.stateDir, { recursive: true, mode: 0o700 });
  const db = openMetaDatabase(join(deps.stateDir, 'meta.db'), deps.random);
  const hub = createEventHub();
  const events = createEventLog(db, deps.clock, hub);
  const poller = createEventPoller(events, hub, deps.scheduler, POLL_HOLD_MS);
  const meta = createMetaStore(db, deps.clock, hub);
  const audit = createAuditLog(db);
  const vaultRoot = join(deps.stateDir, 'vault');
  for (const ref of sweepOrphanTemps(vaultRoot)) audit.append({ action: 'vault.temp_swept', subject: ref, at: deps.clock.now() });
  const vault = createFileVault(vaultRoot);
  return { db, meta, audit, events, poller, vault, routes: controlRoutes({ meta, audit, events, poller }), close: () => db.close() };
}
