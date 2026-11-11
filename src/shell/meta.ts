// KBOX-5, KBOX-19, KBOX-30: the metadata store over meta.db. Every text it takes is held to a name; every write that
// changes what the snapshot shows appends its event in the same transaction and wakes the pollers after the commit.
import type { DatabaseSync } from 'node:sqlite';
import type { Clock } from '../ports/clock.ts';
import type { EventSignal } from '../ports/events.ts';
import type {
  Coverage,
  KeyRow,
  KeyStatus,
  MetaApproval,
  MetaBox,
  MetaDestination,
  MetaKey,
  MetaMachine,
  MetaSnapshot,
  MetaStore,
  NewMachine,
  ShareState,
  TokenRecord,
  TokenScope,
  TokenStore,
} from '../ports/meta.ts';
import type { KeyClass } from '../ports/types.ts';
import { ApiError, WriteRefused } from '../pure/errors.ts';
import { CODE, LABEL, NAME, NETWORK, TITLE, int, oneOf, optional, parseObject, text } from '../pure/schemas.ts';
import type { Parsed } from '../pure/schemas.ts';
import { inReadTransaction, inTransaction } from './db.ts';
import { insertEvent } from './events.ts';

const KEY_SCHEMA = {
  keyref: text(NAME),
  platform: text(LABEL),
  name: text(NAME),
  class: oneOf('ordinary', 'admin', 'master'),
  status: oneOf('works', 'rotating', 'awaiting_approval', 'awaiting_paste', 'failed'),
  gen_current: int(1),
  rotate_every_days: int(),
  grace_hours: int(),
  next_due_at: optional(int()),
  expires_at: optional(int()),
  coverage: optional(oneOf('windowed', 'anchored', 'none')),
  last_use_at: optional(int()),
} as const;
const DESTINATION_SCHEMA = { keyref: text(NAME), kind: text(NAME), target: text(NAME), readable_by: oneOf('api', 'runtime') } as const;
const GRANT_SCHEMA = { keyref: text(NAME), machine: text(LABEL) } as const;
const MACHINE_SCHEMA = { label: text(LABEL), scope: oneOf('control', 'relay'), token_sha256: text(/^[0-9a-f]{64}$/), enrolled_at: int() } as const;
const APPROVAL_SCHEMA = { approval_id: text(NAME), kind: text(CODE), title: text(TITLE), slot: text(NAME), opened_at: int(), expires_at: int() } as const;
/** A raw 32-byte Ed25519 public key as base64: 43 characters and one `=`. */
const SHARE_KEY_B64 = /^[A-Za-z0-9+/]{43}=$/;
const USE_SCHEMA ={ label: text(LABEL), network: text(NETWORK) } as const;

const closed = <T>(parsed: Parsed<T>): T => {
  if (!parsed.ok) throw new WriteRefused();
  return parsed.value;
};
const present = <T extends object>(members: T): Partial<T> => Object.fromEntries(Object.entries(members).filter(([, v]) => v !== null)) as Partial<T>;

interface KeyStored {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects_json: string;
  readonly class: string;
  readonly status: string;
  readonly gen_current: number;
  readonly rotate_every_days: number;
  readonly grace_hours: number;
  readonly next_due_at: number | null;
  readonly expires_at: number | null;
  readonly coverage: string | null;
  readonly last_use_at: number | null;
}

function readSnapshot(db: DatabaseSync): MetaSnapshot {
  const cursor = (db.prepare('SELECT coalesce(max(seq), 0) AS seq FROM events').get() as { seq: number }).seq;
  const box: MetaBox = { ...(db.prepare('SELECT release, share_version, share_public_key_ed25519_b64, oidc_issuer, epoch FROM box_info').get() as unknown as MetaBox) };
  const group = <R extends { keyref: string }, V>(rows: R[], pick: (r: R) => V): Map<string, V[]> => {
    const byKey = new Map<string, V[]>();
    for (const r of rows) byKey.set(r.keyref, [...(byKey.get(r.keyref) ?? []), pick(r)]);
    return byKey;
  };
  const destinations = group(db.prepare('SELECT keyref, kind, target, readable_by FROM destinations ORDER BY keyref, kind, target').all() as unknown as (MetaDestination & { keyref: string })[], (r) => ({
    kind: r.kind,
    target: r.target,
    readable_by: r.readable_by,
  }));
  const grants = group(db.prepare('SELECT keyref, machine FROM grants ORDER BY keyref, machine').all() as unknown as { keyref: string; machine: string }[], (r) => ({ machine: r.machine }));
  const rules = group(db.prepare('SELECT keyref, rule_id FROM allow_rules ORDER BY keyref, rule_id').all() as unknown as { keyref: string; rule_id: string }[], (r) => r.rule_id);
  const keys = (db.prepare('SELECT * FROM keys ORDER BY keyref').all() as unknown as KeyStored[]).map(
    (k): MetaKey => ({
      keyref: k.keyref,
      platform: k.platform,
      name: k.name,
      projects: JSON.parse(k.projects_json) as string[],
      class: k.class as KeyClass,
      status: k.status as KeyStatus,
      gen_current: k.gen_current,
      destinations: destinations.get(k.keyref) ?? [],
      schedule: { rotate_every_days: k.rotate_every_days, grace_hours: k.grace_hours, next_due_at: k.next_due_at, expires_at: k.expires_at },
      grants: grants.get(k.keyref) ?? [],
      allow_rules: rules.get(k.keyref) ?? [],
      coverage: k.coverage as Coverage | null,
      last_use_at: k.last_use_at,
    }),
  );
  const machines = (db.prepare('SELECT label, scope, enrolled_at, revoked, last_network FROM machines ORDER BY label').all() as unknown as (Omit<MetaMachine, 'revoked'> & { revoked: number })[]).map(
    (m): MetaMachine => ({ label: m.label, scope: m.scope, enrolled_at: m.enrolled_at, revoked: m.revoked === 1, last_network: m.last_network }),
  );
  const approvals = (db.prepare("SELECT approval_id, kind, title, slot, opened_at, expires_at FROM approvals WHERE status = 'pending' ORDER BY opened_at, approval_id").all() as unknown as MetaApproval[]).map((a): MetaApproval => ({ ...a }));
  return { cursor, box, keys, machines, approvals };
}

export function createMetaStore(db: DatabaseSync, clock: Clock, hub: EventSignal): MetaStore & TokenStore {
  /** Runs the mutation and its events in one transaction; the pollers are woken only after the commit. */
  const write = (mutate: () => void): void => {
    inTransaction(db, mutate);
    hub.notify();
  };
  const keyChanged = (keyref: string): void => void insertEvent(db, clock.now(), 'key.changed', { keyref });

  return {
    epoch: () => (db.prepare('SELECT epoch FROM box_info').get() as { epoch: string }).epoch,

    setRelease(release) {
      if (!/^[0-9a-f]{64}$/.test(release)) throw new RangeError('a release is a 64-hex content hash');
      db.prepare('UPDATE box_info SET release = ?').run(release);
    },

    snapshot: () => inReadTransaction(db, () => readSnapshot(db)),

    shareState(): ShareState {
      const row = db.prepare('SELECT share_version, share_public_key_ed25519_b64 FROM box_info').get() as { share_version: number; share_public_key_ed25519_b64: string | null };
      return { version: row.share_version, publicKeyB64: row.share_public_key_ed25519_b64 };
    },

    setSharePublicKey(keyB64: string): void {
      const k = closed(parseObject({ key: text(SHARE_KEY_B64) }, { key: keyB64 }));
      write(() => {
        const current = (db.prepare('SELECT share_public_key_ed25519_b64 AS key FROM box_info').get() as { key: string | null }).key;
        if (current !== null && current !== k.key) throw new WriteRefused();
        db.prepare('UPDATE box_info SET share_public_key_ed25519_b64 = ?').run(k.key);
      });
    },

    announceShare(version: number): void {
      const v = closed(parseObject({ version: int(1) }, { version }));
      write(() => {
        const current = (db.prepare('SELECT share_version AS version FROM box_info').get() as { version: number }).version;
        if (v.version <= current) throw new WriteRefused();
        db.prepare('UPDATE box_info SET share_version = ?').run(v.version);
        insertEvent(db, clock.now(), 'share.version', { version: v.version });
      });
    },

    putKey(key: KeyRow): void {
      const k = closed(
        parseObject(KEY_SCHEMA, {
          keyref: key.keyref,
          platform: key.platform,
          name: key.name,
          class: key.class,
          status: key.status,
          gen_current: key.gen_current,
          rotate_every_days: key.schedule.rotate_every_days,
          grace_hours: key.schedule.grace_hours,
          ...present({ next_due_at: key.schedule.next_due_at, expires_at: key.schedule.expires_at, coverage: key.coverage, last_use_at: key.last_use_at }),
        }),
      );
      if (key.projects.length > 64 || !key.projects.every((p) => NAME.test(p))) throw new WriteRefused();
      write(() => {
        db.prepare(
          `INSERT INTO keys (keyref, platform, name, projects_json, class, status, gen_current, rotate_every_days, grace_hours, next_due_at, expires_at, coverage, last_use_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (keyref) DO UPDATE SET platform = excluded.platform, name = excluded.name, projects_json = excluded.projects_json, class = excluded.class,
             status = excluded.status, gen_current = excluded.gen_current, rotate_every_days = excluded.rotate_every_days, grace_hours = excluded.grace_hours,
             next_due_at = excluded.next_due_at, expires_at = excluded.expires_at, coverage = excluded.coverage, last_use_at = excluded.last_use_at`,
        ).run(k.keyref, k.platform, k.name, JSON.stringify(key.projects), k.class, k.status, k.gen_current, k.rotate_every_days, k.grace_hours, k.next_due_at ?? null, k.expires_at ?? null, k.coverage ?? null, k.last_use_at ?? null);
        keyChanged(k.keyref);
      });
    },

    putDestination(keyref: string, destination: MetaDestination): void {
      const d = closed(parseObject(DESTINATION_SCHEMA, { keyref, ...destination }));
      write(() => {
        db.prepare('INSERT OR REPLACE INTO destinations (keyref, kind, target, readable_by) VALUES (?, ?, ?, ?)').run(d.keyref, d.kind, d.target, d.readable_by);
        keyChanged(d.keyref);
      });
    },

    putGrant(keyref: string, machine: string): void {
      const g = closed(parseObject(GRANT_SCHEMA, { keyref, machine }));
      write(() => {
        db.prepare('INSERT OR IGNORE INTO grants (keyref, machine) VALUES (?, ?)').run(g.keyref, g.machine);
        keyChanged(g.keyref);
      });
    },

    removeGrant(keyref: string, machine: string): void {
      const g = closed(parseObject(GRANT_SCHEMA, { keyref, machine }));
      write(() => {
        if (db.prepare('DELETE FROM grants WHERE keyref = ? AND machine = ?').run(g.keyref, g.machine).changes === 0) throw new ApiError('not_found');
        keyChanged(g.keyref);
      });
    },

    removeDestination(keyref: string, kind: string, target: string): void {
      const d = closed(parseObject({ keyref: text(NAME), kind: text(NAME), target: text(NAME) }, { keyref, kind, target }));
      write(() => {
        if (db.prepare('DELETE FROM destinations WHERE keyref = ? AND kind = ? AND target = ?').run(d.keyref, d.kind, d.target).changes === 0) throw new ApiError('not_found');
        keyChanged(d.keyref);
      });
    },

    coverageOf(keyref: string): Coverage | null | undefined {
      const row = db.prepare('SELECT coverage FROM keys WHERE keyref = ?').get(keyref) as { coverage: Coverage | null } | undefined;
      return row === undefined ? undefined : row.coverage;
    },

    addMachine(machine: NewMachine): void {
      const m = closed(parseObject(MACHINE_SCHEMA, { label: machine.label, scope: machine.scope, token_sha256: machine.tokenSha256, enrolled_at: machine.enrolledAt }));
      write(() => {
        db.prepare('INSERT INTO machines (label, scope, token_sha256, enrolled_at) VALUES (?, ?, ?, ?)').run(m.label, m.scope, m.token_sha256, m.enrolled_at);
        insertEvent(db, clock.now(), 'machine.changed', { label: m.label, change: 'enrolled' });
      });
    },

    revokeMachine(label: string): void {
      write(() => {
        if (db.prepare('UPDATE machines SET revoked = 1 WHERE label = ?').run(label).changes === 0) throw new ApiError('not_found');
        insertEvent(db, clock.now(), 'machine.changed', { label, change: 'revoked' });
      });
    },

    putApproval(approval: MetaApproval): void {
      const a = closed(parseObject(APPROVAL_SCHEMA, { ...approval }));
      write(() => void db.prepare('INSERT OR REPLACE INTO approvals (approval_id, kind, title, slot, opened_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(a.approval_id, a.kind, a.title, a.slot, a.opened_at, a.expires_at));
    },

    tokens(): readonly TokenRecord[] {
      const rows = db.prepare('SELECT label, scope, token_sha256, revoked FROM machines ORDER BY label').all() as unknown as { label: string; scope: TokenScope; token_sha256: string; revoked: number }[];
      return rows.map((r) => ({ label: r.label, scope: r.scope, tokenSha256: r.token_sha256, revoked: r.revoked === 1 }));
    },

    recordUse(label: string, network: string): void {
      const use = closed(parseObject(USE_SCHEMA, { label, network }));
      write(() => {
        const row = db.prepare('SELECT last_network FROM machines WHERE label = ?').get(use.label) as { last_network: string | null } | undefined;
        if (row === undefined) throw new ApiError('not_found');
        if (row.last_network === use.network) return;
        db.prepare('UPDATE machines SET last_network = ? WHERE label = ?').run(use.network, use.label);
        insertEvent(db, clock.now(), 'token.new_network', { label: use.label, network: use.network });
      });
    },
  };
}
