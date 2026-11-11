// KBOX-50: the audit log in meta.db. Each row's hash is SHA-256(prev_hash bytes, canonical JSON of the row without hash).
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { AuditEvent, AuditLog, AuditRow, ChainVerdict } from '../ports/audit.ts';
import { canonicalJson } from '../pure/canonical.ts';
import { WriteRefused } from '../pure/errors.ts';
import { inTransaction } from './db.ts';
import { AUDIT_ACTOR, AUDIT_SCHEMAS, NAME, isAuditAction, parseObject, text, int } from '../pure/schemas.ts';
import type { Schema } from '../pure/schemas.ts';

const ZERO_HASH = '0'.repeat(64);

interface StoredRow {
  readonly seq: number;
  readonly at: number;
  readonly actor: string;
  readonly action: string;
  readonly ref: string;
  readonly detail_json: string;
  readonly prev_hash: string;
  readonly hash: string;
}

const ENVELOPE = { actor: text(AUDIT_ACTOR), ref: text(NAME), at: int() } as const satisfies Schema;

function hashOf(row: Omit<AuditRow, 'hash'>): string {
  return createHash('sha256').update(Buffer.from(row.prev_hash, 'hex')).update(canonicalJson(row), 'utf8').digest('hex');
}

const toRow = (s: StoredRow): AuditRow => ({
  seq: s.seq,
  at: s.at,
  actor: s.actor,
  action: s.action,
  ref: s.ref,
  detail: JSON.parse(s.detail_json) as AuditRow['detail'],
  prev_hash: s.prev_hash,
  hash: s.hash,
});

/** The closed shape of an event, or a refusal; nothing of a refused entry is kept or quoted. */
function closed(event: AuditEvent): { actor: string; ref: string; at: number; action: string; detail: Record<string, string | number | boolean> } {
  if (!isAuditAction(event.action)) throw new WriteRefused();
  const envelope = parseObject(ENVELOPE, { actor: event.actor ?? 'box', ref: event.subject, at: event.at });
  const detail = parseObject(AUDIT_SCHEMAS[event.action] as Schema, event.detail ?? {});
  if (!envelope.ok || !detail.ok) throw new WriteRefused();
  return { ...envelope.value, action: event.action, detail: detail.value };
}

export function createAuditLog(db: DatabaseSync): AuditLog {
  const last = db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1');
  const nextSeq = db.prepare("SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit'), 0) + 1 AS seq");
  const insert = db.prepare('INSERT INTO audit (seq, at, actor, action, ref, detail_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');

  return {
    append(event: AuditEvent): void {
      const entry = closed(event);
      inTransaction(db, () => {
        const prev = (last.get() as { hash: string } | undefined)?.hash ?? ZERO_HASH;
        const seq = (nextSeq.get() as { seq: number }).seq;
        const row = { seq, at: entry.at, actor: entry.actor, action: entry.action, ref: entry.ref, detail: entry.detail, prev_hash: prev };
        insert.run(seq, entry.at, entry.actor, entry.action, entry.ref, canonicalJson(entry.detail), prev, hashOf(row));
      });
    },

    read(since: number, limit?: number): { entries: readonly AuditRow[]; more: boolean } {
      const take = limit ?? Number.MAX_SAFE_INTEGER;
      const rows = db.prepare('SELECT * FROM audit WHERE seq > ? ORDER BY seq LIMIT ?').all(since, take === Number.MAX_SAFE_INTEGER ? -1 : take + 1) as unknown as StoredRow[];
      return { entries: rows.slice(0, take).map(toRow), more: rows.length > take };
    },

    verifyChain(): ChainVerdict {
      let expectedPrev = ZERO_HASH;
      let expectedSeq = 1;
      let rows = 0;
      for (const stored of db.prepare('SELECT * FROM audit ORDER BY seq').iterate() as Iterable<StoredRow>) {
        const row = toRow(stored);
        const { hash, ...unsigned } = row;
        if (row.seq !== expectedSeq || row.prev_hash !== expectedPrev || hashOf(unsigned) !== hash) return { ok: false, firstBadSeq: row.seq };
        expectedPrev = hash;
        expectedSeq = row.seq + 1;
        rows += 1;
      }
      return { ok: true, rows };
    },
  };
}
