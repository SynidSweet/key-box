// KBOX-3: the messages on the lend socket between kb-relay and core, parsed closed on both sides. One connection carries one
// operation: the relay sends one request frame; core answers and closes (a scan session carries data frames until it ends).
// Frames are a 4-byte big-endian length, a kind byte and the body. Nothing here ever carries a value except the one `B` frame
// that answers a granted lend.
import { HTTP_METHODS, LABEL, NAME, NETWORK, ADDRESS, CODE, int, oneOf, optional, parseObject, text } from './schemas.ts';
import type { Infer, Parsed, Schema } from './schemas.ts';
import type { ScanStep } from './scanner.ts';

export const FRAME_JSON = 0x4a; // 'J'
export const FRAME_BYTES = 0x42; // 'B'
export const FRAME_END = 0x45; // 'E'
/** A mechanical bound on one frame; the relay splits larger chunks. */
export const FRAME_MAX = 1024 * 1024;

const TOKEN_HASH = /^[0-9a-f]{64}$/;
const KEYREF_TEXT = /^[a-z0-9]{6,24}$/;

export const AUDIT_ROW_SCHEMA = {
  label: optional(text(LABEL)),
  source: optional(text(ADDRESS)),
  agent: optional(text(LABEL)),
  project: optional(text(NAME)),
  keyref: optional(text(KEYREF_TEXT)),
  route: oneOf('relay', 'grants', 'unmatched'),
  method: oneOf(...HTTP_METHODS),
  rule_id: optional(text(NAME)),
  status: int(100, 599),
  bytes: int(),
  code: optional(text(CODE)),
  reason: optional(oneOf('partial', 'encoded', 'value', 'credential', 'upstream_refused')),
} as const satisfies Schema;

export type RelayAuditRow = Infer<typeof AUDIT_ROW_SCHEMA>;

const REQUESTS = {
  resolve: { op: oneOf('resolve'), token_hash: text(TOKEN_HASH), keyref: text(KEYREF_TEXT), network: text(NETWORK) },
  grants: { op: oneOf('grants'), token_hash: text(TOKEN_HASH), network: text(NETWORK) },
  lend: { op: oneOf('lend'), token_hash: text(TOKEN_HASH), keyref: text(KEYREF_TEXT), rule_id: text(NAME) },
  scan: { op: oneOf('scan'), token_hash: text(TOKEN_HASH), keyref: text(KEYREF_TEXT) },
} as const satisfies Readonly<Record<string, Schema>>;

export type LendRequest =
  | Infer<(typeof REQUESTS)['resolve']>
  | Infer<(typeof REQUESTS)['grants']>
  | Infer<(typeof REQUESTS)['lend']>
  | Infer<(typeof REQUESTS)['scan']>
  | { readonly op: 'audit'; readonly row: RelayAuditRow };

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function parseLendRequest(raw: unknown): Parsed<LendRequest> {
  if (!isRecord(raw)) return { ok: false };
  const op = raw['op'];
  if (op === 'audit') {
    if (Object.keys(raw).some((k) => k !== 'op' && k !== 'row')) return { ok: false };
    const row = parseObject(AUDIT_ROW_SCHEMA, raw['row']);
    return row.ok ? { ok: true, value: { op: 'audit', row: row.value } } : { ok: false };
  }
  if (op !== 'resolve' && op !== 'grants' && op !== 'lend' && op !== 'scan') return { ok: false };
  return parseObject(REQUESTS[op], raw) as Parsed<LendRequest>;
}

/** Why core refused: `bad_token` (unknown, revoked or not a relay pass), `forbidden` (no key, grant, class, profile or rule). */
export type LendRefusal = 'bad_token' | 'forbidden' | 'bad_request';
const REFUSAL = { ok: oneOf('false'), code: oneOf('bad_token', 'forbidden', 'bad_request') } as const satisfies Schema;

export interface Grant {
  readonly keyref: string;
  readonly platform: string;
  readonly name: string;
  readonly projects: readonly string[];
}

export type ResolveAnswer = { readonly ok: true; readonly label: string; readonly platform: string } | { readonly ok: false; readonly code: LendRefusal };
export type GrantsAnswer = { readonly ok: true; readonly machine: string; readonly grants: readonly Grant[] } | { readonly ok: false; readonly code: LendRefusal };

/** Refusals travel as `{"ok":"false","code":…}` so every answer is a flat closed object. */
export const refusalMessage = (code: LendRefusal): Record<string, string> => ({ ok: 'false', code });

function refusalOf(raw: unknown): { readonly ok: false; readonly code: LendRefusal } | undefined {
  const parsed = parseObject(REFUSAL, raw);
  return parsed.ok ? { ok: false, code: parsed.value.code } : undefined;
}

const RESOLVED = { ok: oneOf('true'), label: text(LABEL), platform: text(/^[a-z0-9][a-z0-9-]{0,31}$/) } as const satisfies Schema;

export function parseResolveAnswer(raw: unknown): Parsed<ResolveAnswer> {
  const refusal = refusalOf(raw);
  if (refusal !== undefined) return { ok: true, value: refusal };
  const parsed = parseObject(RESOLVED, raw);
  return parsed.ok ? { ok: true, value: { ok: true, label: parsed.value.label, platform: parsed.value.platform } } : { ok: false };
}

const GRANT = { keyref: text(KEYREF_TEXT), platform: text(/^[a-z0-9][a-z0-9-]{0,31}$/), name: text(NAME) } as const satisfies Schema;

export function parseGrantsAnswer(raw: unknown): Parsed<GrantsAnswer> {
  const refusal = refusalOf(raw);
  if (refusal !== undefined) return { ok: true, value: refusal };
  if (!isRecord(raw) || raw['ok'] !== 'true' || typeof raw['machine'] !== 'string' || !LABEL.test(raw['machine']) || !Array.isArray(raw['grants'])) return { ok: false };
  if (Object.keys(raw).some((k) => !['ok', 'machine', 'grants'].includes(k))) return { ok: false };
  const grants: Grant[] = [];
  for (const entry of raw['grants'] as unknown[]) {
    if (!isRecord(entry)) return { ok: false };
    const { projects, ...rest } = entry;
    const flat = parseObject(GRANT, rest);
    if (!flat.ok || !Array.isArray(projects) || !projects.every((p): p is string => typeof p === 'string' && NAME.test(p))) return { ok: false };
    grants.push({ ...flat.value, projects });
  }
  return { ok: true, value: { ok: true, machine: raw['machine'], grants } };
}

const SCAN_PROGRESS = { step: oneOf('progress'), releasable: int() } as const satisfies Schema;
const SCAN_HIT = { step: oneOf('hit'), reason: oneOf('value', 'credential') } as const satisfies Schema;

export const scanStepMessage = (step: ScanStep): Record<string, string | number> =>
  step.kind === 'progress' ? { step: 'progress', releasable: step.releasable } : { step: 'hit', reason: step.reason };

export function parseScanStep(raw: unknown): Parsed<ScanStep> {
  const progress = parseObject(SCAN_PROGRESS, raw);
  if (progress.ok) return { ok: true, value: { kind: 'progress', releasable: progress.value.releasable } };
  const hit = parseObject(SCAN_HIT, raw);
  return hit.ok ? { ok: true, value: { kind: 'hit', reason: hit.value.reason } } : { ok: false };
}

const ACCEPTED = { ok: oneOf('true') } as const satisfies Schema;
export const acceptedMessage = (): Record<string, string> => ({ ok: 'true' });
export const parseAccepted = (raw: unknown): boolean => parseObject(ACCEPTED, raw).ok;
