// KBOX-29, KBOX-31, KBOX-50: untrusted input becomes a typed value at the edge, or a refusal that says nothing about the
// input. The same closed-object parser backs request bodies, query strings, event data and audit detail.
import { AdapterError } from './errors.ts';

export type Parsed<T> = { readonly ok: true; readonly value: T } | { readonly ok: false };

// --- fields -----------------------------------------------------------------------------------------------------

interface TextField {
  readonly kind: 'text';
  readonly pattern: RegExp;
}
interface IntField {
  readonly kind: 'int';
  readonly min: number;
  readonly max: number;
}
interface OneOfField<V extends readonly string[]> {
  readonly kind: 'oneOf';
  readonly values: V;
}
interface TrueField {
  readonly kind: 'true';
}
interface BoolField {
  readonly kind: 'bool';
}
type BaseField = TextField | IntField | OneOfField<readonly string[]> | TrueField | BoolField;
type OptionalOf<F extends BaseField> = F & { readonly optional: true };
export type Field = BaseField | OptionalOf<BaseField>;
export type Schema = Readonly<Record<string, Field>>;

export const text = (pattern: RegExp): TextField => ({ kind: 'text', pattern });
export const int = (min = 0, max = Number.MAX_SAFE_INTEGER): IntField => ({ kind: 'int', min, max });
export const oneOf = <const V extends readonly string[]>(...values: V): OneOfField<V> => ({ kind: 'oneOf', values });
export const isTrue: TrueField = { kind: 'true' };
export const isBool: BoolField = { kind: 'bool' };
export const optional = <F extends BaseField>(field: F): OptionalOf<F> => ({ ...field, optional: true });

type ValueOf<F> = F extends { kind: 'text' } ? string : F extends { kind: 'int' } ? number : F extends { kind: 'oneOf'; values: infer V extends readonly string[] } ? V[number] : F extends { kind: 'true' } ? true : F extends { kind: 'bool' } ? boolean : never;
type RequiredKeys<S extends Schema> = { [K in keyof S]: S[K] extends { optional: true } ? never : K }[keyof S];
type OptionalKeys<S extends Schema> = { [K in keyof S]: S[K] extends { optional: true } ? K : never }[keyof S];
type Flat<T> = { [K in keyof T]: T[K] };
export type Infer<S extends Schema> = Flat<{ [K in RequiredKeys<S>]: ValueOf<S[K]> } & { [K in OptionalKeys<S>]?: ValueOf<S[K]> }>;

// --- the shapes of names the box writes ---------------------------------------------------------------------------

/** A machine label: chosen by the enrolling machine, so it is held to a short name. */
export const LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** A name the box itself chose: key reference, route, approval id, project. */
export const NAME = /^[A-Za-z0-9/][A-Za-z0-9._:/@-]{0,127}$/;
/** A code: a reason, a step, a state. */
export const CODE = /^[a-z][a-z0-9_]{0,63}$/;
/** The one-line title of an approval, printable ASCII only. */
export const TITLE = /^[\x20-\x7e]{1,200}$/;
export const REQUEST_ID = /^req_[A-Za-z0-9_-]{12}$/;
export const ADDRESS = /^[0-9A-Fa-f.:]{2,45}$/;
export const NETWORK = /^[0-9a-f.:]{3,45}\/(24|48)$/;

const MAX_TEXT = 512;

// --- the parser -----------------------------------------------------------------------------------------------------

const refused = { ok: false } as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function fieldValue(field: Field, raw: unknown, fromQuery: boolean): Parsed<unknown> {
  switch (field.kind) {
    case 'text':
      return typeof raw === 'string' && raw.length <= MAX_TEXT && field.pattern.test(raw) ? { ok: true, value: raw } : refused;
    case 'oneOf':
      return typeof raw === 'string' && field.values.includes(raw) ? { ok: true, value: raw } : refused;
    case 'true':
      return !fromQuery && raw === true ? { ok: true, value: true } : refused;
    case 'bool':
      return !fromQuery && typeof raw === 'boolean' ? { ok: true, value: raw } : refused;
    case 'int': {
      const n = fromQuery ? (typeof raw === 'string' && /^\d{1,15}$/.test(raw) ? Number(raw) : Number.NaN) : raw;
      return typeof n === 'number' && Number.isSafeInteger(n) && n >= field.min && n <= field.max ? { ok: true, value: n } : refused;
    }
  }
}

function parseMembers<S extends Schema>(schema: S, input: Record<string, unknown>, fromQuery: boolean): Parsed<Infer<S>> {
  for (const name of Object.keys(input)) if (!Object.hasOwn(schema, name)) return refused;
  const out: Record<string, unknown> = {};
  for (const [name, field] of Object.entries(schema)) {
    if (!Object.hasOwn(input, name)) {
      if ('optional' in field) continue;
      return refused;
    }
    const parsed = fieldValue(field, input[name], fromQuery);
    if (!parsed.ok) return refused;
    out[name] = parsed.value;
  }
  return { ok: true, value: out as Infer<S> };
}

/** A closed object: every member known, required ones present, each of its type and shape. Nothing of the input is kept in a refusal. */
export function parseObject<S extends Schema>(schema: S, input: unknown): Parsed<Infer<S>> {
  return isPlainObject(input) ? parseMembers(schema, input, false) : refused;
}

/** The same for a query string: members are strings, an integer is its decimal text, a repeated member is refused. */
export function parseQuery<S extends Schema>(schema: S, params: URLSearchParams): Parsed<Infer<S>> {
  const seen: Record<string, string> = {};
  for (const [name, value] of params) {
    if (Object.hasOwn(seen, name)) return refused;
    seen[name] = value;
  }
  return parseMembers(schema, seen, true);
}

const BOM = [0xef, 0xbb, 0xbf] as const;

/** A request body as JSON: valid UTF-8 without a byte order mark, one JSON value. */
export function decodeJsonBody(bytes: Uint8Array): Parsed<unknown> {
  if (bytes.length >= 3 && BOM.every((b, i) => bytes[i] === b)) return refused;
  let textOf: string;
  try {
    textOf = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return refused;
  }
  try {
    return { ok: true, value: JSON.parse(textOf) as unknown };
  } catch {
    return refused;
  }
}

/** JSON text from an upstream platform. A failure is a fixed error: the text may hold a new key and is never quoted. */
export function parseUpstreamJson(textOf: string): unknown {
  try {
    return JSON.parse(textOf) as unknown;
  } catch {
    throw new AdapterError('bad_response');
  }
}

// --- events (KBOX-31): the closed list of kinds and their data --------------------------------------------------------

export const BOX_NOTICE_TEXTS = ['credential withheld', 'idle near', 'orphan key found', 'delivery unacknowledged'] as const;

export const EVENT_SCHEMAS = {
  'approval.opened': { approval_id: text(NAME), approval_kind: text(CODE), title: text(TITLE), slot: text(NAME), revision: int() },
  'approval.decided': { approval_id: text(NAME), decision: oneOf('approved', 'denied', 'expired') },
  'approval.executed': { approval_id: text(NAME), result: oneOf('done', 'failed'), reason_code: text(CODE) },
  'key.changed': { keyref: text(NAME) },
  'rotation.state': { run_id: text(NAME), keyref: text(NAME), state: text(CODE), step: text(CODE) },
  'rotation.failed': { run_id: text(NAME), keyref: text(NAME), step: text(CODE), reason_code: text(CODE), old_key_works: isBool },
  'rotation.old_key_still_on': { run_id: text(NAME), keyref: text(NAME), gen: int(1) },
  'delivery.ready': { delivery_id: text(NAME), keyref: text(NAME), project: text(NAME), name: text(NAME), gen: int(1) },
  'share.version': { version: int() },
  'machine.changed': { label: text(LABEL), change: oneOf('enrolled', 'revoked') },
  'token.new_network': { label: text(LABEL), network: text(NETWORK) },
  'update.state': { approval_id: text(NAME), state: oneOf('pending', 'installed', 'rolled_back') },
  'box.notice': { code: text(CODE), text: oneOf(...BOX_NOTICE_TEXTS) },
} as const satisfies Readonly<Record<string, Schema>>;

export type EventKind = keyof typeof EVENT_SCHEMAS;
export type EventData<K extends EventKind> = Infer<(typeof EVENT_SCHEMAS)[K]>;

export const EVENT_KINDS = Object.keys(EVENT_SCHEMAS) as readonly EventKind[];

export const isEventKind = (kind: string): kind is EventKind => Object.hasOwn(EVENT_SCHEMAS, kind);

export function parseEventData<K extends EventKind>(kind: K, data: unknown): Parsed<EventData<K>> {
  return parseObject(EVENT_SCHEMAS[kind], data) as Parsed<EventData<K>>;
}

// --- audit (KBOX-50): a closed detail object per action ---------------------------------------------------------------

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'OTHER'] as const;

/** The actions the box writes. A unit that writes a new action adds its closed detail here. */
export const AUDIT_SCHEMAS = {
  'api.request': {
    request_id: text(REQUEST_ID),
    method: oneOf(...HTTP_METHODS),
    status: int(100, 599),
    code: optional(text(CODE)),
    cause: optional(text(CODE)),
    source: optional(text(ADDRESS)),
  },
  // kernel-approve (KBOX-7, KBOX-9, KBOX-11, KBOX-20, KBOX-49): the row's ref is the approval id, the approver id or the label.
  'approval.proposed': { kind: text(CODE), slot: text(NAME), revision: int(1), decision: oneOf('open', 'replace', 'takeover') },
  'approval.decided': { decision: oneOf('approved', 'denied', 'expired') },
  'approval.executed': { result: oneOf('done', 'failed'), reason_code: text(CODE) },
  /** A passkey assertion or device signature that did not hold: the purpose and a fixed code, nothing of the proof. */
  'proof.refused': { purpose: oneOf('view', 'op', 'register', 'decide'), code: text(CODE) },
  'view.opened': {},
  'approver.registered': { via: oneOf('setup', 'recovery', 'approver_add') },
  'approver.removed': { via: oneOf('recovery', 'approver_remove') },
  /** Recovery replaced the approvers. No code, no text. */
  'recovery.used': {},
  'trust.refused': { change: oneOf('setup', 'recovery', 'approver_add', 'approver_remove'), code: text(CODE) },
  'enrol.window_opened': {},
  'enrol.accepted': { scope: oneOf('control', 'relay') },
  'token.revoked': {},
  'key.issued': {},
  'key.revoked': {},
  // rotate (KBOX-51, KBOX-17, KBOX-34): the row's ref is the key reference (a delivery id for `delivery.acked`).
  'rotation.started': { run_id: text(NAME), origin: oneOf('schedule', 'owner', 'agent', 'approval', 'paste', 'create', 'reconcile'), gen: int(1) },
  'rotation.step_failed': { run_id: text(NAME), step: text(CODE), code: text(CODE) },
  'rotation.completed': { run_id: text(NAME), gen: int(1) },
  'rotation.orphan_revoked': { run_id: text(NAME) },
  'rotation.restarted': { old_run: text(NAME), new_run: text(NAME) },
  'rotation.revoke_unconfirmed': { run_id: text(NAME), gen: int(0), attempt: int(1) },
  'rotation.drive_failed': { run_id: text(NAME), code: text(CODE) },
  'delivery.acked': {},
  /** The hourly approvals sweep threw (core's own timer); a fixed code, nothing of the failure. The next sweep is still scheduled. */
  'approvals.sweep_failed': { code: text(CODE) },
  /** The updater's 5-second settle threw (core's own timer); a fixed code, nothing of the failure. The next settle is still scheduled. */
  'update.settle_failed': { code: text(CODE) },
  /** A push service accepted one message. The row's ref is `push`; no endpoint, key or title is recorded. */
  'push.delivered': { status: int(100, 599) },
  /** A push service answered 404 or 410: that subscription was removed. */
  'push.subscription_removed': { status: int(100, 599) },
  /** One push did not arrive: a closed `code` (`bad_status` carries the status). */
  'push.failed': { code: text(CODE), status: optional(int(100, 599)) },
  /** An orphan temp file of a vault write was zero-filled and removed at start; the row's ref is the key, nothing else is recorded. */
  'vault.temp_swept': {},
  // relay (KBOX-13 step 9, KBOX-50): one row per relayed request; the row's ref is the keyref (or the route) and its actor the
  // pass's label. The query, the path and every body are left out; `rule_id` names the operation.
  'relay.request': {
    route: oneOf('relay', 'grants', 'unmatched'),
    method: oneOf(...HTTP_METHODS),
    status: int(100, 599),
    bytes: int(),
    source: optional(text(ADDRESS)),
    agent: optional(text(LABEL)),
    project: optional(text(NAME)),
    rule_id: optional(text(NAME)),
    code: optional(text(CODE)),
    reason: optional(text(CODE)),
  },
  /** The share writer could not refresh the share file (KBOX-33): a fixed code, nothing of the failure. The file is then served as stale. */
  'share.refresh_failed': { code: text(CODE) },
} as const satisfies Readonly<Record<string, Schema>>;

export type AuditAction = keyof typeof AUDIT_SCHEMAS;
export const isAuditAction = (action: string): action is AuditAction => Object.hasOwn(AUDIT_SCHEMAS, action);

export const AUDIT_ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$/;
