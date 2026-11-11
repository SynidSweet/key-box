// KBOX-53, KBOX-7: the closed action kinds and their typed members. An action is parsed once, at the edge, into one of
// these; the box stores it as typed data and builds its words, slot and digest from it, never from requester text.
import { LABEL, NAME, parseObject, text, int, oneOf, optional, isTrue } from './schemas.ts';
import type { Parsed, Schema } from './schemas.ts';

const PLATFORM = /^[a-z0-9][a-z0-9-]{0,31}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SCOPE_ITEM = /^[A-Za-z0-9_.:/-]{1,128}$/;
const HASH = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SETTING = /^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/;
const SETTING_VALUE = /^[\x20-\x7e]{0,256}$/;
const TARGET = /^[A-Za-z0-9_./:@-]{0,256}$/;
const OP = /^[a-z][a-z0-9_]{0,63}$/;
const PARAM_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const PARAM_VALUE = /^[\x20-\x7e]{0,256}$/;
export const APPROVER_ID = /^ap-[A-Za-z0-9_-]{8,64}$/;
/** The enrol label of KBOX-53. */
export const ENROL_LABEL = /^[a-z0-9-]{1,32}$/;
export const ADDRESS_TEXT = /^[0-9A-Fa-f.:]{2,45}$/;

export interface Destination {
  readonly kind: 'vercel_env' | 'gcp_secret' | 'supabase_secret' | 'workstation';
  readonly target: string;
  readonly environments?: readonly ('production' | 'preview' | 'development')[];
}

export interface AllowRule {
  readonly op: string;
  readonly params: Readonly<Record<string, string>>;
}

export type Action =
  | { readonly kind: 'add_key'; readonly platform: string; readonly name: string; readonly projects: readonly string[]; readonly scope: { readonly items: readonly string[] }; readonly mark_admin?: true; readonly label?: string }
  | { readonly kind: 'delete_key' | 'rotate_key' | 'demote'; readonly keyref: string }
  | { readonly kind: 'grant' | 'revoke_grant'; readonly keyref: string; readonly machine: string }
  | { readonly kind: 'add_destination' | 'remove_destination'; readonly keyref: string; readonly destination: Destination }
  | { readonly kind: 'set_allow_rules'; readonly keyref: string; readonly rules: readonly AllowRule[] }
  | { readonly kind: 'set_schedule'; readonly keyref: string; readonly rotate_every_days: number; readonly grace_hours: number }
  | { readonly kind: 'vercel_set_domain'; readonly project: string; readonly op: 'add' | 'remove' | 'move'; readonly domain: string; readonly to_project?: string }
  | { readonly kind: 'vercel_set_team_setting'; readonly setting: string; readonly value: string }
  | { readonly kind: 'approver_add' }
  | { readonly kind: 'approver_remove'; readonly approver_id: string }
  | { readonly kind: 'install_update'; readonly install: string; readonly commit: string; readonly base: string }
  | { readonly kind: 'enrol'; readonly label: string; readonly token_sha256: string; readonly address: string };

export type ActionKind = Action['kind'];

export const ACTION_KINDS = [
  'add_key',
  'delete_key',
  'rotate_key',
  'grant',
  'revoke_grant',
  'add_destination',
  'remove_destination',
  'set_allow_rules',
  'set_schedule',
  'demote',
  'vercel_set_domain',
  'vercel_set_team_setting',
  'approver_add',
  'approver_remove',
  'install_update',
  'enrol',
] as const satisfies readonly ActionKind[];

/** The kinds `POST /api/proposals` creates; the other three have their own routes (KBOX-53). */
export const PROPOSAL_ROUTE_KINDS = ACTION_KINDS.filter((k) => k !== 'add_key' && k !== 'install_update' && k !== 'enrol');

const refused = { ok: false } as const;
const KEYREF = text(NAME);

/** The flat members of each kind; the nested ones are checked by hand below. */
const FLAT: { readonly [K in ActionKind]: Schema } = {
  add_key: { kind: text(/^add_key$/), platform: text(PLATFORM), name: text(ENV_NAME), mark_admin: optional(isTrue), label: optional(text(LABEL)) },
  delete_key: { kind: text(/^delete_key$/), keyref: KEYREF },
  rotate_key: { kind: text(/^rotate_key$/), keyref: KEYREF },
  demote: { kind: text(/^demote$/), keyref: KEYREF },
  grant: { kind: text(/^grant$/), keyref: KEYREF, machine: text(LABEL) },
  revoke_grant: { kind: text(/^revoke_grant$/), keyref: KEYREF, machine: text(LABEL) },
  add_destination: { kind: text(/^add_destination$/), keyref: KEYREF },
  remove_destination: { kind: text(/^remove_destination$/), keyref: KEYREF },
  set_allow_rules: { kind: text(/^set_allow_rules$/), keyref: KEYREF },
  set_schedule: { kind: text(/^set_schedule$/), keyref: KEYREF, rotate_every_days: int(1, 3650), grace_hours: int(0, 24 * 365) },
  vercel_set_domain: { kind: text(/^vercel_set_domain$/), project: text(NAME), op: oneOf('add', 'remove', 'move'), domain: text(DOMAIN), to_project: optional(text(NAME)) },
  vercel_set_team_setting: { kind: text(/^vercel_set_team_setting$/), setting: text(SETTING), value: text(SETTING_VALUE) },
  approver_add: { kind: text(/^approver_add$/) },
  approver_remove: { kind: text(/^approver_remove$/), approver_id: text(APPROVER_ID) },
  install_update: { kind: text(/^install_update$/), install: text(HASH), commit: text(COMMIT), base: text(HASH) },
  enrol: { kind: text(/^enrol$/), label: text(ENROL_LABEL), token_sha256: text(HASH), address: text(ADDRESS_TEXT) },
};

/** The nested members of a kind, by name. */
const NESTED: Partial<Readonly<Record<ActionKind, readonly string[]>>> = {
  add_key: ['projects', 'scope'],
  add_destination: ['destination'],
  remove_destination: ['destination'],
  set_allow_rules: ['rules'],
};

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

const stringList = (v: unknown, pattern: RegExp, min: number, max: number): readonly string[] | undefined =>
  Array.isArray(v) && v.length >= min && v.length <= max && v.every((s) => typeof s === 'string' && pattern.test(s)) && new Set(v).size === v.length ? (v as string[]) : undefined;

function destination(v: unknown): Destination | undefined {
  if (!isRecord(v)) return undefined;
  const flat = parseObject({ kind: oneOf('vercel_env', 'gcp_secret', 'supabase_secret', 'workstation'), target: text(TARGET) }, { kind: v['kind'], target: v['target'] });
  if (!flat.ok || !Object.keys(v).every((k) => k === 'kind' || k === 'target' || k === 'environments')) return undefined;
  if ((flat.value.kind === 'workstation') !== (flat.value.target === '')) return undefined;
  if (!Object.hasOwn(v, 'environments')) return flat.value;
  const environments = stringList(v['environments'], /^(production|preview|development)$/, 1, 3) as Destination['environments'];
  return environments === undefined ? undefined : { ...flat.value, environments };
}

function rules(v: unknown): readonly AllowRule[] | undefined {
  if (!Array.isArray(v) || v.length > 64) return undefined;
  const out: AllowRule[] = [];
  for (const r of v) {
    if (!isRecord(r) || Object.keys(r).length !== 2 || typeof r['op'] !== 'string' || !OP.test(r['op']) || !isRecord(r['params'])) return undefined;
    const params: Record<string, string> = {};
    for (const [name, value] of Object.entries(r['params'])) {
      if (!PARAM_NAME.test(name) || typeof value !== 'string' || !PARAM_VALUE.test(value)) return undefined;
      params[name] = value;
    }
    out.push({ op: r['op'], params });
  }
  return out;
}

const isKind = (k: unknown): k is ActionKind => typeof k === 'string' && (ACTION_KINDS as readonly string[]).includes(k);

/** One closed action, or a refusal that says nothing about the input. An unknown kind or member is refused. */
export function parseAction(input: unknown): Parsed<Action> {
  if (!isRecord(input) || !isKind(input['kind'])) return refused;
  const kind = input['kind'];
  const nested = NESTED[kind] ?? [];
  const flatInput = Object.fromEntries(Object.entries(input).filter(([k]) => !nested.includes(k)));
  const flat = parseObject(FLAT[kind], flatInput);
  if (!flat.ok) return refused;
  const out: Record<string, unknown> = { ...flat.value };
  if (kind === 'add_key') {
    const projects = stringList(input['projects'], NAME, 1, 64);
    const scope = input['scope'];
    if (projects === undefined || !isRecord(scope) || Object.keys(scope).length !== 1) return refused;
    const items = stringList(scope['items'], SCOPE_ITEM, 0, 64);
    if (items === undefined) return refused;
    out['projects'] = projects;
    out['scope'] = { items };
  } else if (kind === 'add_destination' || kind === 'remove_destination') {
    const d = destination(input['destination']);
    if (d === undefined) return refused;
    out['destination'] = d;
  } else if (kind === 'set_allow_rules') {
    const r = rules(input['rules']);
    if (r === undefined) return refused;
    out['rules'] = r;
  }
  if (kind === 'vercel_set_domain' && (out['op'] === 'move') !== (out['to_project'] !== undefined)) return refused;
  return { ok: true, value: out as Action };
}
