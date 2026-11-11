// KBOX-6: the requests core writes into staging and kb-install reads, and the results root answers. One home for both
// sides: core's writers build these types, kb-install parses the bytes it read back into them and trusts nothing else.
import type { ApprovalProof, TrustApprover, TrustRequest } from '../ports/trust.ts';
import { APPROVER_ID, DOMAIN_NAME } from './actions.ts';
import { RELEASE_HASH } from './release-hash.ts';
import { decodeJsonBody, parseObject, text } from './schemas.ts';
import type { Parsed } from './schemas.ts';

export interface InstallRequest {
  readonly kind: 'install';
  readonly install: string;
  readonly commit: string;
  readonly base: string;
  readonly approval: ApprovalProof;
}

export type RootRequest = InstallRequest | TrustRequest;

/** What kb-install answers, as the text of `<name>.result`. */
export type InstallRefusal = 'no_proof' | 'bad_proof' | 'bad_request' | 'base' | 'already_current' | 'spent' | 'not_regular' | 'hash' | 'lock' | 'size' | 'timeout' | 'internal';
export type TrustRefusal =
  | 'no_proof'
  | 'bad_proof'
  | 'bad_request'
  | 'spent'
  | 'no_trust'
  | 'unknown_approver'
  | 'last_approver'
  | 'no_code'
  | 'wrong_code'
  | 'expired'
  | 'stale_boot'
  | 'trust_exists'
  | 'not_regular'
  | 'size'
  | 'internal';
export type RootResult = 'installed' | 'rolled_back' | 'applied' | `refused:${InstallRefusal | TrustRefusal}`;

/** The base name of a request (`<name>.request`) and its result (`<name>.result`). */
export const REQUEST_NAME = /^[A-Za-z0-9_-]{1,96}$/;
/** A request is read at most this far (KBOX-6). */
export const REQUEST_LIMIT = 64 * 1024;

const B64U = /^[A-Za-z0-9_-]{1,4096}$/;
const COMMIT = /^[0-9a-f]{40}$/;
/** The code as the owner typed it; root normalises and checks it (codes.ts). */
const CODE_TEXT = /^[A-Za-z \t]{1,256}$/;
const APPROVAL_ID = /^[A-Za-z0-9_-]{1,128}$/;

const PROOF = {
  approval_id: text(APPROVAL_ID),
  approver_id: text(APPROVER_ID),
  nonce_b64: text(B64U),
  credential_id_b64: text(B64U),
  authenticator_data_b64: text(B64U),
  client_data_json_b64: text(B64U),
  signature_b64: text(B64U),
  device_signature_b64: text(B64U),
} as const;
const APPROVER = { id: text(APPROVER_ID), cose_b64: text(B64U), device_pub_b64: text(B64U) } as const;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const onlyKeys = (v: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(v).every((k) => keys.includes(k));

const approverOf = (v: unknown): TrustApprover | undefined => {
  const p = parseObject(APPROVER, v);
  return p.ok ? p.value : undefined;
};
const approverList = (v: unknown): readonly TrustApprover[] | undefined => {
  if (!Array.isArray(v) || v.length === 0 || v.length > 16) return undefined;
  const out = v.map(approverOf);
  return out.every((a): a is TrustApprover => a !== undefined) && new Set(out.map((a) => a.id)).size === out.length ? out : undefined;
};

export type RequestParse = { readonly ok: true; readonly request: RootRequest } | { readonly ok: false; readonly code: 'no_proof' | 'bad_proof' | 'bad_request' };

/** A request as root reads it: an unknown member, a missing proof or a malformed one is a fixed refusal. */
export function parseRootRequest(bytes: Uint8Array): RequestParse {
  const bad = { ok: false, code: 'bad_request' } as const;
  const decoded = decodeJsonBody(bytes);
  if (!decoded.ok || !isRecord(decoded.value)) return bad;
  const v = decoded.value;
  const proof = (): Parsed<ApprovalProof> | 'none' => (v['approval'] === undefined ? 'none' : parseObject(PROOF, v['approval']));
  if (v['kind'] === 'install') {
    if (!onlyKeys(v, ['kind', 'install', 'commit', 'base', 'approval'])) return bad;
    const head = parseObject({ install: text(RELEASE_HASH), commit: text(COMMIT), base: text(RELEASE_HASH) }, { install: v['install'], commit: v['commit'], base: v['base'] });
    if (!head.ok) return bad;
    const p = proof();
    if (p === 'none') return { ok: false, code: 'no_proof' };
    if (!p.ok) return { ok: false, code: 'bad_proof' };
    return { ok: true, request: { kind: 'install', ...head.value, approval: p.value } };
  }
  if (v['kind'] !== 'trust') return bad;
  switch (v['change']) {
    case 'setup': {
      if (!onlyKeys(v, ['kind', 'change', 'code', 'domain', 'approvers'])) return bad;
      const head = parseObject({ code: text(CODE_TEXT), domain: text(DOMAIN_NAME) }, { code: v['code'], domain: v['domain'] });
      const approvers = approverList(v['approvers']);
      return head.ok && approvers !== undefined ? { ok: true, request: { kind: 'trust', change: 'setup', ...head.value, approvers } } : bad;
    }
    case 'recovery': {
      if (!onlyKeys(v, ['kind', 'change', 'code', 'approvers'])) return bad;
      const code = typeof v['code'] === 'string' && CODE_TEXT.test(v['code']) ? v['code'] : undefined;
      const approvers = approverList(v['approvers']);
      return code !== undefined && approvers !== undefined ? { ok: true, request: { kind: 'trust', change: 'recovery', code, approvers } } : bad;
    }
    case 'approver_add': {
      if (!onlyKeys(v, ['kind', 'change', 'approval', 'approver'])) return bad;
      const approver = approverOf(v['approver']);
      if (approver === undefined) return bad;
      const p = proof();
      if (p === 'none') return { ok: false, code: 'no_proof' };
      return p.ok ? { ok: true, request: { kind: 'trust', change: 'approver_add', approval: p.value, approver } } : { ok: false, code: 'bad_proof' };
    }
    case 'approver_remove': {
      if (!onlyKeys(v, ['kind', 'change', 'approval', 'approver_id'])) return bad;
      const id = typeof v['approver_id'] === 'string' && APPROVER_ID.test(v['approver_id']) ? v['approver_id'] : undefined;
      if (id === undefined) return bad;
      const p = proof();
      if (p === 'none') return { ok: false, code: 'no_proof' };
      return p.ok ? { ok: true, request: { kind: 'trust', change: 'approver_remove', approval: p.value, approver_id: id } } : { ok: false, code: 'bad_proof' };
    }
    default:
      return bad;
  }
}

/** A result file's text, parsed by core. */
export function parseRootResult(text: string): RootResult | undefined {
  const t = text.trim();
  return /^(installed|rolled_back|applied|refused:[a-z_]{1,32})$/.test(t) ? (t as RootResult) : undefined;
}
