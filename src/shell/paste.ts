// KBOX-12: the phone paste flow. A paste task is a proposal that sits in the slot of its action (`add_key` or `rotate_key`) and is
// settled by the owner's paste: the passkey assertion and device-key signature over SHA-256("kbox-v1-paste" || pasteId || actionDigest || nonce)
// ARE the approval of that one action. The value is checked (16-byte floor, the key's strict shape, the verifier that applies to the key), stored, and never
// echoed. A task is only in the app: the box sends no link to it.
import type { DatabaseSync } from 'node:sqlite';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import { actionDigest, pasteChallenge } from '../pure/challenge.ts';
import { keyrefOf, matchesShape } from '../pure/class.ts';
import { ApiError } from '../pure/errors.ts';
import { shapeOfKey } from '../pure/platform-shape.ts';
import { decideSlot, parseRequester, requesterText, slotOf } from '../pure/slots.ts';
import type { Requester } from '../pure/slots.ts';
import { FIXED, renderPage, titleOf } from '../pure/words.ts';
import type { Reason } from '../pure/words.ts';
import { makeLent } from '../pure/lent.ts';
import type { Parsed } from '../pure/schemas.ts';
import { parseProof } from './approvers.ts';
import type { Approvers, ProofBytes } from './approvers.ts';
import { file } from './routes-approve.ts';
import { parsedRoute, route } from './http.ts';
import type { Route } from './http.ts';
import { inTransaction } from './db.ts';
import { locationOf, newKeyOf } from './new-key.ts';
import type { RotationStore } from './rotation-store.ts';
import type { KeyKind, Verifier } from '../ports/issuer.ts';
import type { KeyLocation, KeyShape } from '../ports/types.ts';
import type { PasteAction } from './new-key.ts';
import type { Orchestrator } from './orchestrator.ts';
import { kindOfStored, kitFor, storedPlacement, verifierFor, verifyTargetOf } from './rotation-ports.ts';
import type { PlatformKit, PlatformSource } from './rotation-ports.ts';

export const PASTE_TTL_MS = 14 * 24 * 3600_000;
/** The core length floor of KBOX-12 (open point 2: one constant). */
export const PASTE_FLOOR_BYTES = 16;
const VALUE_LIMIT = 4096;
/** A hint name is at most 32 characters (KBOX-23); a longer one is not a request this route understands. */
const VERIFY_HINT_LIMIT = 64;

/** The sentence that asks for the paste; the fixed rule on every paste page is `FIXED.pasteWhere`. */
export const PASTE_ASK = 'Create the key on your phone, at the platform, then paste it here.';

interface TaskRow {
  readonly paste_id: string;
  readonly slot: string;
  readonly action_json: string;
  readonly digest_hex: string;
  readonly revision: number;
  readonly requester: string;
  readonly reason_json: string | null;
  readonly opened_at: number;
  readonly expires_at: number;
}

export interface PasteDeps {
  readonly db: DatabaseSync;
  readonly approvers: Approvers;
  readonly clock: Clock;
  readonly random: Random;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly push: Push;
  readonly meta: MetaStore;
  readonly source: PlatformSource;
  readonly orchestrator: Orchestrator;
  /** Whether a reference is taken, and a stored key's location (KBOX-57). */
  readonly store: Pick<RotationStore, 'key' | 'keyExists' | 'keyInfo'>;
}

export interface PasteView {
  readonly paste_id: string;
  readonly revision: number;
  readonly title: string;
  readonly lines: readonly string[];
  /** The adapter's own page for making the key. Never from mission control. */
  readonly platform_link?: string;
  /** The entry's verify hints for the paste page's choice (KBOX-40); absent for an entry with none. */
  readonly verify_hints?: readonly string[];
  /** The hint stored with the key, preselected on a rotation. */
  readonly verify_hint?: string;
  readonly phrase: string;
  readonly digest_b64: string;
  readonly nonce_b64: string;
  readonly expires_at: number;
}

export interface Paste {
  /** Opens a task, replaces the pending one of the same requester, or (the box) takes the slot over. `slot_taken` for another token. */
  open(input: { readonly action: PasteAction; readonly requester: Requester; readonly reason?: Reason }): { readonly paste_id: string; readonly revision: number; readonly slot: string; readonly replaced: boolean };
  /** For `GET /p/<id>`: needs a view session; shows the viewer's own phrase. */
  view(id: string, cookie: string | undefined): PasteView;
  /** Whether a task waits in this slot (the scheduler opens none beside it). */
  hasPending(slot: string): boolean;
  /** KBOX-62: expires every pending task naming the key (a rotation by paste of a key being deleted), each as its own expiry writes it. */
  expireNaming(keyref: string): void;
  /**
   * When the box's latest task in this slot expired unanswered (KBOX-52): its own expiry time, the only time a task records for it. undefined
   * when that task is pending or was settled, or there is none; a token's task (a manual "replace now") never counts. A paste has no refusal.
   */
  lastExpiredAt(slot: string): number | undefined;
  /** The pending tasks of the app's queue. */
  pending(cookie: string | undefined): readonly { readonly paste_id: string; readonly title: string }[];
  /** For `POST /p/<id>`: the paste with its proof, and the verify hint the owner chose (KBOX-40; not covered by the proof). */
  submit(id: string, cookie: string | undefined, value: string, proof: ProofBytes, verifyHint?: string): Promise<{ readonly keyref: string }>;
}

const rejected = (code: string): ApiError => new ApiError('rejected', code);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

export function createPaste(deps: PasteDeps): Paste {
  const { db } = deps;
  const now = (): number => deps.clock.now();
  const row = (id: string): TaskRow | undefined => db.prepare("SELECT * FROM paste_tasks WHERE paste_id = ? AND status = 'pending'").get(id) as TaskRow | undefined;
  const actionOf = (r: TaskRow): PasteAction => JSON.parse(r.action_json) as PasteAction;

  const expire = (stale: readonly { readonly paste_id: string }[]): void => {
    for (const { paste_id } of stale) {
      inTransaction(db, () => void db.prepare("UPDATE paste_tasks SET status = 'expired' WHERE paste_id = ?").run(paste_id));
      deps.events.append('approval.decided', { approval_id: paste_id, decision: 'expired' });
    }
  };
  const sweep = (): void => {
    expire(db.prepare("SELECT paste_id FROM paste_tasks WHERE status = 'pending' AND expires_at <= ?").all(now()) as unknown as { paste_id: string }[]);
  };
  const viewer = (cookie: string | undefined): string => {
    const id = deps.approvers.viewer(cookie);
    if (id === undefined) throw new ApiError('unauthorized', 'view_session_needed');
    return id;
  };
  const pending = (id: string): TaskRow => {
    sweep();
    const r = row(id);
    if (r === undefined) throw new ApiError('not_found');
    return r;
  };
  const settle = (id: string, status: 'done' | 'failed'): void => void inTransaction(db, () => db.prepare('UPDATE paste_tasks SET status = ? WHERE paste_id = ?').run(status, id));

  /** The task can no longer be settled by a paste (no retry can change that): it is settled failed with the names-only code, and the paste is refused. */
  const refuse = (id: string, error: ApiError, code: string): never => {
    settle(id, 'failed');
    deps.events.append('approval.executed', { approval_id: id, result: 'failed', reason_code: code });
    deps.audit.append({ action: 'approval.executed', subject: id, at: now(), detail: { result: 'failed', reason_code: code } });
    throw error;
  };
  /** The task's key reference exists: `conflict` `key_exists`. */
  const refuseTaken = (id: string): never => refuse(id, new ApiError('conflict', 'key_exists'), 'key_exists');
  /** The stored key's location no longer passes its entry (KBOX-57): `rejected` with the refusal code, before the verifier is asked. */
  const refuseUnplaced = (id: string, keyref: string): void => {
    const head = deps.store.key(keyref);
    const info = deps.store.keyInfo(keyref);
    const placed = head === undefined || info === undefined ? 'ok' : storedPlacement(deps.source, head, info);
    if (placed !== 'ok') refuse(id, rejected(placed), placed);
  };

  /** The platform a task's key is on: the action's for a new key, the stored key's for a rotation ('' for a key no longer stored). */
  const platformOf = (action: PasteAction): string =>
    action.kind === 'add_key' ? action.platform : (deps.meta.snapshot().keys.find((k) => k.keyref === action.keyref)?.platform ?? '');
  /** The adapters a task is judged with: its platform's for a new key, the stored key's own kit for a rotation (KBOX-55). */
  const kitOfTask = (action: PasteAction): PlatformKit | undefined =>
    action.kind === 'add_key' ? deps.source.platform(action.platform) : kitFor(deps.source, { platform: platformOf(action), keyref: action.keyref });
  /** The key a task is for, as KBOX-58 judges it: the action's scope and location for a new key, the stored ones for a rotation. */
  const kindOf = (action: PasteAction): KeyKind =>
    action.kind === 'add_key' ? { scopeItems: action.scope.items, at: locationOf(action) } : kindOfStored(deps.store.keyInfo(action.keyref));
  /** KBOX-58: no verifier of the platform applies to the task's key, so no paste can ever settle it: the task fails `no_verifier`. */
  const refuseUnverifiable = (id: string, verifier: Verifier | undefined): Verifier => verifier ?? refuse(id, rejected('no_verifier'), 'no_verifier');

  /** The value checks of KBOX-12, in order: the floor, the key's strict shape, the verifier that applies to the key. Names only. */
  async function checkValue(target: { readonly platform: string; readonly at: KeyLocation; readonly hint: string | undefined }, value: string, shape: KeyShape, verifier: Verifier, kind: KeyKind): Promise<void> {
    const { platform, at, hint } = target;
    if (Buffer.byteLength(value, 'utf8') < PASTE_FLOOR_BYTES) throw rejected('too_short');
    if (!matchesShape(shape, value)) throw rejected('bad_shape');
    const bytes = Uint8Array.from(Buffer.from(value, 'utf8'));
    const lent = makeLent('paste:1', () => Uint8Array.from(bytes));
    // KBOX-58: a verifier that needs the master gets the one KBOX-57 chooses for the key, resolved now; none chosen, its own answer decides.
    const chosen = verifier.needsMaster === true ? deps.source.master(platform, kind.at, kind.scopeItems) : undefined;
    const asked = verifyTargetOf(verifier, { platform, at, ...(hint === undefined ? {} : { hint }) }, chosen?.ok === true ? chosen.value : undefined);
    const verdict = await verifier.verify(lent, asked).catch((): 'unreachable' => 'unreachable');
    bytes.fill(0);
    if (verdict !== 'ok') throw rejected(verdict === 'rejected' ? 'verifier_rejected' : 'verifier_unreachable');
  }

  /** `chosen` is the hint this paste carried (stored with the key); a paste without one leaves the stored choice as it is. */
  async function execute(action: PasteAction, bytes: Uint8Array, chosen: string | undefined): Promise<string> {
    const verifyHint = chosen === undefined ? {} : { verifyHint: chosen };
    if (action.kind === 'rotate_key') {
      deps.orchestrator.start({ keyref: action.keyref, origin: 'paste', value: bytes, ...verifyHint });
      return action.keyref;
    }
    const key = { ...newKeyOf(action, deps.source), ...verifyHint };
    const created = await deps.orchestrator.create(key, bytes);
    if (created.status !== 'works') throw rejected('check_failed');
    return key.keyref;
  }

  return {
    open({ action, requester, reason }) {
      sweep();
      const slot = slotOf(action);
      const held = db.prepare("SELECT * FROM paste_tasks WHERE slot = ? AND status = 'pending'").get(slot) as TaskRow | undefined;
      const decision = decideSlot(held === undefined ? undefined : (parseRequester(held.requester) ?? { kind: 'box' }), requester);
      if (decision === 'taken' && held !== undefined) throw new ApiError('slot_taken', { pending_approval_id: held.paste_id });
      const digest = Buffer.from(actionDigest(action)).toString('hex');
      const title = titleOf(action);
      const at = now();
      const reasonJson = reason === undefined ? null : JSON.stringify(reason);
      const out = inTransaction(db, () => {
        if (held === undefined || decision === 'open') {
          const id = `apr_${b64u(deps.random.bytes(12))}`;
          db.prepare('INSERT INTO paste_tasks (paste_id, slot, action_json, digest_hex, revision, requester, reason_json, opened_at, expires_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)').run(
            id,
            slot,
            JSON.stringify(action),
            digest,
            requesterText(requester),
            reasonJson,
            at,
            at + PASTE_TTL_MS,
          );
          return { id, revision: 1 };
        }
        const revision = held.revision + 1;
        db.prepare('UPDATE paste_tasks SET action_json = ?, digest_hex = ?, revision = ?, requester = ?, reason_json = ? WHERE paste_id = ?').run(JSON.stringify(action), digest, revision, requesterText(requester), reasonJson, held.paste_id);
        return { id: held.paste_id, revision };
      });
      deps.events.append('approval.opened', { approval_id: out.id, approval_kind: action.kind, title, slot, revision: out.revision });
      deps.audit.append({ action: 'approval.proposed', subject: out.id, at, detail: { kind: action.kind, slot, revision: out.revision, decision: decision === 'taken' ? 'open' : decision } });
      if (decision === 'open') deps.push.send({ title, kind: action.kind });
      return { paste_id: out.id, revision: out.revision, slot, replaced: decision !== 'open' };
    },

    view(id, cookie) {
      const approverId = viewer(cookie);
      const r = pending(id);
      const action = actionOf(r);
      const requester = parseRequester(r.requester) ?? { kind: 'box' as const };
      const reason = r.reason_json === null ? undefined : (JSON.parse(r.reason_json) as Reason);
      const coverage = action.kind === 'rotate_key' ? deps.meta.coverageOf(action.keyref) : undefined;
      const page = renderPage(action, { requester, ...(reason === undefined ? {} : { reason }), ...(coverage === undefined ? {} : { coverage }) });
      const kit = kitOfTask(action);
      const link = kit?.keyPageUrl;
      // KBOX-40, KBOX-58: a hint is a choice of the verifier's calls, so it is offered only where a verifier applies to the task's key.
      const hints = verifierFor(kit, kindOf(action)) === undefined ? [] : (kit?.verifyHints ?? []);
      const stored = action.kind === 'rotate_key' ? deps.store.keyInfo(action.keyref)?.verifyHint : undefined;
      const nonce = deps.approvers.nonce({ kind: 'decide', approvalId: id, revision: r.revision });
      return {
        paste_id: id,
        revision: r.revision,
        title: page.title,
        lines: [...page.lines, PASTE_ASK, FIXED.pasteWhere],
        ...(link === undefined ? {} : { platform_link: link }),
        ...(hints.length === 0 ? {} : { verify_hints: hints }),
        ...(hints.length === 0 || stored === undefined ? {} : { verify_hint: stored }),
        phrase: deps.approvers.phraseOf(approverId) ?? '',
        digest_b64: Buffer.from(r.digest_hex, 'hex').toString('base64url'),
        nonce_b64: b64u(nonce),
        expires_at: r.expires_at,
      };
    },

    expireNaming(keyref) {
      const pending = db.prepare("SELECT * FROM paste_tasks WHERE status = 'pending'").all() as unknown as TaskRow[];
      expire(pending.filter((r) => { const action = actionOf(r); return action.kind === 'rotate_key' && action.keyref === keyref; }));
    },

    hasPending(slot) {
      sweep();
      return db.prepare("SELECT 1 AS one FROM paste_tasks WHERE slot = ? AND status = 'pending'").get(slot) !== undefined;
    },

    lastExpiredAt(slot) {
      sweep();
      const latest = db.prepare("SELECT status, expires_at FROM paste_tasks WHERE slot = ? AND requester = 'box' ORDER BY opened_at DESC, rowid DESC LIMIT 1").get(slot) as { status: string; expires_at: number } | undefined;
      return latest?.status === 'expired' ? latest.expires_at : undefined;
    },

    pending(cookie) {
      viewer(cookie);
      sweep();
      return (db.prepare("SELECT paste_id, action_json FROM paste_tasks WHERE status = 'pending' ORDER BY opened_at, paste_id").all() as unknown as { paste_id: string; action_json: string }[]).map((r) => ({
        paste_id: r.paste_id,
        title: titleOf(JSON.parse(r.action_json) as PasteAction),
      }));
    },

    async submit(id, cookie, value, proof, verifyHint) {
      viewer(cookie);
      const r = pending(id);
      const digest =Uint8Array.from(Buffer.from(r.digest_hex, 'hex'));
      const verdict = deps.approvers.check({ kind: 'decide', approvalId: id, revision: r.revision }, (nonce) => pasteChallenge(id, digest, nonce), proof);
      if (!verdict.ok) throw new ApiError('forbidden', 'proof_refused');
      const action = actionOf(r);
      const platform = platformOf(action);
      const kit = kitOfTask(action);
      // KBOX-40: a hint outside the entry's list is refused before anything is stored, and the task stays for the retry.
      if (verifyHint !== undefined && !(kit?.verifyHints ?? []).includes(verifyHint)) throw rejected('bad_verify_hint');
      // KBOX-57: a reference taken while the task waited settles it failed, before the verifier sees the value; a key elsewhere is a new key.
      if (action.kind === 'add_key' && deps.store.keyExists(keyrefOf(action.platform, action.projects, action.name))) refuseTaken(id);
      // KBOX-57: a stored location the entry now refuses fails the task with that code, so the value never reaches the verifier.
      if (action.kind === 'rotate_key') refuseUnplaced(id, action.keyref);
      const at = action.kind === 'add_key' ? locationOf(action) : (deps.store.keyInfo(action.keyref)?.location ?? {});
      const kind = kindOf(action);
      const shape = shapeOfKey(kit, kind);
      if (kit === undefined || shape === undefined) throw rejected('unknown_platform');
      // KBOX-58: before the value is checked, a verifier must apply to the key; none fails the task and stores nothing.
      const verifier = refuseUnverifiable(id, verifierFor(kit, kind));
      // The verifier is told this paste's hint, else the one stored with the key (a rotation without a new choice).
      const stored = action.kind === 'rotate_key' ? deps.store.keyInfo(action.keyref)?.verifyHint : undefined;
      await checkValue({ platform, at, hint: verifyHint ?? stored }, value, shape, verifier, kind);
      const bytes = Uint8Array.from(Buffer.from(value, 'utf8'));
      try {
        const keyref = await execute(action, bytes, verifyHint);
        // The paste with its assertion is the approval of this one action (decided here): it is recorded like any approval, and settled
        // only once the action executed, so a failed execution never spends it.
        settle(id, 'done');
        deps.events.append('approval.decided', { approval_id: id, decision: 'approved' });
        deps.audit.append({ action: 'approval.decided', subject: id, at: now(), actor: verdict.approverId, detail: { decision: 'approved' } });
        deps.events.append('approval.executed', { approval_id: id, result: 'done', reason_code: 'ok' });
        deps.audit.append({ action: 'approval.executed', subject: id, at: now(), detail: { result: 'done', reason_code: 'ok' } });
        return { keyref };
      } catch (error) {
        // The task stays pending for a retry (a fresh page gives a fresh nonce); the attempt is audited by its names-only reason.
        const code = error instanceof ApiError ? (error.detail !== undefined && 'code' in error.detail ? error.detail.code : error.code) : 'failed';
        deps.audit.append({ action: 'approval.executed', subject: id, at: now(), detail: { result: 'failed', reason_code: code } });
        throw error;
      } finally {
        bytes.fill(0);
      }
    },
  };
}

// --- the routes ------------------------------------------------------------------------------------------------------

interface PasteBody {
  readonly value: string;
  readonly proof: ProofBytes;
  /** The read call the owner chose to verify with (KBOX-40); checked against the entry's list when the paste is settled. */
  readonly verifyHint?: string;
}

function parsePasteBody(raw: unknown): Parsed<PasteBody> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false };
  const members = raw as Record<string, unknown>;
  const keys = Object.keys(members);
  const value = members['value'];
  const hint = members['verify_hint'];
  const hinted = hint !== undefined;
  if (keys.length !== (hinted ? 3 : 2) || typeof value !== 'string' || value.length > VALUE_LIMIT) return { ok: false };
  if (hinted && (typeof hint !== 'string' || hint.length > VERIFY_HINT_LIMIT)) return { ok: false };
  const proof = parseProof(members['proof']);
  return proof.ok ? { ok: true, value: { value, proof: proof.value, ...(typeof hint === 'string' ? { verifyHint: hint } : {}) } } : { ok: false };
}

export function pasteRoutes(paste: Paste): Route[] {
  return [
    route({ method: 'GET', path: '/p/:id', surface: 'phone', handle: ({ params, cookie }) => ({ json: paste.view(params['id'] ?? '', cookie) }) }),
    route({ method: 'GET', path: '/app/pastes', surface: 'phone', handle: ({ cookie }) => ({ json: { pastes: paste.pending(cookie) } }) }),
    parsedRoute({
      method: 'POST',
      path: '/p/:id',
      surface: 'phone',
      parse: parsePasteBody,
      handle: async ({ params, cookie, body }) => ({ status: 201, json: { status: 'stored', ...(await paste.submit(params['id'] ?? '', cookie, body.value, body.proof, body.verifyHint)) } }),
    }),
    route({ method: 'GET', path: '/paste.html', surface: 'phone', handle: () => file('paste.html', 'text/html; charset=utf-8') }),
    route({ method: 'GET', path: '/paste.js', surface: 'phone', handle: () => file('paste.js', 'text/javascript; charset=utf-8') }),
  ];
}

