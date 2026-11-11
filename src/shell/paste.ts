// KBOX-12: the phone paste flow. A paste task is a proposal that sits in the slot of its action (`add_key` or `rotate_key`) and is
// settled by the owner's paste: the passkey assertion and device-key signature over SHA-256("kbox-v1-paste" || pasteId || actionDigest || nonce)
// ARE the approval of that one action. The value is checked (16-byte floor, the adapter's strict shape, the platform verifier), stored, and never
// echoed. A task is only in the app: the box sends no link to it.
import type { DatabaseSync } from 'node:sqlite';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import { actionDigest, pasteChallenge } from '../pure/challenge.ts';
import { matchesShape } from '../pure/class.ts';
import { ApiError } from '../pure/errors.ts';
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
import { newKeyOf } from './new-key.ts';
import type { PasteAction } from './new-key.ts';
import type { Orchestrator } from './orchestrator.ts';
import type { PlatformSource } from './rotation-ports.ts';

export const PASTE_TTL_MS = 14 * 24 * 3600_000;
/** The core length floor of KBOX-12 (open point 2: one constant). */
export const PASTE_FLOOR_BYTES = 16;
const VALUE_LIMIT = 4096;

/** The sentence that asks for the paste; the fixed rule on every paste page is `FIXED.pasteWhere`. */
export const PASTE_ASK = 'Create the key on your phone, at the platform, then paste it here.';


const SCHEMA = `
  CREATE TABLE IF NOT EXISTS paste_tasks (
    paste_id TEXT PRIMARY KEY,
    slot TEXT NOT NULL,
    action_json TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    revision INTEGER NOT NULL,
    requester TEXT NOT NULL,
    reason_json TEXT,
    opened_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed', 'expired'))
  ) STRICT;
  CREATE UNIQUE INDEX IF NOT EXISTS paste_one_pending_per_slot ON paste_tasks (slot) WHERE status = 'pending';
`;

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
}

export interface PasteView {
  readonly paste_id: string;
  readonly revision: number;
  readonly title: string;
  readonly lines: readonly string[];
  /** The adapter's own page for making the key. Never from mission control. */
  readonly platform_link?: string;
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
  /** The pending tasks of the app's queue. */
  pending(cookie: string | undefined): readonly { readonly paste_id: string; readonly title: string }[];
  /** For `POST /p/<id>`: the paste with its proof. */
  submit(id: string, cookie: string | undefined, value: string, proof: ProofBytes): Promise<{ readonly keyref: string }>;
}

const rejected = (code: string): ApiError => new ApiError('rejected', code);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

export function createPaste(deps: PasteDeps): Paste {
  const { db } = deps;
  db.exec(SCHEMA);
  const now = (): number => deps.clock.now();
  const row = (id: string): TaskRow | undefined => db.prepare("SELECT * FROM paste_tasks WHERE paste_id = ? AND status = 'pending'").get(id) as TaskRow | undefined;
  const actionOf = (r: TaskRow): PasteAction => JSON.parse(r.action_json) as PasteAction;

  const sweep = (): void => {
    const stale = db.prepare("SELECT paste_id FROM paste_tasks WHERE status = 'pending' AND expires_at <= ?").all(now()) as unknown as { paste_id: string }[];
    for (const { paste_id } of stale) {
      inTransaction(db, () => void db.prepare("UPDATE paste_tasks SET status = 'expired' WHERE paste_id = ?").run(paste_id));
      deps.events.append('approval.decided', { approval_id: paste_id, decision: 'expired' });
    }
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

  /** The value checks of KBOX-12, in order: the floor, the strict shape, the platform verifier. Names only. */
  async function checkValue(platform: string, value: string): Promise<void> {
    const kit = deps.source.platform(platform);
    const caps = kit?.issuer?.capabilities();
    if (kit === undefined || caps === undefined) throw rejected('unknown_platform');
    if (Buffer.byteLength(value, 'utf8') < PASTE_FLOOR_BYTES) throw rejected('too_short');
    if (!matchesShape(caps.shape, value)) throw rejected('bad_shape');
    if (kit.verifier === undefined) return;
    const bytes = Uint8Array.from(Buffer.from(value, 'utf8'));
    const lent = makeLent('paste:1', () => Uint8Array.from(bytes));
    const verdict = await kit.verifier.verify(lent, { platform }).catch((): 'unreachable' => 'unreachable');
    bytes.fill(0);
    if (verdict !== 'ok') throw rejected(verdict === 'rejected' ? 'verifier_rejected' : 'verifier_unreachable');
  }

  async function execute(action: PasteAction, bytes: Uint8Array): Promise<string> {
    if (action.kind === 'rotate_key') {
      deps.orchestrator.start({ keyref: action.keyref, origin: 'paste', value: bytes });
      return action.keyref;
    }
    const key = newKeyOf(action, deps.source);
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
      const link = deps.source.platform(action.kind === 'add_key' ? action.platform : (deps.meta.snapshot().keys.find((k) => k.keyref === action.keyref)?.platform ?? ''))?.keyPageUrl;
      const nonce = deps.approvers.nonce({ kind: 'decide', approvalId: id, revision: r.revision });
      return {
        paste_id: id,
        revision: r.revision,
        title: page.title,
        lines: [...page.lines, PASTE_ASK, FIXED.pasteWhere],
        ...(link === undefined ? {} : { platform_link: link }),
        phrase: deps.approvers.phraseOf(approverId) ?? '',
        digest_b64: Buffer.from(r.digest_hex, 'hex').toString('base64url'),
        nonce_b64: b64u(nonce),
        expires_at: r.expires_at,
      };
    },

    hasPending(slot) {
      sweep();
      return db.prepare("SELECT 1 AS one FROM paste_tasks WHERE slot = ? AND status = 'pending'").get(slot) !== undefined;
    },

    pending(cookie) {
      viewer(cookie);
      sweep();
      return (db.prepare("SELECT paste_id, action_json FROM paste_tasks WHERE status = 'pending' ORDER BY opened_at, paste_id").all() as unknown as { paste_id: string; action_json: string }[]).map((r) => ({
        paste_id: r.paste_id,
        title: titleOf(JSON.parse(r.action_json) as PasteAction),
      }));
    },

    async submit(id, cookie, value, proof) {
      viewer(cookie);
      const r = pending(id);
      const digest =Uint8Array.from(Buffer.from(r.digest_hex, 'hex'));
      const verdict = deps.approvers.check({ kind: 'decide', approvalId: id, revision: r.revision }, (nonce) => pasteChallenge(id, digest, nonce), proof);
      if (!verdict.ok) throw new ApiError('forbidden', 'proof_refused');
      const action = actionOf(r);
      const platform = action.kind === 'add_key' ? action.platform : (deps.meta.snapshot().keys.find((k) => k.keyref === action.keyref)?.platform ?? '');
      await checkValue(platform, value);
      const bytes = Uint8Array.from(Buffer.from(value, 'utf8'));
      try {
        const keyref = await execute(action, bytes);
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
}

function parsePasteBody(raw: unknown): Parsed<PasteBody> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false };
  const members = raw as Record<string, unknown>;
  const keys = Object.keys(members);
  const value = members['value'];
  if (keys.length !== 2 || typeof value !== 'string' || value.length > VALUE_LIMIT) return { ok: false };
  const proof = parseProof(members['proof']);
  return proof.ok ? { ok: true, value: { value, proof: proof.value } } : { ok: false };
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
      handle: async ({ params, cookie, body }) => ({ status: 201, json: { status: 'stored', ...(await paste.submit(params['id'] ?? '', cookie, body.value, body.proof)) } }),
    }),
    route({ method: 'GET', path: '/paste.html', surface: 'phone', handle: () => file('paste.html', 'text/html; charset=utf-8') }),
    route({ method: 'GET', path: '/paste.js', surface: 'phone', handle: () => file('paste.js', 'text/javascript; charset=utf-8') }),
  ];
}

