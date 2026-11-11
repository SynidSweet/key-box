// KBOX-53, KBOX-9, KBOX-11, KBOX-49, KBOX-20: the proposal and enrol routes of the machine API and the phone routes.
// Every state-changing phone route takes an approver proof in its body; the view cookie alone opens nothing but reads.
import { readFileSync } from 'node:fs';
import type { MetaStore } from '../ports/meta.ts';
import type { PushSubscriptions } from '../ports/push.ts';
import { PROPOSAL_ROUTE_KINDS, ENROL_LABEL, parseAction } from '../pure/actions.ts';
import type { Action } from '../pure/actions.ts';
import { operationChallenge, viewChallenge } from '../pure/challenge.ts';
import type { NoncePurpose, Operation } from '../pure/challenge.ts';
import { ApiError } from '../pure/errors.ts';
import { LABEL, oneOf } from '../pure/schemas.ts';
import type { Parsed } from '../pure/schemas.ts';
import type { Reason } from '../pure/words.ts';
import type { Approvals } from './approvals.ts';
import { VIEW_COOKIE, VIEW_TTL_MS, parseNewApprover, parseProof } from './approvers.ts';
import type { Approvers, ProofBytes, Registration } from './approvers.ts';
import { parsedRoute, route } from './http.ts';
import type { Reply, Route } from './http.ts';
import type { MachineTokens } from './tokens.ts';

export interface ApproveRouteDeps {
  readonly approvals: Approvals;
  readonly approvers: Approvers;
  readonly tokens: MachineTokens;
  readonly meta: MetaStore;
  readonly push: PushSubscriptions;
}

const refused = { ok: false } as const;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const only = (o: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean =>
  required.every((k) => Object.hasOwn(o, k)) && Object.keys(o).every((k) => required.includes(k) || optional.includes(k));

const REASON_TEXT = /^[^\u0000-\u001f\u007f]{0,500}$/u;
function reasonOf(v: unknown): Reason | undefined | false {
  if (v === undefined) return undefined;
  if (!isRecord(v) || !only(v, ['agent', 'text']) || typeof v['agent'] !== 'string' || !LABEL.test(v['agent']) || typeof v['text'] !== 'string' || !REASON_TEXT.test(v['text'])) return false;
  return { agent: v['agent'], text: v['text'] };
}

interface ProposalBody {
  readonly action: Action;
  readonly reason?: Reason;
}

/** `{action, reason?}`. A kind outside the list, one of the three kinds with their own route, or a malformed member is `bad_request`. */
function parseProposal(raw: unknown): Parsed<ProposalBody> {
  if (!isRecord(raw) || !only(raw, ['action'], ['reason'])) return refused;
  const kind = isRecord(raw['action']) ? raw['action']['kind'] : undefined;
  if (typeof kind !== 'string' || !(PROPOSAL_ROUTE_KINDS as readonly string[]).includes(kind)) return refused;
  const action = parseAction(raw['action']);
  const reason = reasonOf(raw['reason']);
  if (!action.ok || reason === false) return refused;
  return { ok: true, value: reason === undefined ? { action: action.value } : { action: action.value, reason } };
}

interface EnrolBody {
  readonly token_sha256: string;
  readonly label: string;
  readonly scope: 'control' | 'relay';
  readonly reason?: Reason;
}

function parseEnrol(raw: unknown): Parsed<EnrolBody> {
  if (!isRecord(raw) || !only(raw, ['token_sha256', 'label', 'scope'], ['reason'])) return refused;
  const { token_sha256, label, scope } = raw;
  if (typeof token_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(token_sha256)) return refused;
  if (typeof label !== 'string' || !ENROL_LABEL.test(label) || (scope !== 'control' && scope !== 'relay')) return refused;
  const reason = reasonOf(raw['reason']);
  if (reason === false) return refused;
  return { ok: true, value: { token_sha256, label, scope, ...(reason === undefined ? {} : { reason }) } };
}

function parseProofBody(raw: unknown): Parsed<{ readonly proof: ProofBytes }> {
  if (!isRecord(raw) || !only(raw, ['proof'])) return refused;
  const proof = parseProof(raw['proof']);
  return proof.ok ? { ok: true, value: { proof: proof.value } } : refused;
}

function parseOperation(raw: unknown): Parsed<{ readonly op: Operation; readonly proof: ProofBytes }> {
  if (!isRecord(raw) || !only(raw, ['op', 'proof']) || !isRecord(raw['op']) || !only(raw['op'], ['kind', 'label'])) return refused;
  const { kind, label } = raw['op'];
  if (typeof label !== 'string' || !LABEL.test(label) || (kind !== 'enrol_window_open' && kind !== 'token_revoke')) return refused;
  if (kind === 'enrol_window_open' && !ENROL_LABEL.test(label)) return refused;
  const proof = parseProof(raw['proof']);
  return proof.ok ? { ok: true, value: { op: { kind, label }, proof: proof.value } } : refused;
}

interface RegistrationBody {
  readonly code: string;
  readonly registration: Registration;
}

/** `{code, approver, proof, phrase, subscription?}`: the typed code goes to root unread; the keys and their proof are checked here. */
function parseRegistration(raw: unknown): Parsed<RegistrationBody> {
  if (!isRecord(raw) || !only(raw, ['code', 'approver', 'proof', 'phrase'], ['subscription'])) return refused;
  const { code, phrase, subscription } = raw;
  if (typeof code !== 'string' || code.length > 200 || typeof phrase !== 'string') return refused;
  const approver = parseNewApprover(raw['approver']);
  const proof = parseProof(raw['proof']);
  if (!approver.ok || !proof.ok) return refused;
  let sub: Registration['subscription'];
  if (subscription !== undefined) {
    if (!isRecord(subscription) || !only(subscription, ['endpoint', 'p256dh', 'auth'])) return refused;
    const { endpoint, p256dh, auth } = subscription;
    if (typeof endpoint !== 'string' || typeof p256dh !== 'string' || typeof auth !== 'string') return refused;
    sub = { endpoint, p256dh, auth };
  }
  return { ok: true, value: { code, registration: { approver: approver.value, proof: proof.value, phrase, ...(sub === undefined ? {} : { subscription: sub }) } } };
}

// --- the app's own files ------------------------------------------------------------------------------------------

const WEB = new URL('../web/', import.meta.url);
const ASSETS: readonly (readonly [path: string, file: string, type: string])[] = [
  ['/', 'index.html', 'text/html; charset=utf-8'],
  ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
  ['/webauthn-client.js', 'webauthn-client.js', 'text/javascript; charset=utf-8'],
  ['/sw.js', 'sw.js', 'text/javascript; charset=utf-8'],
  ['/manifest.webmanifest', 'manifest.webmanifest', 'application/manifest+json'],
  ['/setup.js', 'setup.js', 'text/javascript; charset=utf-8'],
  ['/recover.js', 'recover.js', 'text/javascript; charset=utf-8'],
  ['/register.js', 'register.js', 'text/javascript; charset=utf-8'],
  ['/app.css', 'app.css', 'text/css; charset=utf-8'],
];
const PAGE_HEADERS = { 'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff' };
const file = (name: string, type: string): Reply => ({ raw: { type, bytes: readFileSync(new URL(name, WEB)) }, headers: PAGE_HEADERS });

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

export function approveRoutes(deps: ApproveRouteDeps): Route[] {
  const { approvals, approvers, tokens } = deps;
  const viewerOf = (cookie: string | undefined): string => {
    const id = approvers.viewer(cookie);
    if (id === undefined) throw new ApiError('unauthorized', 'view_session_needed');
    return id;
  };
  const noncePurpose = (p: 'view' | 'op' | 'register'): NoncePurpose => ({ kind: p });

  return [
    // --- machine API ------------------------------------------------------------------------------------------------
    parsedRoute({
      method: 'POST',
      path: '/api/proposals',
      surface: 'api',
      scope: 'control',
      parse: parseProposal,
      handle: ({ body, actor }) => ({ status: 201, json: approvals.propose({ action: body.action, requester: { kind: 'token', label: actor }, ...(body.reason === undefined ? {} : { reason: body.reason }) }) }),
    }),

    parsedRoute({
      method: 'POST',
      path: '/api/enrol',
      surface: 'api',
      open: true,
      parse: parseEnrol,
      handle: ({ body, source }) => {
        const answer = tokens.enrol({ tokenSha256: body.token_sha256, label: body.label, scope: body.scope, source: source.address, ...(body.reason === undefined ? {} : { reason: body.reason }) });
        return answer.status === 'active'
          ? { status: 201, json: { status: 'active', share_public_key_ed25519_b64: deps.meta.snapshot().box.share_public_key_ed25519_b64 } }
          : { status: 202, json: { status: 'pending' } };
      },
    }),

    route({
      method: 'GET',
      path: '/api/enrol/:sha',
      surface: 'api',
      open: true,
      handle: ({ params }) => {
        const sha = params['sha'] ?? '';
        if (!/^[0-9a-f]{64}$/.test(sha)) throw new ApiError('bad_request');
        const status = approvals.enrolStatus(sha);
        if (status === undefined) throw new ApiError('not_found');
        return { json: { status } };
      },
    }),

    // --- phone: pages and nonces --------------------------------------------------------------------------------------
    ...ASSETS.map(([path, name, type]) => route({ method: 'GET', path, surface: 'phone', handle: () => file(name, type) })),

    route({
      method: 'GET',
      path: '/setup',
      surface: 'phone',
      handle: () => {
        if (approvers.count() > 0) throw new ApiError('not_found');
        return file('setup.html', 'text/html; charset=utf-8');
      },
    }),

    route({ method: 'GET', path: '/recover', surface: 'phone', handle: () => file('recover.html', 'text/html; charset=utf-8') }),

    route({
      method: 'GET',
      path: '/app/nonce',
      surface: 'phone',
      query: { purpose: oneOf('view', 'op', 'register') },
      handle: ({ query }) => ({ json: { nonce_b64: b64u(approvers.nonce(noncePurpose(query.purpose))) } }),
    }),

    route({ method: 'GET', path: '/app/push-key', surface: 'phone', handle: () => ({ json: { application_server_key_b64: deps.push.applicationServerKey() } }) }),

    route({ method: 'GET', path: '/healthz', surface: 'phone', handle: () => ({ json: { release: deps.meta.snapshot().box.release } }) }),

    // --- phone: setup and recovery ---------------------------------------------------------------------------------------
    parsedRoute({
      method: 'POST',
      path: '/setup',
      surface: 'phone',
      parse: parseRegistration,
      handle: async ({ body }) => {
        if (approvers.count() > 0) throw new ApiError('not_found');
        return { status: 201, json: { approver_id: await approvers.setup(body.code, body.registration) } };
      },
    }),

    parsedRoute({
      method: 'POST',
      path: '/recover',
      surface: 'phone',
      parse: parseRegistration,
      handle: async ({ body }) => ({ status: 201, json: { approver_id: await approvers.recover(body.code, body.registration) } }),
    }),

    parsedRoute({
      method: 'POST',
      path: '/recover/register',
      surface: 'phone',
      parse: parseRegistration,
      // Spec revision 4: the new device registers first and is held as pending, trusted by nothing; the box then opens the
      // approver_add that names its keys, and the device shows the fingerprint the approving phone will show beside it.
      handle: ({ body }) => {
        const pending = approvers.register(body.code, body.registration);
        approvals.propose({ action: pending.action, requester: { kind: 'box' } });
        return { status: 201, json: { status: 'pending', fingerprint: pending.fingerprint } };
      },
    }),

    // --- phone: the view session (read only) ---------------------------------------------------------------------------
    parsedRoute({
      method: 'POST',
      path: '/app/view',
      surface: 'phone',
      parse: parseProofBody,
      handle: ({ body }) => {
        const cookie = approvers.openView(body.proof, viewChallenge);
        return { json: { status: 'open' }, headers: { 'set-cookie': `${VIEW_COOKIE}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${VIEW_TTL_MS / 1000}` } };
      },
    }),

    // The viewer's own phrase rides with the queue: a view session needs the passkey and the device key (KBOX-9), so the phrase is never shown without both (KBOX-12).
    route({ method: 'GET', path: '/app/queue', surface: 'phone', handle: ({ cookie }) => ({ json: { phrase: approvers.phraseOf(viewerOf(cookie)), approvals: approvals.queue() } }) }),

    route({
      method: 'POST',
      path: '/app/propose-approver-add',
      surface: 'phone',
      // Spec revision 4: an approver in a view session asks for the new device's one-time registration code; the proposal
      // comes later, from the box, once the device has registered its keys.
      handle: ({ cookie }) => ({ status: 201, json: { registration_code: approvers.startAdd(viewerOf(cookie)) } }),
    }),

    // --- phone: decisions and signed operations (assertion plus device signature, never the cookie alone) -----------------
    ...(['approve', 'deny'] as const).map((decision) =>
      parsedRoute({
        method: 'POST',
        path: `/app/${decision}/:id`,
        surface: 'phone',
        parse: parseProofBody,
        handle: async ({ body, params }) => {
          const outcome = await approvals.decide(params['id'] ?? '', decision, body.proof);
          if (outcome.decision === 'denied') return { json: { decision: 'denied' } };
          return { json: { decision: 'approved', result: outcome.execution.result } };
        },
      }),
    ),

    parsedRoute({
      method: 'POST',
      path: '/app/op',
      surface: 'phone',
      parse: parseOperation,
      handle: ({ body }) => {
        const verdict = approvers.check({ kind: 'op' }, (nonce) => operationChallenge(body.op, nonce), body.proof);
        if (!verdict.ok) throw new ApiError('forbidden', 'proof_refused');
        if (body.op.kind === 'enrol_window_open') tokens.openWindow(body.op.label, verdict.approverId);
        else tokens.revoke(body.op.label, verdict.approverId);
        return { json: { status: 'done' } };
      },
    }),
  ];
}

