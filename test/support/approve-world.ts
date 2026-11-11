// A started core with its approval half on a unix socket in a temp directory: the real parts main-core wires, a TimedClock,
// the fake TrustPort over root's real code store, a recording push, and soft approvers registered through the real setup and
// approver-add flows. It lives outside test/kit because it reaches the verifier, which the kit must not (KBOX-35).
// Run directly, this file does nothing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { softApprover } from '../kit/approver.ts';
import type { ProofParts, Quirks, SoftApprover } from '../kit/approver.ts';
import { TimedClock, drive, seededRandom, tempDir } from '../kit/index.ts';
import type { DriveReply } from '../kit/index.ts';
import { FakePush } from '../fakes/push.ts';
import { FakeTrust } from '../fakes/trust.ts';
import type { TokenScope } from '../../src/ports/meta.ts';
import type { Action } from '../../src/pure/actions.ts';
import { parseWordlist } from '../../src/pure/codes.ts';
import { hashToken, newToken } from '../../src/pure/tokens.ts';
import { openApproveCore } from '../../src/shell/approve-core.ts';
import type { ApproveCore } from '../../src/shell/approve-core.ts';
import type { QueueItem } from '../../src/shell/approvals.ts';
import { createCodeRoot } from '../../src/shell/console.ts';
import type { CodeRoot } from '../../src/shell/console.ts';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { createApiServer } from '../../src/shell/http.ts';
import { openPrivateDatabase } from '../../src/shell/private-db.ts';
import type { PrivateStore } from '../../src/ports/private.ts';
import type { Route } from '../../src/shell/http.ts';

export const DOMAIN = 'box.example';
export const RP = { rpId: `keys.${DOMAIN}`, origin: `https://keys.${DOMAIN}` } as const;
export const WORDLIST = parseWordlist(readFileSync(new URL('../../src/data/wordlist.txt', import.meta.url), 'utf8'));
const BOOT = 'b0070000-0000-4000-8000-000000000001';

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const sha = (...parts: (string | Uint8Array)[]): Uint8Array => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return Uint8Array.from(h.digest());
};

/** The challenges, written again here from the spec text (KBOX-9), so the world is an independent oracle of the box's own. */
export const challenges = {
  approval: (id: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array => sha('kbox-v1', id, digest, nonce),
  denial: (id: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array => sha('kbox-v1-deny', id, digest, nonce),
  view: (nonce: Uint8Array): Uint8Array => sha('kbox-v1-view', nonce),
  op: (op: { kind: string; label: string }, nonce: Uint8Array): Uint8Array => sha('kbox-v1-op', sha(`{"kind":${JSON.stringify(op.kind)},"label":${JSON.stringify(op.label)}}`), nonce),
  register: (nonce: Uint8Array): Uint8Array => sha('kbox-v1-register', nonce),
};

export interface WireProof {
  readonly nonce: string;
  readonly credential_id: string;
  readonly authenticator_data: string;
  readonly client_data_json: string;
  readonly signature: string;
  readonly device_signature: string;
}

export function wire(nonce: Uint8Array, parts: ProofParts): WireProof {
  return {
    nonce: b64u(nonce),
    credential_id: b64u(parts.credentialId),
    authenticator_data: b64u(parts.authenticatorData),
    client_data_json: b64u(parts.clientDataJSON),
    signature: b64u(parts.signature),
    device_signature: b64u(parts.deviceSignature),
  };
}

export const newApproverBody = (a: SoftApprover) => ({ credential_id: b64u(a.credentialId), cose_key: b64u(a.coseKey), device_public_key: b64u(a.devicePublicKey) });

export interface CallOptions {
  readonly method?: string;
  readonly json?: unknown;
  readonly token?: string;
  readonly cookie?: string;
  readonly ip?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface World {
  readonly parts: CoreParts;
  readonly core: ApproveCore;
  readonly priv: PrivateStore;
  readonly clock: TimedClock;
  readonly push: FakePush;
  readonly trust: FakeTrust;
  readonly console: string[];
  /** The fixed codes the HTTP frame wrote to the journal. */
  readonly journal: string[];
  readonly codes: CodeRoot;
  readonly stateDir: string;
  readonly owner: SoftApprover;
  readonly ownerId: string;
  call(path: string, options?: CallOptions): Promise<DriveReply>;
  /** Enrols a machine directly in the store and returns its token. */
  token(label: string, scope: TokenScope): string;
  /** A nonce from the phone route. */
  nonce(purpose: 'view' | 'op' | 'register'): Promise<Uint8Array>;
  /** Opens a view session for an approver; the Cookie header value. */
  view(approver?: SoftApprover): Promise<string>;
  /** The queue as the phone sees it. */
  queue(approver?: SoftApprover): Promise<readonly QueueItem[]>;
  /** A proof for one queue item, as the phone would build it; `quirks` plants one fault under a valid signature. */
  proofFor(item: QueueItem, approver?: SoftApprover, quirks?: Quirks): WireProof;
  /** With `decision` the proof signs that decision's challenge (approval or denial); the route of the other decision refuses it. */
  proofFor(item: QueueItem, approver: SoftApprover | undefined, quirks: Quirks | undefined, decision: 'approve' | 'deny'): WireProof;
  decide(id: string, decision: 'approve' | 'deny', proof: WireProof): Promise<DriveReply>;
  // `decide('deny', proof)` signs a proof made by `proofFor` with no decision, handed over unchanged, again over the denial
  // challenge (the phone signs when the button is pressed); any other proof goes as it is, so a test that wants the wrong
  // challenge posts with `call`.
  /** Proposes through the service (no route), as a token, the box or an enrol would. */
  propose(action: Action, requester?: string | 'box'): ReturnType<ApproveCore['approvals']['propose']>;
  /** Adds a second approver through the real approver_add approval and the registration step. */
  addApprover(): Promise<{ readonly approver: SoftApprover; readonly approverId: string }>;
  /** Writes a fresh recovery code for this boot through root's code store and returns it. */
  recoveryCode(): string;
}

export interface WorldOptions {
  readonly seed?: number;
  readonly vet?: (action: Action) => 'ok' | 'rejected';
  /** Leave the box without an approver (setup tests). */
  readonly noSetup?: boolean;
  /** Extra routes beside the box's own (a relay-scope probe route, say). */
  readonly routes?: readonly Route[];
  /** Executors of kinds other units own (the update unit's install_update). */
  readonly executors?: Parameters<typeof openApproveCore>[0]['executors'];
  /** install_update: what the page counts against the running release (the updater's count). */
  readonly updateChanges?: Parameters<typeof openApproveCore>[0]['updateChanges'];
  /** Root's code directory and boot id, when a journey shares them with a real kb-code process. */
  readonly codes?: { readonly dir: string; readonly bootId: () => string };
}

export async function approveWorld(t: TestContext, options: WorldOptions = {}): Promise<World> {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(options.seed ?? 21);
  const parts = openCore({ stateDir, clock, scheduler: clock, random });
  const priv = openPrivateDatabase(join(stateDir, 'private.db'));
  const push = new FakePush();
  const consoleLines: string[] = [];
  const journalLines: string[] = [];
  const codes = createCodeRoot({ dir: options.codes?.dir ?? join(dir, 'codes'), sink: (line) => void consoleLines.push(line), random, clock, wordlist: WORDLIST });
  const trust = new FakeTrust(codes, options.codes?.bootId ?? (() => BOOT));
  const core = openApproveCore({ parts, approverStore: priv, trust, push, clock, random, domain: DOMAIN, wordlist: WORDLIST, vet: options.vet ?? (() => 'ok'), ...(options.executors === undefined ? {} : { executors: options.executors }), ...(options.updateChanges === undefined ? {} : { updateChanges: options.updateChanges }) });
  const server = createApiServer({ routes: [...parts.routes, ...core.routes, ...(options.routes ?? [])], tokens: core.tokens.tokenStore, audit: parts.audit, random, clock, journal: (code) => void journalLines.push(code) });
  const socket = join(dir, 'http.sock');
  await server.listen(socket);
  t.after(async () => {
    await server.stop();
    priv.close();
    parts.close();
  });
  const driver = drive(socket);
  const lastCode = (): string => /([a-z]+(?: [a-z]+){11})/.exec(consoleLines.at(-1) ?? '')?.[1] ?? '';

  const call: World['call'] = (path, o = {}) => {
    const headers: Record<string, string> = { 'x-kb-client-ip': o.ip ?? '203.0.113.9', ...o.headers };
    if (o.token !== undefined) headers['authorization'] = `Bearer ${o.token}`;
    if (o.cookie !== undefined) headers['cookie'] = o.cookie;
    if (o.json !== undefined) headers['content-type'] = 'application/json';
    return driver.request({ path, method: o.method ?? (o.json === undefined ? 'GET' : 'POST'), headers, ...(o.json === undefined ? {} : { body: JSON.stringify(o.json) }) });
  };
  const nonce: World['nonce'] = async (purpose) => {
    const reply = await call(`/app/nonce?purpose=${purpose}`);
    assert.equal(reply.status, 200, reply.body);
    return Uint8Array.from(Buffer.from((reply.json() as { nonce_b64: string }).nonce_b64, 'base64url'));
  };

  const register = async (path: '/setup' | '/recover' | '/recover/register', code: string, approver: SoftApprover): Promise<DriveReply> => {
    const n = await nonce('register');
    return call(path, { json: { code, approver: newApproverBody(approver), proof: wire(n, approver.prove(challenges.register(n), RP)), phrase: 'blue kettle' } });
  };

  const owner = softApprover();
  let ownerId = '';
  if (options.noSetup !== true) {
    codes.writeSetupCode(false);
    const reply = await register('/setup', lastCode(), owner);
    assert.equal(reply.status, 201, reply.body);
    ownerId = (reply.json() as { approver_id: string }).approver_id;
  }

  const view: World['view'] = async (approver = owner) => {
    const n = await nonce('view');
    const reply = await call('/app/view', { json: { proof: wire(n, approver.prove(challenges.view(n), RP)) } });
    assert.equal(reply.status, 200, reply.body);
    return (reply.headers['set-cookie'] ?? '').split(';')[0] ?? '';
  };
  const queue: World['queue'] = async (approver = owner) => {
    const reply = await call('/app/queue', { cookie: await view(approver) });
    assert.equal(reply.status, 200, reply.body);
    return (reply.json() as { approvals: QueueItem[] }).approvals;
  };
  const proofFor: World['proofFor'] = (item, approver = owner, quirks) => {
    const n = Uint8Array.from(Buffer.from(item.nonce_b64, 'base64url'));
    const digest = Uint8Array.from(Buffer.from(item.digest_b64, 'base64url'));
    return wire(n, approver.prove(challenges.approval(item.approval_id, digest, n), RP, quirks));
  };
  const decide: World['decide'] = (id, decision, proof) => call(`/app/${decision}/${id}`, { json: { proof } });
  const requesterOf = (r: string): Parameters<ApproveCore['approvals']['propose']>[0]['requester'] =>
    r === 'box' ? { kind: 'box' } : r.startsWith('enrol:') ? { kind: 'enrol', address: r.slice(6) } : { kind: 'token', label: r };

  const world: World = {
    parts,
    core,
    priv,
    clock,
    push,
    trust,
    console: consoleLines,
    journal: journalLines,
    stateDir,
    owner,
    codes,
    get ownerId() {
      return ownerId;
    },
    call,
    token(label, scope) {
      const token = newToken(random);
      parts.meta.addMachine({ label, scope, tokenSha256: hashToken(token), enrolledAt: clock.now() });
      return token;
    },
    nonce,
    view,
    queue,
    proofFor,
    decide,
    propose: (action, requester = 'ctl-1') => core.approvals.propose({ action, requester: requesterOf(requester) }),
    // FORCED-FLIP: as of the spec revision 4 the new phone registers first (pending, trusted by nothing) and the box then
    // proposes the approver_add that names its keys; the owner approves it after comparing the fingerprint.
    async addApprover() {
      const cookie = await view();
      // FORCED-FLIP: as of the spec revision 4 the route answers the code; the add is approved after the registration, below.
      const asked = await call('/app/propose-approver-add', { method: 'POST', cookie });
      assert.equal(asked.status, 201, asked.body);
      const code = (asked.json() as { registration_code: string }).registration_code;
      const approver = softApprover();
      const reply = await register('/recover/register', code, approver);
      assert.equal(reply.status, 201, reply.body);
      const item = (await queue()).find((q) => q.kind === 'approver_add');
      assert.ok(item);
      const before = core.approvers.ids();
      const approved = await decide(item.approval_id, 'approve', proofFor(item));
      assert.equal(approved.status, 200, approved.body);
      assert.equal((approved.json() as { result: string }).result, 'done', approved.body);
      const approverId = core.approvers.ids().find((id) => !before.includes(id));
      assert.ok(approverId !== undefined);
      return { approver, approverId };
    },
    recoveryCode() {
      codes.consume('recovery');
      codes.writeRecoveryCode(BOOT);
      return lastCode();
    },
  };
  // The decision is in the challenge (KBOX-9): proofs for a denial sign the denial challenge. Added over the world above so the
  // approval-challenge helpers stay as they were.
  const approvalProofs = new Map<string, { readonly made: WireProof; readonly redo: () => WireProof }>();
  const proofForDecision = (item: QueueItem, approver: SoftApprover = owner, quirks?: Quirks, decision: 'approve' | 'deny' = 'approve'): WireProof => {
    if (decision === 'approve') {
      const made = proofFor(item, approver, quirks);
      approvalProofs.set(made.nonce, { made, redo: () => proofForDecision(item, approver, quirks, 'deny') });
      return made;
    }
    const n = Uint8Array.from(Buffer.from(item.nonce_b64, 'base64url'));
    const digest = Uint8Array.from(Buffer.from(item.digest_b64, 'base64url'));
    return wire(n, approver.prove(challenges.denial(item.approval_id, digest, n), RP, quirks));
  };
  const decideByDecision: World['decide'] = (id, decision, proof) => {
    const own = approvalProofs.get(proof.nonce);
    return decide(id, decision, decision === 'deny' && own !== undefined && JSON.stringify(own.made) === JSON.stringify(proof) ? own.redo() : proof);
  };
  Object.assign(world, { proofFor: proofForDecision, decide: decideByDecision });
  return world;
}

/** Registers through a phone route as a new approver (setup, recovery or the approver-add step). */
export async function registerAt(w: World, path: '/setup' | '/recover' | '/recover/register', code: string, approver: SoftApprover, phrase = 'blue kettle'): Promise<DriveReply> {
  const n = await w.nonce('register');
  return w.call(path, { json: { code, approver: newApproverBody(approver), proof: wire(n, approver.prove(challenges.register(n), RP)), phrase } });
}

export const setupCodeFrom = (lines: readonly string[]): string => /([a-z]+(?: [a-z]+){11})/.exec(lines.at(-1) ?? '')?.[1] ?? '';
