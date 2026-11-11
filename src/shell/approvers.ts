// KBOX-9, KBOX-49, KBOX-20, KBOX-53: the approvers. One place checks every approver proof (an approval, a denial, a view
// session, a signed operation, a registration): the box's own single-use nonce, the passkey assertion and the device-key
// signature of the SAME approver over the same challenge. A passkey alone (a synced or hybrid passkey on a workstation)
// can do nothing here. Core's approver table changes only after root answers `applied` through the TrustPort.
import { timingSafeEqual } from 'node:crypto';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { ApproverRecord, ApproverStore } from '../ports/private.ts';
import type { Push, PushSubscriptionInput, PushSubscriptions } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import type { ApprovalProof, TrustApprover, TrustPort, TrustRequest } from '../ports/trust.ts';
import { checkNonce, mintNonce, registrationChallenge, relyingParty, verifyProof } from '../pure/challenge.ts';
import type { ApproverKeys, NoncePurpose, ProofParts } from '../pure/challenge.ts';
import { CODE_BYTES, approverFingerprint, codeFromBytes, codeHash, codeMatches } from '../pure/codes.ts';
import { decodeCoseEs256, parseRawPoint } from '../pure/cose.ts';
import { ApiError } from '../pure/errors.ts';
import { approverAddOf } from '../pure/actions.ts';
import type { ApproverAdd } from '../pure/actions.ts';
import { PROPOSAL_TTL_MS } from '../pure/slots.ts';
import type { Parsed } from '../pure/schemas.ts';

/** A page's nonce is good this long (decided here: long enough to read a page, short enough to be useless later). */
export const NONCE_TTL_MS = 10 * 60_000;
/** A read-only view session lasts this long (decided here). */
export const VIEW_TTL_MS = 15 * 60_000;
/** The approver-add registration code: 10 minutes, once (KBOX-53). */
export const REGISTRATION_CODE_TTL_MS = 10 * 60_000;
export const VIEW_COOKIE = '__Host-kb_view';

/** A proof as the phone sends it, decoded: the nonce it was given and both signatures. */
export interface ProofBytes extends ProofParts {
  readonly nonce: Uint8Array;
}

/** A new approver's public keys as the phone sends them at registration. */
export interface NewApprover {
  readonly credentialId: Uint8Array;
  readonly coseKey: Uint8Array;
  readonly devicePublicKey: Uint8Array;
}

const B64U = /^[A-Za-z0-9_-]*$/;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

function bytesMember(o: Record<string, unknown>, name: string, min: number, max: number): Uint8Array | undefined {
  const v = o[name];
  if (typeof v !== 'string' || !B64U.test(v) || v.length > Math.ceil((max * 4) / 3)) return undefined;
  const bytes = Uint8Array.from(Buffer.from(v, 'base64url'));
  return bytes.length >= min && bytes.length <= max && Buffer.from(bytes).toString('base64url') === v ? bytes : undefined;
}

function closedBytes<K extends string>(raw: unknown, spec: Readonly<Record<K, readonly [number, number]>>): Record<K, Uint8Array> | undefined {
  if (!isRecord(raw) || Object.keys(raw).length !== Object.keys(spec).length) return undefined;
  const out: Partial<Record<K, Uint8Array>> = {};
  for (const name of Object.keys(spec) as K[]) {
    const [min, max] = spec[name];
    const b = bytesMember(raw, name, min, max);
    if (b === undefined) return undefined;
    out[name] = b;
  }
  return out as Record<K, Uint8Array>;
}

/** `{nonce, credential_id, authenticator_data, client_data_json, signature, device_signature}`, each base64url, closed. */
export function parseProof(raw: unknown): Parsed<ProofBytes> {
  const p = closedBytes(raw, {
    nonce: [32, 32],
    credential_id: [16, 1023],
    authenticator_data: [37, 1024],
    client_data_json: [1, 4096],
    signature: [8, 80],
    device_signature: [0, 64],
  });
  return p === undefined
    ? { ok: false }
    : { ok: true, value: { nonce: p.nonce, credentialId: p.credential_id, authenticatorData: p.authenticator_data, clientDataJSON: p.client_data_json, signature: p.signature, deviceSignature: p.device_signature } };
}

/** `{credential_id, cose_key, device_public_key}`, each base64url, closed. */
export function parseNewApprover(raw: unknown): Parsed<NewApprover> {
  const p = closedBytes(raw, { credential_id: [16, 1023], cose_key: [77, 77], device_public_key: [65, 65] });
  return p === undefined ? { ok: false } : { ok: true, value: { credentialId: p.credential_id, coseKey: p.cose_key, devicePublicKey: p.device_public_key } };
}

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const fromB64u = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64url'));

/** Every record parsed back into keys; a record whose keys do not parse can never approve and is left out. */
function keysOf(r: ApproverRecord): ApproverKeys | undefined {
  const passkey = decodeCoseEs256(fromB64u(r.coseKey));
  const device = parseRawPoint(fromB64u(r.devicePublicKey));
  return passkey.ok && device.ok ? { approverId: r.approverId, credentialId: fromB64u(r.credentialId), passkey: passkey.key, device: device.key } : undefined;
}

export type ProofCheck = { readonly ok: true; readonly approverId: string; readonly proof: Omit<ApprovalProof, 'approval_id'> } | { readonly ok: false; readonly code: string };

export interface ApproversDeps {
  readonly store: ApproverStore;
  readonly trust: TrustPort;
  readonly push: Push & PushSubscriptions;
  readonly audit: Audit;
  readonly clock: Clock;
  readonly random: Random;
  /** The box's domain: the pages are on `keys.<domain>`. */
  readonly domain: string;
  readonly wordlist: readonly string[];
}

export interface Registration {
  readonly approver: NewApprover;
  readonly proof: ProofBytes;
  /** 1 to 64 printable characters. */
  readonly phrase: string;
  readonly subscription?: PushSubscriptionInput;
}

export interface Approvers {
  count(): number;
  ids(): readonly string[];
  phraseOf(approverId: string): string | undefined;
  /** A fresh single-use nonce for one purpose, as the page render gets it. */
  nonce(purpose: NoncePurpose): Uint8Array;
  /** The one check of an approver proof over `challenge(nonce)`. A nonce that passes the box's own check is spent, whatever follows. */
  check(purpose: NoncePurpose, challenge: (nonce: Uint8Array) => Uint8Array, proof: ProofBytes): ProofCheck;
  /** A read-only view session for a proof over the view challenge; the cookie value. */
  openView(proof: ProofBytes, challenge: (nonce: Uint8Array) => Uint8Array): string;
  /** The approver of a live view session, from the raw Cookie header. */
  viewer(cookie: string | undefined): string | undefined;
  /** First approver (KBOX-49). Root checks the code; core's table changes only after `applied`. */
  setup(code: string, registration: Registration): Promise<string>;
  /** Recovery (KBOX-20): the new approver replaces every other, each told by push first, after root checked the code. */
  recover(code: string, registration: Registration): Promise<string>;
  /**
   * The first step of adding an approver (KBOX-53, spec revision 4): a one-time registration code (12 words, 10 minutes,
   * once) asked for by an approver in a view session. A newer code replaces it; a recovery, or removing the approver who
   * asked for it, ends it.
   */
  startAdd(issuerId: string): string;
  /**
   * The new device's step: the code, its keys and their proof. The device is held as pending, trusted by nothing, until the
   * approver_add naming its keys is approved; a newer registration replaces it and it is dropped with the proposal's expiry.
   * The answer is that approver_add and the fingerprint the new device shows.
   */
  register(code: string, registration: Registration): { readonly action: ApproverAdd; readonly fingerprint: string };
  /** The 6-word fingerprint of the keys an approver_add names: the words both phones show. */
  fingerprint(action: ApproverAdd): string;
  /** True while a registered device waits whose keys are the ones this approver_add names; only then is its page shown. */
  awaits(action: ApproverAdd): boolean;
  /** An approved approver_add: root first, with the pending device's keys, then core's table. */
  add(action: ApproverAdd, approvalProof: ApprovalProof): Promise<'done' | 'no_registration' | 'root_refused'>;
  /** Ends a registration code, or a pending device, that has run out (the approvals sweep calls this). */
  expire(): void;
  /** After an approved `approver_remove`: root first, then core's table. */
  remove(approverId: string, approvalProof: ApprovalProof): Promise<'done' | 'refused'>;
}

export function createApprovers(deps: ApproversDeps): Approvers {
  const rp = relyingParty(deps.domain);
  const nonceKey = deps.random.bytes(32);
  /** Spent nonces, hex, with their issue time; dropped once too old to pass the age check anyway. */
  const spent = new Map<string, number>();
  const views = new Map<string, { readonly approverId: string; readonly until: number }>();
  /** The one outstanding approver-add registration code: its hash, its end and the approver who asked for it. */
  let addCode: { readonly hash: string; readonly until: number; readonly issuer: string } | undefined;
  /** The one new device waiting for its approver_add: trusted by nothing until root applies the approved add. */
  let pendingDevice: { readonly record: ApproverRecord; readonly action: ApproverAdd; readonly until: number; readonly subscription: PushSubscriptionInput | undefined } | undefined;

  const expire = (): void => {
    const now = deps.clock.now();
    if (addCode !== undefined && now > addCode.until) addCode = undefined;
    if (pendingDevice !== undefined && now > pendingDevice.until) pendingDevice = undefined;
  };
  /** A recovery replaces every approver: no code asked for, and no device registered, under the old ones goes on. */
  const cancelAdds = (): void => {
    addCode = undefined;
    pendingDevice = undefined;
  };

  const records = (): readonly ApproverRecord[] => deps.store.listApprovers();
  const prune = (now: number): void => {
    for (const [n, at] of spent) if (now - at > NONCE_TTL_MS) spent.delete(n);
    for (const [c, v] of views) if (v.until <= now) views.delete(c);
  };
  const refuse = (purpose: NoncePurpose, code: string): ProofCheck => {
    deps.audit.append({ action: 'proof.refused', subject: 'approver', at: deps.clock.now(), detail: { purpose: purpose.kind, code } });
    return { ok: false, code };
  };

  const check = (purpose: NoncePurpose, challenge: (nonce: Uint8Array) => Uint8Array, proof: ProofBytes): ProofCheck => {
    const now = deps.clock.now();
    prune(now);
    const fresh = checkNonce(nonceKey, proof.nonce, purpose, now, NONCE_TTL_MS);
    if (!fresh.ok) return refuse(purpose, fresh.code);
    const id = Buffer.from(proof.nonce).toString('hex');
    if (spent.has(id)) return refuse(purpose, 'nonce_used');
    spent.set(id, fresh.issuedAt);
    const record = records().find((r) => {
      const a = fromB64u(r.credentialId);
      return a.length === proof.credentialId.length && timingSafeEqual(a, proof.credentialId);
    });
    const keys = record === undefined ? undefined : keysOf(record);
    if (record === undefined || keys === undefined) return refuse(purpose, 'unknown_approver');
    const verdict = verifyProof(keys, proof, { challenge: challenge(proof.nonce), origin: rp.origin, rpId: rp.rpId, storedCounter: record.signCount });
    if (!verdict.ok) return refuse(purpose, verdict.code);
    if (verdict.counter !== record.signCount) deps.store.setSignCount(record.approverId, verdict.counter);
    return {
      ok: true,
      approverId: record.approverId,
      proof: {
        approver_id: record.approverId,
        nonce_b64: b64u(proof.nonce),
        credential_id_b64: b64u(proof.credentialId),
        authenticator_data_b64: b64u(proof.authenticatorData),
        client_data_json_b64: b64u(proof.clientDataJSON),
        signature_b64: b64u(proof.signature),
        device_signature_b64: b64u(proof.deviceSignature),
      },
    };
  };

  /** A new approver proves it holds both keys it registers, over the registration challenge with a box nonce. */
  const admit = (reg: Registration): ApproverRecord => {
    const now = deps.clock.now();
    prune(now);
    const purpose = { kind: 'register' } as const;
    const fresh = checkNonce(nonceKey, reg.proof.nonce, purpose, now, NONCE_TTL_MS);
    const id = Buffer.from(reg.proof.nonce).toString('hex');
    if (!fresh.ok || spent.has(id)) {
      refuse(purpose, fresh.ok ? 'nonce_used' : fresh.code);
      throw new ApiError('forbidden', 'proof_refused');
    }
    spent.set(id, fresh.issuedAt);
    const passkey = decodeCoseEs256(reg.approver.coseKey);
    const device = parseRawPoint(reg.approver.devicePublicKey);
    if (!passkey.ok || !device.ok) throw new ApiError('bad_request');
    if (!/^[\x20-\x7e]{1,64}$/.test(reg.phrase)) throw new ApiError('bad_request');
    const approverId = `ap-${b64u(deps.random.bytes(12))}`;
    const keys: ApproverKeys = { approverId, credentialId: reg.approver.credentialId, passkey: passkey.key, device: device.key };
    const verdict = verifyProof(keys, reg.proof, { challenge: registrationChallenge(reg.proof.nonce), origin: rp.origin, rpId: rp.rpId, storedCounter: 0 });
    if (!verdict.ok) {
      refuse(purpose, verdict.code);
      throw new ApiError('forbidden', 'proof_refused');
    }
    return { approverId, credentialId: b64u(reg.approver.credentialId), coseKey: b64u(reg.approver.coseKey), devicePublicKey: b64u(reg.approver.devicePublicKey), phrase: reg.phrase, signCount: verdict.counter };
  };

  const trusted = (r: ApproverRecord): TrustApprover => ({ id: r.approverId, cose_b64: r.coseKey, device_pub_b64: r.devicePublicKey });

  const askRoot = async (request: TrustRequest): Promise<void> => {
    const answer = await deps.trust.apply(request);
    if (answer.result === 'applied') return;
    deps.audit.append({ action: 'trust.refused', subject: 'trust', at: deps.clock.now(), detail: { change: request.change, code: /^[a-z][a-z0-9_]{0,63}$/.test(answer.code) ? answer.code : 'refused' } });
    throw new ApiError('forbidden', 'root_refused');
  };

  const subscribe = (subscription: PushSubscriptionInput | undefined): void => {
    if (subscription !== undefined && !deps.push.subscribe(subscription).ok) throw new ApiError('rejected', 'bad_subscription');
  };
  const fingerprint = (action: ApproverAdd): string => approverFingerprint(action.cose_sha256, action.device_sha256, deps.wordlist);
  const awaits = (action: ApproverAdd): boolean => {
    expire();
    return pendingDevice !== undefined && pendingDevice.action.cose_sha256 === action.cose_sha256 && pendingDevice.action.device_sha256 === action.device_sha256;
  };

  return {
    count: () => records().length,
    ids: () => records().map((r) => r.approverId),
    phraseOf: (approverId) => records().find((r) => r.approverId === approverId)?.phrase,

    nonce: (purpose) => mintNonce(nonceKey, purpose, deps.clock.now(), deps.random.bytes(8)),

    check,

    openView(proof, challenge) {
      const verdict = check({ kind: 'view' }, challenge, proof);
      if (!verdict.ok) throw new ApiError('forbidden', 'proof_refused');
      const cookie = b64u(deps.random.bytes(32));
      views.set(cookie, { approverId: verdict.approverId, until: deps.clock.now() + VIEW_TTL_MS });
      deps.audit.append({ action: 'view.opened', subject: verdict.approverId, actor: verdict.approverId, at: deps.clock.now() });
      return cookie;
    },

    viewer(cookie) {
      prune(deps.clock.now());
      const value = (cookie ?? '')
        .split(';')
        .map((c) => c.trim())
        .find((c) => c.startsWith(`${VIEW_COOKIE}=`))
        ?.slice(VIEW_COOKIE.length + 1);
      if (value === undefined) return undefined;
      const view = views.get(value);
      return view !== undefined && records().some((r) => r.approverId === view.approverId) ? view.approverId : undefined;
    },

    async setup(code, reg) {
      if (records().length > 0) throw new ApiError('not_found');
      const record = admit(reg);
      await askRoot({ kind: 'trust', change: 'setup', code, domain: deps.domain, approvers: [trusted(record)] });
      deps.store.putApprover(record);
      subscribe(reg.subscription);
      deps.audit.append({ action: 'approver.registered', subject: record.approverId, at: deps.clock.now(), detail: { via: 'setup' } });
      return record.approverId;
    },

    async recover(code, reg) {
      const record = admit(reg);
      await askRoot({ kind: 'trust', change: 'recovery', code, approvers: [trusted(record)] });
      const others = records().filter((r) => r.approverId !== record.approverId);
      deps.push.send({ title: 'Recovery: every other approver of the key box is being removed', kind: 'recovery' });
      deps.store.replaceApprovers([record]);
      cancelAdds();
      subscribe(reg.subscription);
      for (const r of others) deps.audit.append({ action: 'approver.removed', subject: r.approverId, at: deps.clock.now(), detail: { via: 'recovery' } });
      deps.audit.append({ action: 'recovery.used', subject: record.approverId, at: deps.clock.now() });
      deps.audit.append({ action: 'approver.registered', subject: record.approverId, at: deps.clock.now(), detail: { via: 'recovery' } });
      return record.approverId;
    },

    startAdd(issuerId) {
      const code = codeFromBytes(deps.random.bytes(CODE_BYTES), deps.wordlist);
      addCode = { hash: codeHash(code), until: deps.clock.now() + REGISTRATION_CODE_TTL_MS, issuer: issuerId };
      return code;
    },

    register(code, reg) {
      expire();
      const issued = addCode;
      if (issued === undefined || !codeMatches(code, issued.hash, deps.wordlist)) throw new ApiError('forbidden', 'code_refused');
      addCode = undefined; // spent by the attempt, whatever follows
      const record = admit(reg);
      const action = approverAddOf(fromB64u(record.coseKey), fromB64u(record.devicePublicKey));
      pendingDevice = { record, action, until: deps.clock.now() + PROPOSAL_TTL_MS, subscription: reg.subscription };
      return { action, fingerprint: fingerprint(action) };
    },

    fingerprint,

    awaits,

    expire,

    async add(action, approvalProof) {
      const device = awaits(action) ? pendingDevice : undefined;
      if (device === undefined) return 'no_registration';
      pendingDevice = undefined;
      try {
        await askRoot({ kind: 'trust', change: 'approver_add', approval: approvalProof, approver: trusted(device.record) });
      } catch (error) {
        if (error instanceof ApiError) return 'root_refused';
        throw error;
      }
      deps.store.putApprover(device.record);
      subscribe(device.subscription);
      deps.audit.append({ action: 'approver.registered', subject: device.record.approverId, at: deps.clock.now(), detail: { via: 'approver_add' } });
      return 'done';
    },

    async remove(approverId, approvalProof) {
      if (!records().some((r) => r.approverId === approverId) || records().length <= 1) return 'refused';
      try {
        await askRoot({ kind: 'trust', change: 'approver_remove', approval: approvalProof, approver_id: approverId });
      } catch (error) {
        if (error instanceof ApiError) return 'refused';
        throw error;
      }
      deps.store.removeApprover(approverId);
      if (addCode?.issuer === approverId) addCode = undefined;
      deps.audit.append({ action: 'approver.removed', subject: approverId, at: deps.clock.now(), detail: { via: 'approver_remove' } });
      return 'done';
    },
  };
}
