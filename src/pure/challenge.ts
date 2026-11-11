// KBOX-9: what the approver signs, and the check that an approver proof is the passkey AND the device key of the same
// approver over the same challenge. The one home of every challenge the box builds (approval, denial, view, operation,
// paste, registration) and of the single-use nonces the pages carry. core and kb-install import this file; it has no state.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from './canonical.ts';
import type { Es256PublicKey } from './cose.ts';
import { verifyAssertion, verifyEs256Raw } from './webauthn.ts';
import type { AssertionExpect, AssertionFailure } from './webauthn.ts';

export const NONCE_BYTES = 32;
const DIGEST_BYTES = 32;

const sha256 = (...parts: (string | Uint8Array)[]): Uint8Array => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return Uint8Array.from(h.digest());
};

const fixed = (bytes: Uint8Array, n: number, what: string): Uint8Array => {
  if (bytes.length !== n) throw new RangeError(`${what} is ${n} bytes`);
  return bytes;
};

/** SHA-256 of the canonical action JSON (RFC 8785 restricted to integers). Throws for a value without a canonical form. */
export function actionDigest(action: object): Uint8Array {
  return sha256(canonicalJson(action));
}

/** `SHA-256("kbox-v1" || approvalId || actionDigest || nonce)`. */
export function approvalChallenge(approvalId: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1', approvalId, fixed(digest, DIGEST_BYTES, 'the action digest'), fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** `SHA-256("kbox-v1-deny" || approvalId || actionDigest || nonce)`: a denial signs this, so an approval proof cannot deny and a denial proof cannot approve. */
export function denialChallenge(approvalId: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1-deny', approvalId, fixed(digest, DIGEST_BYTES, 'the action digest'), fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** `SHA-256("kbox-v1-view" || nonce)`. */
export function viewChallenge(nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1-view', fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** The signed operations: a phone action that changes state at once and is not the approval of a stored action. */
export type Operation = { readonly kind: 'enrol_window_open'; readonly label: string } | { readonly kind: 'token_revoke'; readonly label: string };

/** `SHA-256("kbox-v1-op" || SHA-256(canonical operation JSON) || nonce)`. */
export function operationChallenge(op: Operation, nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1-op', sha256(canonicalJson(op)), fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** `SHA-256("kbox-v1-paste" || pasteId || actionDigest || nonce)` (KBOX-12). */
export function pasteChallenge(pasteId: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1-paste', pasteId, fixed(digest, DIGEST_BYTES, 'the action digest'), fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** `SHA-256("kbox-v1-register" || nonce)`: a new approver proves it holds both keys it registers (setup, recovery; decided here). */
export function registrationChallenge(nonce: Uint8Array): Uint8Array {
  return sha256('kbox-v1-register', fixed(nonce, NONCE_BYTES, 'the nonce'));
}

/** The relying party of a box: the phone pages live on `keys.<domain>`. */
export function relyingParty(domain: string): { readonly rpId: string; readonly origin: string } {
  return { rpId: `keys.${domain}`, origin: `https://keys.${domain}` };
}

// --- the approver proof --------------------------------------------------------------------------------------------

/** An approver: a passkey and a device key registered together. */
export interface ApproverKeys {
  readonly approverId: string;
  readonly credentialId: Uint8Array;
  readonly passkey: Es256PublicKey;
  readonly device: Es256PublicKey;
}

export interface ProofParts {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  readonly signature: Uint8Array;
  /** Raw 64-byte r||s over the challenge bytes. */
  readonly deviceSignature: Uint8Array;
}

export type ProofFailure = AssertionFailure | 'credential' | 'device_signature';
export type ProofVerdict = { readonly ok: true; readonly counter: number } | { readonly ok: false; readonly code: ProofFailure };

/** Both signatures, over `expect.challenge`, by the passkey and the device key of the one approver given. */
export function verifyProof(approver: ApproverKeys, proof: ProofParts, expect: AssertionExpect): ProofVerdict {
  if (!sameBytes(approver.credentialId, proof.credentialId)) return { ok: false, code: 'credential' };
  const passkey = verifyAssertion(approver.passkey, proof, expect);
  if (!passkey.ok) return passkey;
  if (!verifyEs256Raw(approver.device, fixed(expect.challenge, DIGEST_BYTES, 'the challenge'), proof.deviceSignature)) return { ok: false, code: 'device_signature' };
  return passkey;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);

// --- single-use nonces ----------------------------------------------------------------------------------------------

/**
 * What a nonce was issued for. An approval nonce names the approval and its revision, so a replaced action (revision + 1)
 * voids every nonce issued before it.
 */
export type NoncePurpose =
  | { readonly kind: 'view' }
  | { readonly kind: 'op' }
  | { readonly kind: 'register' }
  | { readonly kind: 'decide'; readonly approvalId: string; readonly revision: number };

const purposeTag = (p: NoncePurpose): string => (p.kind === 'decide' ? `decide\u0000${p.approvalId}\u0000${p.revision}` : p.kind);

const NONCE_TAG = 16;
const NONCE_RANDOM = 8;

/**
 * A nonce is `issuedAt (8 bytes) || random (8) || HMAC-SHA-256(key, purpose, issuedAt, random)[0..16]`, so the box keeps no
 * state per page render: it can tell its own nonces, their purpose and their age. "Used once" is the caller's set of spent
 * nonces, kept until they are too old to pass anyway.
 */
export function mintNonce(key: Uint8Array, purpose: NoncePurpose, issuedAt: number, random: Uint8Array): Uint8Array {
  const head = new Uint8Array(8 + NONCE_RANDOM);
  new DataView(head.buffer).setBigUint64(0, BigInt(issuedAt));
  head.set(fixed(random, NONCE_RANDOM, 'the nonce randomness'), 8);
  const tag = createHmac('sha256', key).update(purposeTag(purpose)).update(head).digest().subarray(0, NONCE_TAG);
  return Uint8Array.from([...head, ...tag]);
}

export type NonceCheck = { readonly ok: true; readonly issuedAt: number } | { readonly ok: false; readonly code: 'nonce_foreign' | 'nonce_expired' };

/** The nonce is the box's own, for this purpose, and younger than `ttlMs`. */
export function checkNonce(key: Uint8Array, nonce: Uint8Array, purpose: NoncePurpose, now: number, ttlMs: number): NonceCheck {
  if (nonce.length !== NONCE_BYTES) return { ok: false, code: 'nonce_foreign' };
  const head = nonce.subarray(0, 8 + NONCE_RANDOM);
  const issuedAt = Number(new DataView(nonce.buffer, nonce.byteOffset, 8).getBigUint64(0));
  const tag = createHmac('sha256', key).update(purposeTag(purpose)).update(head).digest().subarray(0, NONCE_TAG);
  if (!timingSafeEqual(tag, nonce.subarray(8 + NONCE_RANDOM))) return { ok: false, code: 'nonce_foreign' };
  if (issuedAt > now || now - issuedAt > ttlMs) return { ok: false, code: 'nonce_expired' };
  return { ok: true, issuedAt };
}
