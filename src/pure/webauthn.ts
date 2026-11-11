// KBOX-9: WebAuthn assertion verification, by hand over node:crypto primitives. The one verifier: core and kb-install both
// import it. Every refusal is a fixed code; nothing of the input is ever quoted.
import { createHash, timingSafeEqual, verify } from 'node:crypto';
import { keyObject } from './cose.ts';
import type { Es256PublicKey } from './cose.ts';

export interface Assertion {
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  /** DER ECDSA, as the authenticator gives it. */
  readonly signature: Uint8Array;
}

export interface AssertionExpect {
  /** The 32 challenge bytes the box built. */
  readonly challenge: Uint8Array;
  /** Exactly `https://keys.<domain>`. */
  readonly origin: string;
  /** Exactly `keys.<domain>`. */
  readonly rpId: string;
  /** The approver's last signature counter; 0 when it never sent one. */
  readonly storedCounter: number;
}

export type AssertionFailure =
  | 'malformed'
  | 'type'
  | 'challenge'
  | 'origin'
  | 'cross_origin'
  | 'rp_id'
  | 'user_presence'
  | 'user_verification'
  | 'counter'
  | 'signature';

export type AssertionVerdict = { readonly ok: true; readonly counter: number } | { readonly ok: false; readonly code: AssertionFailure };

const AUTH_DATA_BYTES = 37;
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
/** Attested credential data and extension data: neither belongs in an assertion the box accepts. */
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;
const COORD = 32;

const fail = (code: AssertionFailure): AssertionVerdict => ({ ok: false, code });

const sha256 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);

interface ClientData {
  readonly type: string;
  readonly challenge: string;
  readonly origin: string;
  readonly crossOrigin: unknown;
  readonly topOrigin: unknown;
}

function clientData(bytes: Uint8Array): ClientData | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
  const o = parsed as Record<string, unknown>;
  const { type, challenge, origin } = o;
  if (typeof type !== 'string' || typeof challenge !== 'string' || typeof origin !== 'string') return undefined;
  return { type, challenge, origin, crossOrigin: o['crossOrigin'], topOrigin: o['topOrigin'] };
}

/**
 * Checks a WebAuthn `get` assertion: clientDataJSON type, challenge, origin and no cross-origin use; authenticator data rpIdHash,
 * UP and UV; the signature counter (a counter that does not grow is refused unless both are 0, which a synced passkey sends);
 * the ES256 signature over authenticatorData || SHA-256(clientDataJSON).
 */
export function verifyAssertion(key: Es256PublicKey, assertion: Assertion, expect: AssertionExpect): AssertionVerdict {
  const data = assertion.authenticatorData;
  if (data.length !== AUTH_DATA_BYTES) return fail('malformed');
  const flags = data[32] ?? 0;
  if ((flags & (FLAG_AT | FLAG_ED)) !== 0) return fail('malformed');
  const client = clientData(assertion.clientDataJSON);
  if (client === undefined) return fail('malformed');
  if (client.type !== 'webauthn.get') return fail('type');
  if (client.challenge !== Buffer.from(expect.challenge).toString('base64url')) return fail('challenge');
  if (client.origin !== expect.origin) return fail('origin');
  if (client.crossOrigin !== undefined && client.crossOrigin !== false) return fail('cross_origin');
  if (client.topOrigin !== undefined) return fail('cross_origin');
  if (!same(data.subarray(0, 32), sha256(Buffer.from(expect.rpId, 'utf8')))) return fail('rp_id');
  if ((flags & FLAG_UP) === 0) return fail('user_presence');
  if ((flags & FLAG_UV) === 0) return fail('user_verification');
  const counter = Buffer.from(data.buffer, data.byteOffset, data.length).readUInt32BE(33);
  if ((counter !== 0 || expect.storedCounter !== 0) && counter <= expect.storedCounter) return fail('counter');
  const raw = derToRaw(assertion.signature);
  if (raw === undefined || !verifyEs256Raw(key, sha256Concat(data, sha256(assertion.clientDataJSON)), raw)) return fail('signature');
  return { ok: true, counter };
}

const sha256Concat = (a: Uint8Array, b: Uint8Array): Uint8Array => Uint8Array.from([...a, ...b]);

/** ES256 over a message (hashed with SHA-256 here) with a raw 64-byte r||s signature. */
export function verifyEs256Raw(key: Es256PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 2 * COORD) return false;
  try {
    return verify('sha256', message, { key: keyObject(key), dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}

/** One DER INTEGER, positive and minimally encoded, of at most 32 value bytes, left-padded to 32. */
function derInteger(bytes: Uint8Array, at: number): { readonly value: Uint8Array; readonly next: number } | undefined {
  if (bytes[at] !== 0x02) return undefined;
  const length = bytes[at + 1];
  if (length === undefined || length === 0 || length > COORD + 1) return undefined;
  const body = bytes.subarray(at + 2, at + 2 + length);
  if (body.length !== length) return undefined;
  const first = body[0] ?? 0;
  if (first & 0x80) return undefined;
  if (first === 0 && (length === 1 || ((body[1] ?? 0) & 0x80) === 0)) return undefined;
  const value = first === 0 ? body.subarray(1) : body;
  if (value.length > COORD) return undefined;
  const padded = new Uint8Array(COORD);
  padded.set(value, COORD - value.length);
  return { value: padded, next: at + 2 + length };
}

/** A DER `SEQUENCE { INTEGER r, INTEGER s }` (short-form lengths, nothing after it) as raw r||s; undefined for anything else. */
export function derToRaw(der: Uint8Array): Uint8Array | undefined {
  if (der[0] !== 0x30 || der[1] === undefined || der[1] !== der.length - 2 || der[1] >= 0x80) return undefined;
  const r = derInteger(der, 2);
  if (r === undefined) return undefined;
  const s = derInteger(der, r.next);
  if (s === undefined || s.next !== der.length) return undefined;
  if (r.value.every((b) => b === 0) || s.value.every((b) => b === 0)) return undefined;
  const out = new Uint8Array(2 * COORD);
  out.set(r.value, 0);
  out.set(s.value, COORD);
  return out;
}
