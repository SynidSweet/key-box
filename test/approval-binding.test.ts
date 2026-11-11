// KBOX-9: the signature is bound to the exact action and to the approver device. The verifier is checked against
// published vectors (test/fixtures/webauthn/SOURCE.md), then every binding is refused one at a time under a valid signature.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import type { Quirks } from './kit/approver.ts';
import { seededRandom } from './kit/index.ts';
import { actionDigest, approvalChallenge, operationChallenge, pasteChallenge, verifyProof, viewChallenge } from '../src/pure/challenge.ts';
import type { ApproverKeys } from '../src/pure/challenge.ts';
import { decodeCoseEs256, parseRawPoint } from '../src/pure/cose.ts';
import { derToRaw, verifyAssertion, verifyEs256Raw } from '../src/pure/webauthn.ts';

const FIXTURE = new URL('./fixtures/webauthn/vectors.json', import.meta.url);

interface Vector {
  readonly credentialId: string;
  readonly cosePublicKey: string;
  readonly challenge: string;
  readonly authenticatorData: string;
  readonly clientDataJSON: string;
  readonly signature: string;
}
interface Fixture {
  readonly rpId: string;
  readonly origin: string;
  readonly vectors: Readonly<Record<'packed.ES256' | 'none.ES256' | 'crossOrigin.ES256', Vector>>;
  readonly rfc6979: { readonly ux: string; readonly uy: string; readonly message: string; readonly r: string; readonly s: string };
}

/** The fixture is mandatory: a missing or unreadable vector file fails here, it never skips (KBOX-9, Revision 2 row 11). */
function fixture(): Fixture {
  assert.ok(existsSync(FIXTURE), 'test/fixtures/webauthn/vectors.json is missing: the WebAuthn vector is mandatory');
  return JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;
}
const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'hex'));

function vectorCase(name: keyof Fixture['vectors']) {
  const f = fixture();
  const v = f.vectors[name];
  const cose = decodeCoseEs256(hex(v.cosePublicKey));
  assert.ok(cose.ok, `the ${name} COSE key decodes`);
  const assertion = { authenticatorData: hex(v.authenticatorData), clientDataJSON: hex(v.clientDataJSON), signature: hex(v.signature) };
  const expected = { challenge: hex(v.challenge), origin: f.origin, rpId: f.rpId, storedCounter: 0 };
  return { key: cose.key, assertion, expected };
}

// --- the published vectors ------------------------------------------------------------------------------------------

test('KBOX-9 the verifier accepts the published WebAuthn L3 section 16.7 ES256 assertion', () => {
  const { key, assertion, expected } = vectorCase('packed.ES256');
  assert.deepEqual(verifyAssertion(key, assertion, expected), { ok: true, counter: 0 });
});

test('KBOX-9 the published section 16.2 assertion (valid signature, UV clear) is refused for user verification', () => {
  const { key, assertion, expected } = vectorCase('none.ES256');
  assert.deepEqual(verifyAssertion(key, assertion, expected), { ok: false, code: 'user_verification' });
});

test('KBOX-9 the published section 16.4 assertion (valid signature, crossOrigin true) is refused', () => {
  const { key, assertion, expected } = vectorCase('crossOrigin.ES256');
  assert.deepEqual(verifyAssertion(key, assertion, expected), { ok: false, code: 'cross_origin' });
});

test('KBOX-9 the published assertion is refused for another challenge, origin, rpId, a stale counter, one flipped signature byte', () => {
  const { key, assertion, expected } = vectorCase('packed.ES256');
  const otherChallenge = Uint8Array.from(expected.challenge);
  otherChallenge[0] = (otherChallenge[0] ?? 0) ^ 1;
  assert.deepEqual(verifyAssertion(key, assertion, { ...expected, challenge: otherChallenge }), { ok: false, code: 'challenge' });
  assert.deepEqual(verifyAssertion(key, assertion, { ...expected, origin: 'https://example.org.evil' }), { ok: false, code: 'origin' });
  assert.deepEqual(verifyAssertion(key, assertion, { ...expected, rpId: 'example.com' }), { ok: false, code: 'rp_id' });
  assert.deepEqual(verifyAssertion(key, assertion, { ...expected, storedCounter: 1 }), { ok: false, code: 'counter' });
  const sig = Uint8Array.from(assertion.signature);
  sig[sig.length - 1] = (sig[sig.length - 1] ?? 0) ^ 1;
  assert.deepEqual(verifyAssertion(key, { ...assertion, signature: sig }, expected), { ok: false, code: 'signature' });
  const other = vectorCase('none.ES256');
  assert.deepEqual(verifyAssertion(other.key, assertion, expected), { ok: false, code: 'signature' }, 'another credential key');
});

test('KBOX-9 the device-key verify passes RFC 6979 A.2.5 (P-256, SHA-256, "sample") as raw r||s and refuses one flipped bit', () => {
  const { rfc6979: v } = fixture();
  const point = parseRawPoint(hex(`04${v.ux}${v.uy}`));
  assert.ok(point.ok);
  const raw = hex(v.r + v.s);
  const message = Buffer.from(v.message);
  assert.equal(verifyEs256Raw(point.key, message, raw), true);
  const bad = Uint8Array.from(raw);
  bad[63] = (bad[63] ?? 0) ^ 1;
  assert.equal(verifyEs256Raw(point.key, message, bad), false);
  assert.equal(verifyEs256Raw(point.key, message, raw.subarray(0, 63)), false, 'a 63-byte signature');
});

test('KBOX-9 DER-to-raw turns the RFC 6979 r and s, hand-encoded as DER here, into r||s, and refuses non-minimal or malformed DER', () => {
  const { rfc6979: v } = fixture();
  // r and s both have the top bit set, so each DER INTEGER carries a leading 0x00 (X.690 8.3.2): 30 46 02 21 00 r 02 21 00 s.
  const der = hex(`3046022100${v.r}022100${v.s}`);
  assert.deepEqual(derToRaw(der), hex(v.r + v.s));
  // A short integer is left-padded to 32 bytes: r = 1, s = 0x7f.
  assert.deepEqual(derToRaw(hex('300602010102017f')), hex(`${'00'.repeat(31)}01${'00'.repeat(31)}7f`));
  const refusedDer = [
    `3047022100${v.r}022100${v.s}`, // wrong outer length
    `3046022100${v.r}022100${v.s}00`, // trailing byte
    `304702220000${v.r}022100${v.s}`, // non-minimal: two leading zeros
    `30070202000102017f`, // a leading zero not needed (the next byte, 0x01, is below 0x80)
    `30440220${v.r}0220${v.s}`, // top bit set without the zero: a negative integer
    `3006020100020101`, // r = 0
    `3106020101020101`, // not a SEQUENCE
    `3006030101020101`, // not an INTEGER
    `30`, // truncated
  ];
  for (const d of refusedDer) assert.equal(derToRaw(hex(d)), undefined, d);
});

// --- the challenges -------------------------------------------------------------------------------------------------

const sha = (...parts: (string | Uint8Array)[]): Uint8Array => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return Uint8Array.from(h.digest());
};

test('KBOX-9 the approval, view, operation and paste challenges are SHA-256 over the tagged concatenations of the spec', () => {
  const random = seededRandom(11);
  const nonce = random.bytes(32);
  const action = { kind: 'grant', keyref: 'openai/admin', machine: 'ws-1' };
  const digest = actionDigest(action);
  assert.deepEqual(digest, sha('{"keyref":"openai/admin","kind":"grant","machine":"ws-1"}'));
  assert.deepEqual(approvalChallenge('ap_1', digest, nonce), sha('kbox-v1', 'ap_1', digest, nonce));
  assert.deepEqual(viewChallenge(nonce), sha('kbox-v1-view', nonce));
  const op = { kind: 'token_revoke', label: 'ws-1' } as const;
  assert.deepEqual(operationChallenge(op, nonce), sha('kbox-v1-op', sha('{"kind":"token_revoke","label":"ws-1"}'), nonce));
  assert.deepEqual(pasteChallenge('pt_1', digest, nonce), sha('kbox-v1-paste', 'pt_1', digest, nonce));
  assert.throws(() => approvalChallenge('ap_1', digest, nonce.subarray(1)), RangeError, 'the nonce is fixed length');
  assert.throws(() => approvalChallenge('ap_1', digest.subarray(1), nonce), RangeError, 'the digest is fixed length');
});

test('KBOX-9 the action digest is over canonical JSON: key order does not matter, a float and a null are refused', () => {
  assert.deepEqual(actionDigest({ machine: 'ws-1', kind: 'grant', keyref: 'k' }), actionDigest({ kind: 'grant', keyref: 'k', machine: 'ws-1' }));
  assert.notDeepEqual(actionDigest({ kind: 'grant', keyref: 'k', machine: 'ws-1' }), actionDigest({ kind: 'grant', keyref: 'k', machine: 'ws-2' }));
  assert.throws(() => actionDigest({ kind: 'set_schedule', keyref: 'k', rotate_every_days: 1.5, grace_hours: 1 }));
  assert.throws(() => actionDigest({ kind: 'demote', keyref: null }));
  assert.deepEqual(actionDigest({ kind: 'x', n: 9007199254740991, s: 'é "\\' }), sha('{"kind":"x","n":9007199254740991,"s":"é \\"\\\\"}'));
  assert.throws(() => actionDigest({ kind: 'x', n: 9007199254740992 }), 'an integer past 2^53 - 1 has no exact form');
});

// --- one approver: passkey and device key together --------------------------------------------------------------------

const RP = { rpId: 'keys.box.example', origin: 'https://keys.box.example' } as const;

function keysOf(id: string, a: ReturnType<typeof softApprover>): ApproverKeys {
  const passkey = decodeCoseEs256(a.coseKey);
  const device = parseRawPoint(a.devicePublicKey);
  assert.ok(passkey.ok && device.ok);
  return { approverId: id, credentialId: a.credentialId, passkey: passkey.key, device: device.key };
}

function proofCase(quirks?: Quirks) {
  const owner = softApprover();
  const keys = keysOf('owner-1', owner);
  const challenge = approvalChallenge('ap_1', actionDigest({ kind: 'demote', keyref: 'k' }), seededRandom(3).bytes(32));
  const parts = owner.prove(challenge, RP, quirks);
  return { owner, keys, challenge, parts, expect: { challenge, origin: RP.origin, rpId: RP.rpId, storedCounter: 0 } };
}

test('KBOX-9 a soft approver proof verifies, and returns the new signature counter', () => {
  const { keys, parts, expect } = proofCase();
  assert.deepEqual(verifyProof(keys, parts, expect), { ok: true, counter: 1 });
});

test('KBOX-9 each binding refused under a valid passkey signature: UV, UP, type, origin, rpIdHash, crossOrigin, topOrigin, counter, extra bytes', () => {
  const cases: [Quirks, string][] = [
    [{ flags: 0x01 }, 'user_verification'],
    [{ flags: 0x04 }, 'user_presence'],
    [{ type: 'webauthn.create' }, 'type'],
    [{ origin: 'https://keys.box.example.evil' }, 'origin'],
    [{ origin: 'http://keys.box.example' }, 'origin'],
    [{ rpIdHashOf: 'box.example' }, 'rp_id'],
    [{ crossOrigin: true }, 'cross_origin'],
    [{ topOrigin: 'https://keys.box.example' }, 'cross_origin'],
    [{ flags: 0x45 }, 'malformed'],
    [{ trailing: Uint8Array.of(0xa0) }, 'malformed'],
  ];
  for (const [quirks, code] of cases) {
    const { keys, parts, expect } = proofCase(quirks);
    assert.deepEqual(verifyProof(keys, parts, expect), { ok: false, code }, JSON.stringify(quirks));
  }
  const { keys, parts, expect } = proofCase({ counter: 7 });
  assert.deepEqual(verifyProof(keys, parts, { ...expect, storedCounter: 7 }), { ok: false, code: 'counter' }, 'a counter that did not grow');
  assert.deepEqual(verifyProof(keys, parts, { ...expect, storedCounter: 6 }), { ok: true, counter: 7 });
  const zero = proofCase({ counter: 0 });
  assert.deepEqual(verifyProof(zero.keys, zero.parts, zero.expect), { ok: true, counter: 0 }, 'a synced passkey that keeps no counter');
});

test('KBOX-9 a passkey alone never approves: a missing, short or foreign device signature is refused', () => {
  const { keys, parts, expect, challenge } = proofCase();
  assert.deepEqual(verifyProof(keys, { ...parts, deviceSignature: new Uint8Array(0) }, expect), { ok: false, code: 'device_signature' });
  assert.deepEqual(verifyProof(keys, { ...parts, deviceSignature: parts.deviceSignature.subarray(0, 63) }, expect), { ok: false, code: 'device_signature' });
  const other = softApprover();
  assert.deepEqual(verifyProof(keys, { ...parts, deviceSignature: other.deviceSign(challenge) }, expect), { ok: false, code: 'device_signature' }, 'device key of approver Y');
  const owner2 = softApprover();
  const over = Uint8Array.from(challenge);
  over[0] = (over[0] ?? 0) ^ 1;
  assert.deepEqual(verifyProof(keysOf('o', owner2), { ...owner2.prove(challenge, RP), deviceSignature: owner2.deviceSign(over) }, expect), { ok: false, code: 'device_signature' }, 'device signature over another challenge');
});

test('KBOX-9 passkey of approver X with the device key of approver Y is refused, both ways round', () => {
  const x = softApprover();
  const y = softApprover();
  const { challenge, expect } = proofCase();
  const px = x.prove(challenge, RP);
  const py = y.prove(challenge, RP);
  const mixed = { ...px, deviceSignature: py.deviceSignature };
  assert.deepEqual(verifyProof(keysOf('x', x), mixed, expect), { ok: false, code: 'device_signature' });
  const yKeysXDevice = { ...keysOf('y', y), device: keysOf('x', x).device };
  assert.deepEqual(verifyProof(yKeysXDevice, { ...py, deviceSignature: px.deviceSignature }, expect).ok, true, 'control: the pair as registered verifies');
  assert.deepEqual(verifyProof(keysOf('y', y), { ...py, deviceSignature: px.deviceSignature }, expect), { ok: false, code: 'device_signature' });
  assert.deepEqual(verifyProof(keysOf('x', x), { ...py, credentialId: x.credentialId }, expect), { ok: false, code: 'signature' }, "Y's passkey under X's credential id");
});

test('KBOX-9 an assertion for one challenge is refused for another (action A replayed for action B)', () => {
  const { keys, parts, expect } = proofCase();
  const b = approvalChallenge('ap_1', actionDigest({ kind: 'demote', keyref: 'other' }), seededRandom(3).bytes(32));
  assert.deepEqual(verifyProof(keys, parts, { ...expect, challenge: b }), { ok: false, code: 'challenge' });
});
