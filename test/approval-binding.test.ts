// KBOX-9: the signature is bound to the exact action and to the approver device. The verifier is checked against
// published vectors (test/fixtures/webauthn/SOURCE.md), then every binding is refused one at a time under a valid signature.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import type { Quirks } from './kit/approver.ts';
import { seededRandom } from './kit/index.ts';
import { DOMAIN, WORDLIST, approveWorld, challenges, newApproverBody, wire, RP as WORLD_RP } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';
import { actionDigest, approvalChallenge, operationChallenge, pasteChallenge, verifyProof, viewChallenge } from '../src/pure/challenge.ts';
import type { ApproverKeys } from '../src/pure/challenge.ts';
import { decodeCoseEs256, parseRawPoint } from '../src/pure/cose.ts';
import { derToRaw, verifyAssertion, verifyEs256Raw } from '../src/pure/webauthn.ts';
import { createApprovers } from '../src/shell/approvers.ts';

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

// --- the routes: every binding refused end to end, under a valid passkey signature ----------------------------------

async function pending(w: World, action: Parameters<World['propose']>[0]) {
  const proposed = w.propose(action, 'ctl-1');
  const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
  assert.ok(item);
  return item;
}

test('KBOX-9 route: a valid approval executes once; replaying the same nonce is refused', async (t) => {
  const w = await approveWorld(t);
  const item = await pending(w, { kind: 'demote', keyref: 'k1' });
  const proof = w.proofFor(item);
  const ok = await w.decide(item.approval_id, 'approve', proof);
  assert.equal(ok.status, 200, ok.body);
  const again = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  assert.equal((await w.decide(again.approval_id, 'approve', proof)).status, 403, 'nonce of another approval and already used');
  const item2 = (await w.queue())[0];
  assert.ok(item2);
  const p2 = w.proofFor(item2);
  w.clock.advance(1);
  assert.equal((await w.decide(item2.approval_id, 'deny', { ...p2 })).status, 200);
});

test('KBOX-9 route: an assertion for action A is refused for action B, and a nonce is used once', async (t) => {
  const w = await approveWorld(t);
  const a = await pending(w, { kind: 'demote', keyref: 'k1' });
  const b = await pending(w, { kind: 'demote', keyref: 'k2' });
  const proofA = w.proofFor(a);
  assert.equal((await w.decide(b.approval_id, 'approve', proofA)).status, 403, "A's proof on B");
  const forgedNonce = { ...w.proofFor({ ...a, nonce_b64: b.nonce_b64 }) };
  assert.equal((await w.decide(b.approval_id, 'approve', forgedNonce)).status, 403, "B's nonce signed over A's digest");
  assert.equal((await w.decide(b.approval_id, 'approve', w.proofFor(b))).status, 403, "a nonce that reached the check is spent, even by a refused attempt");
  const b2 = (await w.queue()).find((q) => q.approval_id === b.approval_id);
  assert.ok(b2);
  const proofB = w.proofFor(b2);
  assert.equal((await w.decide(b.approval_id, 'approve', proofB)).status, 200);
  const [again] = await w.queue();
  assert.ok(again);
  const reused = { ...w.proofFor(again), nonce: proofB.nonce };
  assert.equal((await w.decide(again.approval_id, 'approve', reused)).status, 403, 'a used nonce');
});

test('KBOX-9 route: UV clear, UP clear, wrong origin, wrong rpIdHash and a type other than webauthn.get are each refused', async (t) => {
  const w = await approveWorld(t);
  for (const quirks of [{ flags: 0x01 }, { flags: 0x04 }, { origin: 'https://evil.example' }, { rpIdHashOf: 'evil.example' }, { type: 'webauthn.create' }, { crossOrigin: true }]) {
    const item = await pending(w, { kind: 'demote', keyref: `k-${JSON.stringify(quirks).length}` });
    const reply = await w.decide(item.approval_id, 'approve', w.proofFor(item, w.owner, quirks));
    assert.equal(reply.status, 403, JSON.stringify(quirks));
    assert.equal(w.parts.meta.snapshot().approvals.some((p) => p.approval_id === item.approval_id), true, 'still pending');
    const ok = await w.decide(item.approval_id, 'deny', w.proofFor((await w.queue()).find((q) => q.approval_id === item.approval_id) ?? item));
    assert.equal(ok.status, 200, 'control: the same approver with no fault decides it');
  }
});

test('KBOX-9 route: a passkey without the device signature is refused, and so is the device signature of another approver', async (t) => {
  const w = await approveWorld(t);
  const second = await w.addApprover();
  const item = await pending(w, { kind: 'demote', keyref: 'k1' });
  const proof = w.proofFor(item);
  assert.equal((await w.decide(item.approval_id, 'approve', { ...proof, device_signature: '' })).status, 403, 'no device signature');
  const fresh = async () => (await w.queue()).find((q) => q.approval_id === item.approval_id) ?? item;
  const i2 = await fresh();
  const mine = w.proofFor(i2);
  const challenge = challenges.approval(i2.approval_id, Buffer.from(i2.digest_b64, 'base64url'), Buffer.from(i2.nonce_b64, 'base64url'));
  const theirs = Buffer.from(second.approver.deviceSign(challenge)).toString('base64url');
  assert.equal((await w.decide(item.approval_id, 'approve', { ...mine, device_signature: theirs })).status, 403, "X's passkey, Y's device key");
  const i3 = await fresh();
  const yPasskey = w.proofFor(i3, second.approver);
  const xDevice = w.proofFor(i3);
  assert.equal((await w.decide(item.approval_id, 'approve', { ...yPasskey, device_signature: xDevice.device_signature })).status, 403, "Y's passkey, X's device key");
  const i4 = await fresh();
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(i4, second.approver))).status, 200, 'control: Y with its own pair');
});

test('KBOX-9 route: a changed action after render is refused (the digest the phone signed is not the stored one)', async (t) => {
  const w = await approveWorld(t);
  const item = await pending(w, { kind: 'grant', keyref: 'k1', machine: 'ws-1' });
  w.propose({ kind: 'grant', keyref: 'k1', machine: 'ws-evil' }, 'ctl-1');
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item))).status, 403);
  const stale = { ...item, revision: 2 };
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(stale))).status, 403, 'old digest under the old nonce');
});

test('KBOX-9 an approved install_update keeps the proof kb-install needs, and that proof does not verify for another action', async (t) => {
  const w = await approveWorld(t);
  const action = { kind: 'install_update', install: 'a'.repeat(64), commit: 'b'.repeat(40), base: 'c'.repeat(64) } as const;
  const item = await pending(w, action);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item))).status, 200);
  const kept = w.core.approvals.storedProof(item.approval_id);
  assert.ok(kept);
  assert.deepEqual(Object.keys(kept).sort(), ['approval_id', 'approver_id', 'authenticator_data_b64', 'client_data_json_b64', 'credential_id_b64', 'device_signature_b64', 'nonce_b64', 'signature_b64']);
  assert.equal(kept.approver_id, w.ownerId);
  const bytes = (s: string) => Uint8Array.from(Buffer.from(s, 'base64url'));
  const keys = keysOf(kept.approver_id, w.owner);
  const parts = { credentialId: bytes(kept.credential_id_b64), authenticatorData: bytes(kept.authenticator_data_b64), clientDataJSON: bytes(kept.client_data_json_b64), signature: bytes(kept.signature_b64), deviceSignature: bytes(kept.device_signature_b64) };
  const expectFor = (a: object, id: string) => ({ challenge: approvalChallenge(id, actionDigest(a), bytes(kept.nonce_b64)), origin: WORLD_RP.origin, rpId: WORLD_RP.rpId, storedCounter: 0 });
  assert.equal(verifyProof(keys, parts, expectFor(action, item.approval_id)).ok, true, 'root can verify it again for the action it names');
  assert.equal(verifyProof(keys, parts, expectFor({ ...action, install: 'd'.repeat(64) }, item.approval_id)).ok, false, 'another H');
  assert.equal(verifyProof(keys, parts, expectFor({ ...action, base: 'e'.repeat(64) }, item.approval_id)).ok, false, 'another base');
  assert.equal(verifyProof(keys, parts, expectFor(action, 'apr_0000000000000000')).ok, false, 'another approval');
  const plain = await pending(w, { kind: 'demote', keyref: 'k9' });
  assert.equal((await w.decide(plain.approval_id, 'approve', w.proofFor(plain))).status, 200);
  assert.equal(w.core.approvals.storedProof(plain.approval_id), undefined, 'only install_update and the approver kinds keep a proof');
});

test('KBOX-9 a view session needs the device signature; the cookie it gives changes nothing on any state-changing route', async (t) => {
  const w = await approveWorld(t);
  const n = await w.nonce('view');
  const parts = w.owner.prove(challenges.view(n), WORLD_RP);
  assert.equal((await w.call('/app/view', { json: { proof: { ...wire(n, parts), device_signature: '' } } })).status, 403);
  const other = softApprover();
  const n2 = await w.nonce('view');
  assert.equal((await w.call('/app/view', { json: { proof: { ...wire(n2, w.owner.prove(challenges.view(n2), WORLD_RP)), device_signature: Buffer.from(other.deviceSign(challenges.view(n2))).toString('base64url') } } })).status, 403);
  const cookie = await w.view();
  const reply = await w.call('/app/view', { method: 'GET', cookie });
  assert.equal(reply.status, 404);
  const set = (await w.call('/app/view', { json: { proof: wire(await w.nonce('view'), w.owner.prove(challenges.view(await w.nonce('view')), WORLD_RP)) } })).status;
  assert.equal(set, 403, 'a view proof over another nonce than the one sent');
  const item = await pending(w, { kind: 'demote', keyref: 'k1' });
  for (const path of [`/app/approve/${item.approval_id}`, `/app/deny/${item.approval_id}`, '/app/op', '/setup', '/recover', '/recover/register']) {
    for (const json of [{}, undefined]) {
      const r = await w.call(path, { method: 'POST', cookie, ...(json === undefined ? {} : { json }) });
      assert.ok(r.status === 400 || r.status === 415 || r.status === 404, `${path} with only the cookie: ${r.status}`);
    }
  }
  assert.equal(w.parts.meta.snapshot().approvals.length, 1, 'still pending');
});

test('KBOX-9 KBOX-11 a signed operation needs the device signature, a fresh nonce, and is bound to its label', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ws-a', 'relay');
  w.token('ws-b', 'relay');
  const signOp = async (op: { kind: string; label: string }, signedOp = op) => {
    const n = await w.nonce('op');
    return { op, proof: wire(n, w.owner.prove(challenges.op(signedOp, n), WORLD_RP)) };
  };
  const noDevice = await signOp({ kind: 'token_revoke', label: 'ws-a' });
  assert.equal((await w.call('/app/op', { json: { ...noDevice, proof: { ...noDevice.proof, device_signature: '' } } })).status, 403);
  const forA = await signOp({ kind: 'token_revoke', label: 'ws-b' }, { kind: 'token_revoke', label: 'ws-a' });
  assert.equal((await w.call('/app/op', { json: forA })).status, 403, 'a revoke signed for ws-a cannot revoke ws-b');
  const windowForA = await signOp({ kind: 'enrol_window_open', label: 'ws-c' }, { kind: 'token_revoke', label: 'ws-c' });
  assert.equal((await w.call('/app/op', { json: windowForA })).status, 403, 'a revoke signature cannot open a window');
  const good = await signOp({ kind: 'token_revoke', label: 'ws-a' });
  assert.equal((await w.call('/app/op', { json: good })).status, 200);
  assert.equal((await w.call('/app/op', { json: good })).status, 403, 'the nonce is used');
  assert.equal(w.parts.meta.tokens().find((x) => x.label === 'ws-a')?.revoked, true);
  assert.equal(w.parts.meta.tokens().find((x) => x.label === 'ws-b')?.revoked, false);
  void token;
});

test('KBOX-9 KBOX-7 a replaced action is stored under the digest of its new content: the queue shows that digest and a fresh proof over the old one is refused', async (t) => {
  const w = await approveWorld(t);
  const first = await pending(w, { kind: 'grant', keyref: 'k1', machine: 'ws-1' });
  const replacement = { kind: 'grant', keyref: 'k1', machine: 'ws-evil' } as const;
  w.propose(replacement, 'ctl-1');
  const item = (await w.queue()).find((q) => q.approval_id === first.approval_id);
  assert.ok(item);
  // The oracle: RFC 8785 of a flat all-string object is JSON with the keys sorted.
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(replacement).sort(([a], [b]) => (a < b ? -1 : 1))));
  assert.equal(Buffer.from(item.digest_b64, 'base64url').toString('hex'), createHash('sha256').update(canonical).digest('hex'));
  const overOld = w.proofFor({ ...item, digest_b64: first.digest_b64 });
  assert.equal((await w.decide(item.approval_id, 'approve', overOld)).status, 403, 'a fresh nonce over the digest of the action that was replaced');
});

test('KBOX-9 the decision is in the challenge: an approve proof cannot deny, a deny proof cannot approve, and each decides with its own', async (t) => {
  const w = await approveWorld(t);
  const first = await pending(w, { kind: 'demote', keyref: 'k1' });
  const id = first.approval_id;
  const fresh = async () => {
    const item = (await w.queue()).find((q) => q.approval_id === id);
    assert.ok(item);
    return item;
  };
  const stillPending = (): boolean => w.parts.meta.snapshot().approvals.some((p) => p.approval_id === id);
  assert.equal((await w.call(`/app/deny/${id}`, { json: { proof: w.proofFor(first) } })).status, 403, 'an approval proof sent to deny');
  assert.equal(stillPending(), true);
  assert.equal((await w.call(`/app/approve/${id}`, { json: { proof: w.proofFor(await fresh(), w.owner, undefined, 'deny') } })).status, 403, 'a denial proof sent to approve');
  assert.equal(stillPending(), true);
  assert.deepEqual(refusedCodes(w), ['challenge', 'challenge']);
  assert.equal((await w.call(`/app/deny/${id}`, { json: { proof: w.proofFor(await fresh(), w.owner, undefined, 'deny') } })).status, 200, 'control: a denial proof denies');
  const other = await pending(w, { kind: 'demote', keyref: 'k2' });
  assert.equal((await w.call(`/app/approve/${other.approval_id}`, { json: { proof: w.proofFor(other) } })).status, 200, 'control: an approval proof approves');
});

// --- pins for bindings the code has and no test held (kernel-approve minors 1 to 5) -----------------------------------

/** The codes of every refused proof so far, oldest first. */
const refusedCodes = (w: World): string[] => w.parts.audit.read(0).entries.filter((e) => e.action === 'proof.refused').map((e) => String(e.detail['code']));

test('KBOX-9 a nonce minted before a restart is refused after it: the key is fresh per process, so replay protection does not rest on the in-memory spent set', async (t) => {
  const w = await approveWorld(t);
  const n = await w.nonce('view');
  const parts = w.owner.prove(challenges.view(n), WORLD_RP);
  const proof = { nonce: n, ...parts };
  const restarted = createApprovers({ store: w.priv, trust: w.trust, push: w.push, audit: w.parts.audit, clock: w.clock, random: seededRandom(777), domain: DOMAIN, wordlist: WORDLIST });
  assert.deepEqual(restarted.check({ kind: 'view' }, viewChallenge, proof), { ok: false, code: 'nonce_foreign' });
  assert.equal(w.core.approvers.check({ kind: 'view' }, viewChallenge, proof).ok, true, 'control: the same proof is good for the process that minted the nonce');
});

test('KBOX-9 the signature counter is kept between proofs: a lower or equal counter is refused after a higher one, a higher one is accepted', async (t) => {
  const w = await approveWorld(t);
  const open = async (counter: number): Promise<number> => {
    const n = await w.nonce('view');
    return (await w.call('/app/view', { json: { proof: wire(n, w.owner.prove(challenges.view(n), WORLD_RP, { counter })) } })).status;
  };
  assert.equal(await open(7), 200);
  assert.equal(await open(6), 403, 'below the stored 7');
  assert.equal(await open(7), 403, 'equal to the stored 7');
  assert.equal(await open(8), 200, 'above it');
  assert.deepEqual(refusedCodes(w), ['counter', 'counter']);
});

test('KBOX-9 the view cookie is __Host- prefixed, Path=/, HttpOnly, Secure, SameSite=Strict, has no Domain and lasts 15 minutes', async (t) => {
  const w = await approveWorld(t);
  const n = await w.nonce('view');
  const reply = await w.call('/app/view', { json: { proof: wire(n, w.owner.prove(challenges.view(n), WORLD_RP)) } });
  assert.equal(reply.status, 200);
  const [pair = '', ...flags] = (reply.headers['set-cookie'] ?? '').split(';').map((s) => s.trim());
  assert.match(pair, /^__Host-[A-Za-z0-9_-]+=[A-Za-z0-9_-]{20,}$/);
  assert.deepEqual([...flags].sort(), ['HttpOnly', 'Max-Age=900', 'Path=/', 'SameSite=Strict', 'Secure']);
});

test('KBOX-9 a registration nonce is spent by the registration: a second registration under the same nonce is refused even with a valid recovery code', async (t) => {
  const w = await approveWorld(t);
  const n = await w.nonce('register');
  const body = (a: ReturnType<typeof softApprover>, code: string) => ({ code, approver: newApproverBody(a), proof: wire(n, a.prove(challenges.register(n), WORLD_RP)), phrase: 'blue kettle' });
  assert.equal((await w.call('/recover', { json: body(softApprover(), w.recoveryCode()) })).status, 201);
  assert.equal((await w.call('/recover', { json: body(softApprover(), w.recoveryCode()) })).status, 403);
  assert.deepEqual(refusedCodes(w), ['nonce_used']);
});

test('KBOX-9 a nonce is good for the purpose it was minted for only: every other pairing of view, op and register is refused as foreign', async (t) => {
  const w = await approveWorld(t);
  const op = { kind: 'token_revoke', label: 'ws-a' } as const;
  w.token('ws-a', 'relay');
  const challengeOf = {
    view: (n: Uint8Array) => challenges.view(n),
    op: (n: Uint8Array) => challenges.op(op, n),
    register: (n: Uint8Array) => challenges.register(n),
  } as const;
  const purposes = ['view', 'op', 'register'] as const;
  for (const minted of purposes) {
    for (const used of purposes) {
      if (minted === used) continue;
      const n = await w.nonce(minted);
      const proof = { nonce: n, ...w.owner.prove(challengeOf[used](n), WORLD_RP) };
      const verdict = w.core.approvers.check({ kind: used }, challengeOf[used], proof);
      assert.equal(verdict.ok ? 'ok' : verdict.code, 'nonce_foreign', `a ${minted} nonce used as ${used}`);
    }
  }
  const n = await w.nonce('op');
  assert.equal(w.core.approvers.check({ kind: 'op' }, challengeOf.op, { nonce: n, ...w.owner.prove(challengeOf.op(n), WORLD_RP) }).ok, true, 'control: an op nonce is good as op');
});
