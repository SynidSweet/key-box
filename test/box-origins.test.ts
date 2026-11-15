// KBOX-63 (host-model): the box has ONE host name. The phone's pages live on https://<host>:8443 (the passkey origin), the machine API,
// the relay, the OIDC issuer and the push subject on https://<host>. The passkey RP ID is the bare host. Every origin is composed in
// one place; these tests prove the behaviour that follows, never the source.
import assert from 'node:assert/strict';
import { createECDH } from 'node:crypto';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { softApprover } from './kit/approver.ts';
import type { Quirks } from './kit/approver.ts';
import { TimedClock, drive, seededRandom, tempDir } from './kit/index.ts';
import { FakePush } from './fakes/push.ts';
import { FakeTrust } from './fakes/trust.ts';
import { relayWorld } from './support/relay-world.ts';
import { WORDLIST, challenges, newApproverBody, wire } from './support/approve-world.ts';
import type { Action } from '../src/pure/actions.ts';
import { machineOrigin, oidcIssuer, pagesOrigin, pushSubject, relayUrl } from '../src/pure/box-origins.ts';
import { actionDigest, approvalChallenge, relyingParty, verifyProof } from '../src/pure/challenge.ts';
import type { ApproverKeys } from '../src/pure/challenge.ts';
import { decodeCoseEs256, parseRawPoint } from '../src/pure/cose.ts';
import { keptProofHolds } from '../src/pure/kept-proof.ts';
import { vapidAuthorization } from '../src/pure/pushcrypto.ts';
import { openApproveCore } from '../src/shell/approve-core.ts';
import { createCodeRoot } from '../src/shell/console.ts';
import { openCore } from '../src/shell/core.ts';
import { createApiServer } from '../src/shell/http.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';

const HOST = 'keybox.tail09a879.ts.net';
const NOW = 1_700_000_000_000;

// --- the pure composition -------------------------------------------------------------------------------------------------------------

test('KBOX-63 the pages origin is https://<host>:8443, the machine origin is the same without the port, and a pages port given is carried', () => {
  assert.equal(pagesOrigin(HOST), `https://${HOST}:8443`);
  assert.equal(machineOrigin(HOST), `https://${HOST}`);
  assert.equal(pagesOrigin(HOST, 4321), `https://${HOST}:4321`);
});

test('KBOX-63 the relay URL, the OIDC issuer and the push subject are the machine origin (the issuer and the subject are identifiers only)', () => {
  assert.equal(relayUrl(HOST, 'pathplat~shop~KEY'), `https://${HOST}/r/pathplat~shop~KEY`);
  assert.equal(oidcIssuer(HOST), `https://${HOST}`);
  assert.equal(pushSubject(HOST), `https://${HOST}`);
});

test('KBOX-63 the relying party has the bare host as its RP ID and the pages origin as its origin, with the default port or the one given', () => {
  assert.deepEqual(relyingParty(HOST), { rpId: HOST, origin: `https://${HOST}:8443` });
  assert.deepEqual(relyingParty(HOST, 4321), { rpId: HOST, origin: `https://${HOST}:4321` });
});

test('KBOX-63 a Web Push JWT made with the box\'s push subject carries sub = https://<host>', () => {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const result = vapidAuthorization({ sender: { privateKey: Uint8Array.from(ecdh.getPrivateKey()), publicKey: Uint8Array.from(ecdh.getPublicKey()) }, endpoint: new URL('https://fcm.googleapis.com/x'), expiresAt: 1, subject: pushSubject(HOST) });
  assert.ok(result.ok);
  const jwt = /t=([^, ]+)/.exec(result.value)?.[1] ?? '';
  const claims = JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as { sub: string };
  assert.equal(claims.sub, `https://${HOST}`);
});

// --- the passkey: the origin the verifier checks is the pages origin -------------------------------------------------------------------

function keysOf(a: ReturnType<typeof softApprover>): ApproverKeys {
  const passkey = decodeCoseEs256(a.coseKey);
  const device = parseRawPoint(a.devicePublicKey);
  assert.ok(passkey.ok && device.ok);
  return { approverId: 'owner-1', credentialId: a.credentialId, passkey: passkey.key, device: device.key };
}

function verdictOf(quirks: Quirks | undefined, host = HOST) {
  const approver = softApprover();
  const challenge = approvalChallenge('ap_1', actionDigest({ kind: 'demote', keyref: 'k' }), seededRandom(3).bytes(32));
  const rp = relyingParty(host);
  const parts = approver.prove(challenge, rp, quirks);
  return verifyProof(keysOf(approver), parts, { challenge, origin: rp.origin, rpId: rp.rpId, storedCounter: 0 });
}

test('KBOX-63 through the KBOX-9 verifier an assertion made at https://<host>:8443 passes', () => {
  assert.equal(verdictOf({ origin: `https://${HOST}:8443` }).ok, true);
});

test('KBOX-63 through the KBOX-9 verifier an assertion made at https://<host>, at https://<host>:443 or at another node of the tailnet fails the origin', () => {
  for (const origin of [`https://${HOST}`, `https://${HOST}:443`, 'https://sweetdesk.tail09a879.ts.net:8443']) {
    assert.deepEqual(verdictOf({ origin }), { ok: false, code: 'origin' }, origin);
  }
});

test('KBOX-63 through the KBOX-9 verifier an rpIdHash of tail09a879.ts.net (the tailnet, not the host) fails the RP ID', () => {
  assert.deepEqual(verdictOf({ rpIdHashOf: 'tail09a879.ts.net' }), { ok: false, code: 'rp_id' });
});

// --- the same, through core's setup route: the pages port core opens with --------------------------------------------------------------

/** A core's approval half on a unix socket, as the approve world builds it, with the pages port under test; the first approver registers at `origin`. */
async function setupStatus(t: TestContext, o: { readonly pagesPort?: number; readonly origin: string; readonly quirks?: Quirks }): Promise<number> {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const clock = new TimedClock(NOW);
  const random = seededRandom(21);
  const parts = openCore({ stateDir, clock, scheduler: clock, random });
  const priv = openPrivateDatabase(join(stateDir, 'private.db'));
  const lines: string[] = [];
  const codes = createCodeRoot({ dir: join(dir, 'codes'), sink: (line) => void lines.push(line), random, clock, wordlist: WORDLIST });
  const trust = new FakeTrust(codes, () => 'b0070000-0000-4000-8000-000000000001');
  const core = openApproveCore({
    parts,
    approverStore: priv,
    trust,
    push: new FakePush(),
    clock,
    random,
    domain: HOST,
    ...(o.pagesPort === undefined ? {} : { pagesPort: o.pagesPort }),
    wordlist: WORDLIST,
    vet: (_action: Action) => 'ok',
  });
  const server = createApiServer({ routes: [...parts.routes, ...core.routes], tokens: core.tokens.tokenStore, audit: parts.audit, random, clock, journal: () => undefined });
  const socket = join(dir, 'http.sock');
  await server.listen(socket);
  t.after(async () => {
    await server.stop();
    priv.close();
    parts.close();
  });
  const driver = drive(socket);
  codes.writeSetupCode(false);
  const code = /([a-z]+(?: [a-z]+){11})/.exec(lines.at(-1) ?? '')?.[1] ?? '';
  const nonceReply = await driver.request({ path: '/app/nonce?purpose=register', method: 'GET', headers: { 'x-kb-client-ip': '203.0.113.9' } });
  assert.equal(nonceReply.status, 200, nonceReply.body);
  const nonce = Uint8Array.from(Buffer.from((nonceReply.json() as { nonce_b64: string }).nonce_b64, 'base64url'));
  const approver = softApprover();
  const proof = approver.prove(challenges.register(nonce), { rpId: HOST, origin: o.origin }, o.quirks);
  const reply = await driver.request({
    path: '/setup',
    method: 'POST',
    headers: { 'x-kb-client-ip': '203.0.113.9', 'content-type': 'application/json' },
    body: JSON.stringify({ code, approver: newApproverBody(approver), proof: wire(nonce, proof), phrase: 'blue kettle' }),
  });
  return reply.status;
}

test('KBOX-63 a core opened without a pages port takes a first approver at https://<host>:8443 and no other origin', async (t) => {
  assert.equal(await setupStatus(t, { origin: `https://${HOST}:8443` }), 201);
  for (const origin of [`https://${HOST}`, `https://${HOST}:443`, 'https://sweetdesk.tail09a879.ts.net:8443']) {
    assert.equal(await setupStatus(t, { origin }), 403, origin);
  }
  assert.equal(await setupStatus(t, { origin: `https://${HOST}:8443`, quirks: { rpIdHashOf: 'tail09a879.ts.net' } }), 403, 'the RP ID is the host');
});

test('KBOX-63 a core opened with a pages port (the demo and browser harness) takes the approver at that port, and not at 8443', async (t) => {
  assert.equal(await setupStatus(t, { pagesPort: 4321, origin: `https://${HOST}:4321` }), 201);
  assert.equal(await setupStatus(t, { pagesPort: 4321, origin: `https://${HOST}:8443` }), 403);
});

// --- one source of the pages port: root's kept-proof check agrees with core ------------------------------------------------------------

function keptProofAt(origin: string) {
  const approver = softApprover();
  const action = { kind: 'install_update', install: 'a'.repeat(64), commit: 'b'.repeat(40), base: 'c'.repeat(64) } as const;
  const nonce = seededRandom(8).bytes(32);
  const parts = approver.prove(approvalChallenge('apr_0000000000000001', actionDigest(action), nonce), { rpId: HOST, origin });
  const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  const trust = { domain: HOST, approvers: [{ id: 'ap-owner', cose_b64: b64(approver.coseKey), device_pub_b64: b64(approver.devicePublicKey) }] };
  const proof = {
    approval_id: 'apr_0000000000000001',
    approver_id: 'ap-owner',
    nonce_b64: b64(nonce),
    credential_id_b64: b64(parts.credentialId),
    authenticator_data_b64: b64(parts.authenticatorData),
    client_data_json_b64: b64(parts.clientDataJSON),
    signature_b64: b64(parts.signature),
    device_signature_b64: b64(parts.deviceSignature),
  };
  return keptProofHolds(trust, proof, action);
}

test('KBOX-63 a kept approval proof made at https://<host>:8443 holds for kb-install; the same proof at https://<host> or https://<host>:443 does not', () => {
  assert.equal(keptProofAt(`https://${HOST}:8443`), true);
  assert.equal(keptProofAt(`https://${HOST}`), false);
  assert.equal(keptProofAt(`https://${HOST}:443`), false);
});

// --- the relay URL (B3 replacement) -------------------------------------------------------------------------------------------------------

test('KBOX-63 GET /r/_/grants gives each env URL as https://<host>/r/<address>', async (t) => {
  const w = await relayWorld(t);
  w.lend.addKey({ keyref: 'pathplat/shop/REAL_KEY', value: w.value, grants: ['laptop'] });
  const reply = await w.call('/r/_/grants');
  assert.equal(reply.status, 200);
  const listed = JSON.parse(reply.body.toString('utf8')) as { grants: { keyref: string; env: Record<string, string> }[] };
  const urls = Object.fromEntries(listed.grants.map((g) => [g.keyref, g.env]));
  assert.equal(urls['adminkey1']?.['PATHPLAT_BASE_URL'], 'https://box.example/r/adminkey1/v1');
  assert.equal(urls['hostkey001']?.['KBOX_GOOGLE_RELAY_URL'], 'https://box.example/r/hostkey001');
  assert.equal(urls['pathplat/shop/REAL_KEY']?.['PATHPLAT_BASE_URL'], 'https://box.example/r/pathplat~shop~REAL_KEY/v1');
  for (const env of Object.values(urls)) for (const url of Object.values(env)) assert.equal(url.includes('keys.'), false, url);
});
