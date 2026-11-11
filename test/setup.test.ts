// KBOX-49: the first approver: the setup code root made, the phone's passkey and device key, and the one COSE map the box parses.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import { approveWorld, challenges, newApproverBody, registerAt, setupCodeFrom, wire, RP } from './support/approve-world.ts';
import { cborEncode } from './kit/cbor.ts';
import { drive, startNode, tempDir } from './kit/index.ts';
import { decodeCoseEs256 } from '../src/pure/cose.ts';
import { FIXED } from '../src/pure/words.ts';

const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'hex'));
const VECTOR_COSE = 'a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423';

test('KBOX-49 the COSE decoder takes the published EC2 P-256 ES256 key (WebAuthn L3 16.7) and gives its coordinates', () => {
  const key = decodeCoseEs256(hex(VECTOR_COSE));
  assert.ok(key.ok);
  assert.equal(Buffer.from(key.key.x).toString('hex'), '1cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae5');
  assert.equal(Buffer.from(key.key.y).toString('hex'), '59e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423');
});

test('KBOX-49 a COSE map with another key type, an extra member, a float, trailing bytes, a repeated label or an off-curve point is refused', () => {
  const x = hex(VECTOR_COSE.slice(20, 84));
  const y = hex(VECTOR_COSE.slice(90));
  const map = (entries: [number, number | Uint8Array][]) => cborEncode(new Map(entries));
  const base: [number, number | Uint8Array][] = [[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]];
  const refused: [string, Uint8Array][] = [
    ['kty OKP', map([[1, 1], [3, -7], [-1, 1], [-2, x], [-3, y]])],
    ['kty RSA', map([[1, 3], [3, -7], [-1, 1], [-2, x], [-3, y]])],
    ['alg ES384', map([[1, 2], [3, -35], [-1, 1], [-2, x], [-3, y]])],
    ['crv P-384', map([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]])],
    ['an extra member', map([...base, [2, Uint8Array.of(1)]])],
    ['a missing member', map(base.slice(0, 4))],
    ['a float value (alg as half float -7.0)', Uint8Array.from([0xa5, 0x01, 0x02, 0x03, 0xf9, 0xc7, 0x00, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y])],
    ['trailing bytes', Uint8Array.from([...hex(VECTOR_COSE), 0x00])],
    ['a repeated label', Uint8Array.from([0xa5, 0x01, 0x02, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y])],
    ['a short coordinate', map([[1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]])],
    ['a text label', Uint8Array.from([0xa5, 0x61, 0x6b, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y])],
    ['an indefinite map', Uint8Array.from([0xbf, ...hex(VECTOR_COSE).subarray(1), 0xff])],
    ['a non-minimal integer', Uint8Array.from([0xa5, 0x18, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y])],
    ['a point not on the curve', map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Uint8Array.from(y.map((b, i) => (i === 31 ? b ^ 1 : b)))]])],
    ['a truncated map', hex(VECTOR_COSE).subarray(0, 50)],
  ];
  assert.equal(decodeCoseEs256(map(base)).ok, true, 'control: the same map built here decodes');
  for (const [name, bytes] of refused) assert.deepEqual(decodeCoseEs256(bytes), { ok: false }, name);
});

test('KBOX-49 setup with the code root made registers the passkey and device key together, calls the TrustPort with the domain and the keys, and closes for good', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  assert.equal((await w.call('/setup')).status, 200, 'the setup page is open before the first approver');
  w.codes.writeSetupCode(false);
  const code = setupCodeFrom(w.console);
  const owner = softApprover();
  const reply = await registerAt(w, '/setup', code, owner);
  assert.equal(reply.status, 201, reply.body);
  const call = w.trust.calls[0];
  assert.ok(call?.change === 'setup');
  assert.deepEqual(call.domain, 'box.example');
  assert.deepEqual(call.approvers.map((a) => [a.cose_b64, a.device_pub_b64]), [[Buffer.from(owner.coseKey).toString('base64url'), Buffer.from(owner.devicePublicKey).toString('base64url')]]);
  assert.equal(w.core.approvers.count(), 1);
  assert.equal((await w.call('/setup')).status, 404);
  w.codes.writeSetupCode(false);
  assert.equal((await registerAt(w, '/setup', setupCodeFrom(w.console), softApprover())).status, 404, 'a second setup is refused after the first completes');
  await w.view(owner);
});

test('KBOX-49 a wrong code is refused by root and the right code stays valid; core keeps nothing when root refuses', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  w.codes.writeSetupCode(false);
  const code = setupCodeFrom(w.console);
  const wrong = code.split(' ').reverse().join(' ');
  assert.equal((await registerAt(w, '/setup', wrong, softApprover())).status, 403);
  assert.equal(w.core.approvers.count(), 0);
  w.trust.refuseNext('io_error');
  assert.equal((await registerAt(w, '/setup', code, softApprover())).status, 403, 'a refused port answer does not complete setup');
  assert.equal(w.core.approvers.count(), 0);
  assert.equal((await registerAt(w, '/setup', code, softApprover())).status, 201, 'the code is still valid');
});

test('KBOX-49 setup is refused by root once trust.json exists, even when core has no approver and the code is right', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  w.codes.writeSetupCode(false);
  const code = setupCodeFrom(w.console);
  w.trust.copy = { domain: 'box.example', approvers: [] };
  assert.equal((await registerAt(w, '/setup', code, softApprover())).status, 403);
  assert.equal(w.core.approvers.count(), 0);
});

test('KBOX-49 setup without a device-key registration, or with a device key the phone does not hold, refuses to complete', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  w.codes.writeSetupCode(false);
  const code = setupCodeFrom(w.console);
  const owner = softApprover();
  const n = await w.nonce('register');
  const proof = wire(n, owner.prove(challenges.register(n), RP));
  const { device_public_key: _drop, ...noDevice } = newApproverBody(owner);
  void _drop;
  assert.equal((await w.call('/setup', { json: { code, approver: noDevice, proof, phrase: 'p' } })).status, 400);
  const other = softApprover();
  const n2 = await w.nonce('register');
  const foreign = { ...newApproverBody(owner), device_public_key: Buffer.from(other.devicePublicKey).toString('base64url') };
  assert.equal((await w.call('/setup', { json: { code, approver: foreign, proof: wire(n2, owner.prove(challenges.register(n2), RP)), phrase: 'p' } })).status, 403);
  const n3 = await w.nonce('register');
  assert.equal((await w.call('/setup', { json: { code, approver: newApproverBody(owner), proof: { ...wire(n3, owner.prove(challenges.register(n3), RP)), device_signature: '' }, phrase: 'p' } })).status, 403);
  assert.equal(w.core.approvers.count(), 0);
  assert.equal(w.trust.calls.length, 0, 'root is not asked for keys that did not prove themselves');
});

test('KBOX-49 the code never appears in core\'s database, WAL, audit, events or responses; the phrase is in private.db only', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  w.codes.writeSetupCode(false);
  const code = setupCodeFrom(w.console);
  const phrase = 'violet harbour 7781';
  const reply = await registerAt(w, '/setup', code, softApprover(), phrase);
  assert.equal(reply.status, 201);
  const files = readdirSync(w.stateDir);
  const surfaces: [string, string][] = files.map((f) => [f, readFileSync(join(w.stateDir, f)).toString('latin1')]);
  surfaces.push(['response', reply.body], ['audit', JSON.stringify(w.parts.audit.read(0).entries)], ['events', JSON.stringify(w.parts.events.after(0))]);
  for (const [name, body] of surfaces) {
    assert.equal(body.includes(code), false, `code in ${name}`);
    for (const word of [code.split(' ').slice(0, 3).join(' ')]) assert.equal(body.includes(word), false, `code words in ${name}`);
    if (!name.startsWith('private.db')) assert.equal(body.includes(phrase), false, `phrase in ${name}`);
  }
  assert.ok(surfaces.some(([name, body]) => name.startsWith('private.db') && body.includes(phrase)), 'the phrase is kept in private.db');
});

test('KBOX-22 GET /app/push-key gives the phone the box\'s applicationServerKey and nothing else, without a token or a view session', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  const reply = await w.call('/app/push-key');
  assert.equal(reply.status, 200);
  assert.deepEqual(JSON.parse(reply.body), { application_server_key_b64: w.push.applicationServerKey() });
});

test('KBOX-53 every phone page and script is served as the committed bytes with a self-only CSP and nosniff', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  const web = new URL('../src/web/', import.meta.url);
  const pages: [string, string, string][] = [
    ['/', 'index.html', 'text/html'], ['/setup', 'setup.html', 'text/html'], ['/recover', 'recover.html', 'text/html'],
    ['/app.js', 'app.js', 'text/javascript'], ['/setup.js', 'setup.js', 'text/javascript'], ['/recover.js', 'recover.js', 'text/javascript'],
    ['/webauthn-client.js', 'webauthn-client.js', 'text/javascript'], ['/sw.js', 'sw.js', 'text/javascript'], ['/app.css', 'app.css', 'text/css'],
    ['/manifest.webmanifest', 'manifest.webmanifest', 'application/manifest+json'], ['/register.js', 'register.js', 'text/javascript'],
  ];
  for (const [path, name, type] of pages) {
    const reply = await w.call(path);
    assert.equal(reply.status, 200, path);
    assert.equal(reply.body, readFileSync(new URL(name, web), 'utf8'), path);
    assert.ok(reply.headers['content-type']?.startsWith(type), path);
    assert.equal(reply.headers['content-security-policy'], "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", path);
    assert.equal(reply.headers['x-content-type-options'], 'nosniff', path);
  }
});

test('KBOX-49 KBOX-46 KBOX-20 the setup page warns of the device key before the button that makes it, and carries the egress sentence and both recovery cases; /recover carries both cases', () => {
  const setup = readFileSync(new URL('../src/web/setup.html', import.meta.url), 'utf8');
  const recover = readFileSync(new URL('../src/web/recover.html', import.meta.url), 'utf8');
  const warning = setup.indexOf(FIXED.deviceKeyWarning);
  assert.ok(warning >= 0, 'the device key warning');
  assert.ok(warning < setup.indexOf('id="go"'), 'said before the button that creates the key');
  assert.ok(setup.includes('These limits do not stop an approved update that is malicious.'));
  for (const page of [setup, recover]) {
    assert.ok(page.includes(FIXED.recoverReinstalled));
    assert.ok(page.includes(FIXED.recoverLostPhone));
  }
});

test('KBOX-9 the phone page builds the same approval, view, operation and registration challenges as the box, and takes the COSE key out of the authenticator data', async () => {
  const client = await import('../src/web/webauthn-client.js');
  const nonce = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
  const digest = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
  const same = (a: Uint8Array, b: Uint8Array, what: string): void => assert.equal(Buffer.from(a).toString('hex'), Buffer.from(b).toString('hex'), what);
  same(await client.approvalChallenge('apr_AAAAAAAAAAAAAAAA', digest, nonce), challenges.approval('apr_AAAAAAAAAAAAAAAA', digest, nonce), 'approval');
  same(await client.viewChallenge(nonce), challenges.view(nonce), 'view');
  same(await client.registrationChallenge(nonce), challenges.register(nonce), 'register');
  const op = { kind: 'token_revoke', label: 'ctl "laptop" é' } as const;
  same(await client.operationChallenge(op, nonce), challenges.op(op, nonce), 'operation');
  const credentialId = Uint8Array.from([9, 8, 7, 6, 5]);
  const cose = hex(VECTOR_COSE);
  const authData = Uint8Array.from([...new Uint8Array(32).fill(1), 0x45, 0, 0, 0, 0, ...new Uint8Array(16), 0, credentialId.length, ...credentialId, ...cose]);
  const got = client.attestedKey(authData);
  assert.ok(got !== undefined);
  same(got.credentialId, credentialId, 'credential id');
  same(got.coseKey, cose, 'COSE key');
  assert.equal(client.attestedKey(authData.subarray(0, 60)), undefined, 'truncated authenticator data');
  assert.equal(client.attestedKey(Uint8Array.from([...authData.subarray(0, 32), 0x05, ...authData.subarray(33)])), undefined, 'AT flag clear');
});

test('KBOX-49 the running core with KB_DOMAIN serves the phone app, and until the root installer is wired its trust port refuses: setup does not complete', async (t) => {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  mkdirSync(stateDir);
  const socket = join(dir, 'http.sock');
  const core = startNode(t, [new URL('../src/main-core.ts', import.meta.url).pathname], dir, { KB_STATE_DIR: stateDir, KB_SOCKET: socket, KB_DOMAIN: 'box.example' });
  await core.ready('keybox core listening');
  const driver = drive(socket);
  const call = (path: string, body?: unknown) =>
    driver.request({ path, method: body === undefined ? 'GET' : 'POST', headers: { 'x-kb-client-ip': '203.0.113.9', ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  assert.equal((await call('/setup')).status, 200);
  assert.equal((await call('/app/push-key')).status, 200);
  const nonceReply = await call('/app/nonce?purpose=register');
  assert.equal(nonceReply.status, 200, nonceReply.body);
  const n = Uint8Array.from(Buffer.from((nonceReply.json() as { nonce_b64: string }).nonce_b64, 'base64url'));
  const owner = softApprover();
  const reply = await call('/setup', { code: 'abandon '.repeat(11) + 'about', approver: newApproverBody(owner), proof: wire(n, owner.prove(challenges.register(n), RP)), phrase: 'p' });
  assert.equal(reply.status, 403, reply.body);
  assert.equal((await call('/setup')).status, 200, 'still no approver');
  const exit = await core.stop();
  assert.equal(exit.status, 0, exit.stderr);
});

test('KBOX-49 the running core without KB_DOMAIN serves the machine API only: no phone route answers', async (t) => {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  mkdirSync(stateDir);
  const socket = join(dir, 'http.sock');
  const core = startNode(t, [new URL('../src/main-core.ts', import.meta.url).pathname], dir, { KB_STATE_DIR: stateDir, KB_SOCKET: socket });
  await core.ready('keybox core listening');
  const reply = await drive(socket).request({ path: '/setup', method: 'GET', headers: { 'x-kb-client-ip': '203.0.113.9' } });
  assert.equal(reply.status, 404);
  const exit = await core.stop();
  assert.equal(exit.status, 0, exit.stderr);
  assert.match(exit.stderr, /keybox core: no_domain/);
});

test('KBOX-9 the phone page builds the denial challenge the box checks, and it differs from the approval challenge over the same approval, digest and nonce', async () => {
  const client = await import('../src/web/webauthn-client.js');
  const nonce = Uint8Array.from({ length: 32 }, (_, i) => i * 5);
  const digest = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
  const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex');
  const denial = hexOf(await client.denialChallenge('apr_AAAAAAAAAAAAAAAA', digest, nonce));
  assert.equal(denial, hexOf(challenges.denial('apr_AAAAAAAAAAAAAAAA', digest, nonce)));
  assert.notEqual(denial, hexOf(challenges.approval('apr_AAAAAAAAAAAAAAAA', digest, nonce)));
});

test('KBOX-12 the queue shows the viewing approver\'s own phrase, in a view session only; without one the phrase is nowhere in the answer', async (t) => {
  const w = await approveWorld(t);
  const shown = async (approver = w.owner): Promise<unknown> => ((await w.call('/app/queue', { cookie: await w.view(approver) })).json() as { phrase?: unknown }).phrase;
  assert.equal(await shown(), 'blue kettle');
  const bare = await w.call('/app/queue');
  assert.equal(bare.status, 401);
  assert.equal(bare.body.includes('blue kettle'), false);
  const opened = await w.call('/app/propose-approver-add', { method: 'POST', cookie: await w.view() });
  // FORCED-FLIP: as of the spec revision 4 the code comes first, the new phone registers, then the box's approver_add is approved.
  const code = (opened.json() as { registration_code: string }).registration_code;
  const second = softApprover();
  assert.equal((await registerAt(w, '/recover/register', code, second, 'green lantern')).status, 201);
  const item = (await w.queue()).find((q) => q.kind === 'approver_add');
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item))).status, 200);
  assert.equal(await shown(second), 'green lantern', 'each approver sees the phrase it typed');
  assert.equal(await shown(), 'blue kettle', 'and the first still sees its own');
});
