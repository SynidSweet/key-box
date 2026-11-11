// The kit's own behaviour, tested only where it is tricky (KBOX-35).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import {
  FakeClock,
  canary,
  checkProperty,
  drive,
  fakePlatform,
  seedFor,
  seededRandom,
  softAuthenticator,
  tempDir,
} from './index.ts';

test('KBOX-35 tempDir is removed when the test that asked for it ends', async (t) => {
  let made = '';
  await t.test('inner', async (inner) => {
    made = await tempDir(inner);
    await mkdir(join(made, 'sub'));
    await writeFile(join(made, 'sub', 'a name with spaces and "quotes".txt'), 'x');
    assert.ok(existsSync(made));
  });
  assert.ok(made.length > 0);
  assert.equal(existsSync(made), false);
});

test('KBOX-35 FakeClock only moves when told and refuses to go back', () => {
  const clock = new FakeClock(1000);
  assert.equal(clock.now(), 1000);
  clock.advance(250);
  assert.equal(clock.now(), 1250);
  assert.throws(() => clock.advance(-1), RangeError);
  assert.equal(clock.now(), 1250);
  assert.equal(new FakeClock().now(), 0);
});

test('KBOX-35 seededRandom repeats for one seed and differs for another', () => {
  const a = seededRandom(7);
  const b = seededRandom(7);
  const c = seededRandom(8);
  const fromA = [a.int(1000), a.int(1000), a.int(1000), a.int(1000)];
  assert.deepEqual(fromA, [b.int(1000), b.int(1000), b.int(1000), b.int(1000)]);
  assert.notDeepEqual(fromA, [c.int(1000), c.int(1000), c.int(1000), c.int(1000)]);
  assert.equal(a.seed, 7);
  assert.equal(seededRandom(7).bytes(16).length, 16);
  for (let i = 0; i < 200; i += 1) {
    const n = a.int(5);
    assert.ok(n >= 0 && n < 5);
  }
});

test('KBOX-35 the seed comes from KB_SEED, else is drawn and reported, and a bad KB_SEED is refused', () => {
  const reported: number[] = [];
  assert.equal(seedFor({ KB_SEED: '42' }, () => 1, (s) => reported.push(s)), 42);
  assert.equal(seedFor({}, () => 99, (s) => reported.push(s)), 99);
  assert.deepEqual(reported, [42, 99]);
  for (const bad of ['', 'abc', '-1', '1.5', '4294967296']) {
    assert.throws(() => seedFor({ KB_SEED: bad }, () => 1, () => undefined), /KB_SEED/, bad);
  }
});

test('KBOX-35 a failing property reports its seed and keeps the original failure as the cause', () => {
  const original = new Error('boom');
  assert.throws(
    () =>
      checkProperty(1234, 5, () => {
        throw original;
      }),
    (e: unknown) => e instanceof Error && /seed 1234/.test(e.message) && e.cause === original,
  );
  let runs = 0;
  checkProperty(1, 5, () => {
    runs += 1;
  });
  assert.equal(runs, 5);
});

const FORMS: Record<string, (b: Buffer) => string> = {
  'base64 std': (b) => b.toString('base64'),
  'base64 std unpadded': (b) => b.toString('base64').replace(/=+$/, ''),
  'base64 url': (b) => b.toString('base64url'),
  hex: (b) => b.toString('hex'),
  'hex upper': (b) => b.toString('hex').toUpperCase(),
  percent: (b) => [...b].map((x) => `%${x.toString(16).padStart(2, '0')}`).join(''),
  'u-escaped': (b) => [...b].map((x) => `\\u${x.toString(16).padStart(4, '0')}`).join(''),
  'json-escaped': (b) => JSON.stringify(b.toString('latin1')).slice(1, -1),
};

for (const [form, render] of Object.entries(FORMS)) {
  test(`KBOX-35 assertAbsent finds a planted ${form} copy and names the surface and form, never the bytes`, () => {
    const c = canary();
    const planted = `before ${render(Buffer.from(c.bytes))} after`;
    const clean = 'nothing to see here';
    assert.deepEqual([...new Set(c.findIn({ log: planted, db: clean }).map((h) => h.surface))], ['log']);
    assert.throws(
      () => c.assertAbsent({ log: planted, db: clean }),
      (e: unknown) => {
        const message = e instanceof Error ? e.message : String(e);
        assert.match(message, /log/);
        assert.match(message, new RegExp(form));
        assert.equal(message.includes(render(Buffer.from(c.bytes))), false);
        assert.equal(message.includes(Buffer.from(c.bytes).toString('hex')), false);
        return true;
      },
    );
  });
}

test('KBOX-35 assertAbsent finds the raw bytes in a binary surface and stays clean on a decoy', () => {
  const c = canary();
  const surface = Buffer.concat([Buffer.from('header'), Buffer.from(c.bytes), Buffer.from('tail')]);
  assert.equal(c.findIn({ wal: surface }).length > 0, true);
  const decoy = canary();
  c.assertAbsent({ wal: Buffer.from(decoy.bytes), text: `${decoy.bytes.toString()}`, json: JSON.stringify(decoy) });
  assert.notDeepEqual(Buffer.from(c.bytes), Buffer.from(decoy.bytes));
  assert.equal(c.bytes.length >= 16, true);
});

test('KBOX-35 a failing fakePlatform mode really fails, each in its own way', async (t) => {
  const platform = await fakePlatform(t);
  const get = (path: string, init: RequestInit = {}) => fetch(`${platform.url}${path}`, init);

  const ok = await get('/v1/things');
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { ok: true });

  await platform.setMode('500');
  assert.equal((await get('/v1/things')).status, 500);

  await platform.setMode('401-echo');
  const unauthorised = await get('/v1/things', { headers: { authorization: 'Bearer sentinel-key-value' } });
  assert.equal(unauthorised.status, 401);
  assert.match(await unauthorised.text(), /sentinel-key-value/);

  await platform.setMode('malformed-json');
  const malformed = await get('/v1/things');
  assert.equal(malformed.status, 200);
  await assert.rejects(() => malformed.json(), SyntaxError);

  await platform.setMode('partial-body');
  const partial = await get('/v1/things');
  await assert.rejects(() => partial.text());

  await platform.setMode('redirect');
  const redirected = await get('/v1/things', { redirect: 'manual' });
  assert.equal(redirected.status, 302);
  assert.notEqual(new URL(redirected.headers.get('location') ?? '').hostname, new URL(platform.url).hostname);

  await platform.setMode('hang');
  const controller = new AbortController();
  const hung = get('/v1/things', { signal: controller.signal });
  await platform.nextRequest();
  controller.abort();
  await assert.rejects(() => hung, { name: 'AbortError' });

  await platform.setMode('refuse');
  await assert.rejects(() => get('/v1/things'));
  await platform.setMode('ok');
  assert.equal((await get('/v1/things')).status, 200);
  assert.ok(platform.requests.length >= 8);
});

test('KBOX-35 drive talks to a server on a unix socket and returns status, headers and body', async (t) => {
  const dir = await tempDir(t);
  const socketPath = join(dir, 'http.sock');
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(201, { 'content-type': 'application/json', 'x-seen-method': req.method ?? '' });
      res.end(JSON.stringify({ path: req.url, body: Buffer.concat(chunks).toString() }));
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const reply = await drive(socketPath).request({ method: 'POST', path: '/a b?x=1', body: 'payload' });
  assert.equal(reply.status, 201);
  assert.equal(reply.headers['x-seen-method'], 'POST');
  assert.deepEqual(reply.json(), { path: '/a%20b?x=1', body: 'payload' });
});

test('KBOX-35 softAuthenticator makes assertions and device-key signatures that verify independently', () => {
  const rpId = 'box.example.test';
  const origin = `https://${rpId}`;
  const auth = softAuthenticator();
  const cred = auth.createCredential();
  assert.equal(cred.coseKey[0], 0xa5);
  const challenge = Buffer.from('challenge-bytes-1234567890');

  const first = auth.assert({ rpId, origin, challenge });
  const second = auth.assert({ rpId, origin, challenge });
  assert.deepEqual([...first.authenticatorData.subarray(0, 32)], [...createHash('sha256').update(rpId).digest()]);
  assert.equal(first.authenticatorData.readUInt8(32) & 0x01, 0x01);
  assert.equal(second.authenticatorData.readUInt32BE(33), first.authenticatorData.readUInt32BE(33) + 1);
  const clientData = JSON.parse(first.clientDataJSON.toString()) as { type: string; challenge: string; origin: string };
  assert.deepEqual(clientData, { type: 'webauthn.get', challenge: challenge.toString('base64url'), origin });

  const publicKey = createPublicKey({ key: cred.publicJwk, format: 'jwk' });
  const signed = Buffer.concat([first.authenticatorData, createHash('sha256').update(first.clientDataJSON).digest()]);
  assert.equal(verify('sha256', signed, { key: publicKey, dsaEncoding: 'der' }, first.signature), true);
  assert.equal(verify('sha256', Buffer.concat([signed, Buffer.from('x')]), { key: publicKey, dsaEncoding: 'der' }, first.signature), false);
  assert.ok(Buffer.from(cred.coseKey).includes(Buffer.from(cred.publicJwk.x ?? '', 'base64url')));

  const payload = Buffer.from('payload to sign');
  const deviceSignature = auth.deviceSign(payload);
  const deviceKey = createPublicKey({ key: auth.devicePublicJwk, format: 'jwk' });
  assert.equal(verify('sha256', payload, { key: deviceKey, dsaEncoding: 'der' }, deviceSignature), true);
  assert.equal(verify('sha256', Buffer.from('other'), { key: deviceKey, dsaEncoding: 'der' }, deviceSignature), false);
  assert.notEqual(softAuthenticator().createCredential().publicJwk.x, cred.publicJwk.x);
});
