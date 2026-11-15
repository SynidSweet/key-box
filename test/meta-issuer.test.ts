// KBOX-30, design 3.3b: GET /api/meta shows box.oidc_issuer = https://<host>, derived from the box's domain (never stored).
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { openCore } from '../src/shell/core.ts';
import { createApiServer } from '../src/shell/http.ts';
import { drive } from './kit/drive.ts';
import { seededRandom } from './kit/random.ts';
import { tempDir } from './kit/temp.ts';
import { TimedClock } from './kit/timed-clock.ts';

async function metaBox(t: TestContext, domain: string | undefined): Promise<Record<string, unknown>> {
  const dir = await tempDir(t);
  const clock = new TimedClock(1_000_000);
  const random = seededRandom(5);
  const parts = openCore({ stateDir: join(dir, 'state'), clock, scheduler: clock, random, ...(domain === undefined ? {} : { domain }) });
  const token = newToken(random);
  parts.meta.addMachine({ label: 'ctl-1', scope: 'control', tokenSha256: hashToken(token), enrolledAt: 1 });
  const server = createApiServer({ routes: [...parts.routes], tokens: parts.meta, audit: parts.audit, random, clock, journal: () => undefined });
  const socket = join(dir, 'http.sock');
  await server.listen(socket);
  t.after(async () => {
    await server.stop();
    parts.close();
  });
  const reply = await drive(socket).request({ path: '/api/meta', method: 'GET', headers: { authorization: `Bearer ${token}`, 'x-kb-client-ip': '203.0.113.9' } });
  assert.equal(reply.status, 200);
  return (reply.json() as { box: Record<string, unknown> }).box;
}

test('KBOX-30 GET /api/meta gives box.oidc_issuer as https://<host> for the box opened with that host', async (t) => {
  assert.equal((await metaBox(t, 'box.example.net'))['oidc_issuer'], 'https://box.example.net');
});

test('KBOX-30 GET /api/meta gives a null box.oidc_issuer when the box has no domain', async (t) => {
  assert.equal((await metaBox(t, undefined))['oidc_issuer'], null);
});
