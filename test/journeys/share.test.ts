// J6 (KBOX-33, KBOX-18, KBOX-31): a share file written over the real metadata and vault, announced on the event stream, fetched
// over the machine API and read by the reference matcher. A key that is added, rotated and retired moves the file's version.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { KeyRow } from '../../src/ports/meta.ts';
import type { KeyShape } from '../../src/ports/types.ts';
import { createMetaShareSource } from '../../src/shell/share-source.ts';
import { openShare } from '../kit/reference-matcher.ts';
import { base64Document, fakeKey, rawDocument } from '../kit/share-store.ts';
import { seededRandom } from '../kit/index.ts';
import { shareWorld } from '../support/share-world.ts';

const rng = seededRandom(66);

const shape = (length: number): KeyShape => ({ prefix: null, alphabet: 'base62', coreLength: { min: length, max: length }, random: true });
const SHAPES: Readonly<Record<string, KeyShape>> = { openai: shape(48), supabase: { ...shape(40), prefix: 'sb_secret_' } };

const row = (keyref: string, platform: string, name: string, keyClass: KeyRow['class'], gen: number, projects: readonly string[] = ['shop']): KeyRow => ({
  keyref,
  platform,
  name,
  projects,
  class: keyClass,
  status: 'works',
  gen_current: gen,
  schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

test('J6 a share file is written at start, announced, fetched over the machine API and read by the reference matcher; a rotation gives a new version that finds the new value', async (t) => {
  const first = fakeKey(rng, 'OPENAI_ADMIN_KEY', 48);
  const secret = fakeKey(rng, 'SUPABASE_SERVICE', 40, { prefix: 'sb_secret_' });
  const ordinary = fakeKey(rng, 'OPENAI_API_KEY', 48);
  const w = await shareWorld(t, {
    noStart: true,
    source: (core) => createMetaShareSource({ meta: core.meta, values: core.share.values, shapeOf: (platform) => SHAPES[platform] }),
  });
  const { core } = w;
  const put = (keyref: string, gen: number, value: string): void => core.vault.put(keyref, gen, Buffer.from(value));
  put('openai/admin', 1, first.value);
  core.meta.putKey(row('openai/admin', 'openai', 'OPENAI_ADMIN_KEY', 'admin', 1));
  put('supabase/service', 1, secret.value);
  core.meta.putKey(row('supabase/service', 'supabase', 'SUPABASE_SERVICE', 'master', 1));
  put('openai/ordinary', 1, ordinary.value);
  core.meta.putKey(row('openai/ordinary', 'openai', 'OPENAI_API_KEY', 'ordinary', 1));
  core.meta.putKey(row('paste/unknown', 'pasteonly', 'PASTE_ADMIN_KEY', 'admin', 1));
  await w.writer.start();

  const control = core.enrol('mc', 'control');
  const meta = (await core.call('/api/meta', { token: control })).json() as { box: { share_version: number; share_public_key_ed25519_b64: string } };
  assert.equal(meta.box.share_version, 1);
  const events = (await core.call('/api/events?since=0', { token: control })).json() as { events: { kind: string; data: { version?: number } }[] };
  assert.deepEqual(events.events.filter((e) => e.kind === 'share.version').map((e) => e.data.version), [1]);

  const fetched = await core.call('/api/share', { token: control });
  assert.equal(fetched.status, 200);
  assert.equal(fetched.headers['kb-share-version'], '1');
  const opened = openShare(Buffer.from(fetched.body), meta.box.share_public_key_ed25519_b64);
  assert.ok(opened.ok);
  const names = (content: Uint8Array): string[] => [...new Set(opened.share.scan(content).map((f) => f.name))];
  assert.deepEqual(names(rawDocument(first.value)), ['OPENAI_ADMIN_KEY']);
  assert.deepEqual(names(base64Document(secret.value, 1, true, { columns: 76, lineBreak: '\r\n' })), ['SUPABASE_SERVICE']);
  assert.deepEqual(names(rawDocument(ordinary.value)), [], 'an ordinary key is not in the file');
  const body = JSON.parse(Buffer.from((JSON.parse(fetched.body) as { body_b64: string }).body_b64, 'base64').toString('utf8')) as { coverage: { name: string; tier: string }[] };
  assert.deepEqual(
    body.coverage.map((c) => `${c.name}:${c.tier}`).sort(),
    ['OPENAI_ADMIN_KEY:windowed', 'PASTE_ADMIN_KEY:none', 'SUPABASE_SERVICE:windowed'],
    'every admin and master key is listed; one with no shape or no value is explicitly not watched',
  );

  // The rotation: a new generation in the vault and the key row at generation 2.
  const second = fakeKey(rng, 'OPENAI_ADMIN_KEY', 48);
  put('openai/admin', 2, second.value);
  core.meta.putKey(row('openai/admin', 'openai', 'OPENAI_ADMIN_KEY', 'admin', 2));
  await w.writer.idle();
  const next = await core.call('/api/share', { token: control });
  assert.equal(next.headers['kb-share-version'], '2');
  const reopened = openShare(Buffer.from(next.body), meta.box.share_public_key_ed25519_b64, { lastVersion: 1 });
  assert.ok(reopened.ok);
  assert.deepEqual([...new Set(reopened.share.scan(rawDocument(second.value)).map((f) => f.name))], ['OPENAI_ADMIN_KEY']);
  const events2 = (await core.call('/api/events?since=0', { token: control })).json() as { events: { kind: string }[] };
  assert.equal(events2.events.filter((e) => e.kind === 'share.version').length, 2, 'one share.version per version');
});

test('J6 a key with several projects has an entry set per project, and a key with none is listed under one placeholder', async (t) => {
  const key = fakeKey(rng, 'OPENAI_ADMIN_KEY', 48);
  const w = await shareWorld(t, {
    noStart: true,
    source: (core) => createMetaShareSource({ meta: core.meta, values: core.share.values, shapeOf: (platform) => SHAPES[platform] }),
  });
  w.core.vault.put('openai/admin', 1, Buffer.from(key.value));
  w.core.meta.putKey(row('openai/admin', 'openai', 'OPENAI_ADMIN_KEY', 'admin', 1, ['shop', 'site']));
  w.core.vault.put('openai/bare', 1, Buffer.from(key.value));
  w.core.meta.putKey(row('openai/bare', 'openai', 'OPENAI_BARE_KEY', 'admin', 1, []));
  await w.writer.start();
  const body = JSON.parse(Buffer.from((JSON.parse((await w.core.call('/api/share', { token: w.core.enrol('mc', 'control') })).body) as { body_b64: string }).body_b64, 'base64').toString('utf8')) as {
    coverage: { project: string; name: string; tier: string }[];
  };
  assert.deepEqual(
    body.coverage.map((c) => `${c.project}/${c.name}/${c.tier}`),
    ['-/OPENAI_BARE_KEY/windowed', 'shop/OPENAI_ADMIN_KEY/windowed', 'site/OPENAI_ADMIN_KEY/windowed'],
  );
});

test('J6 a vault value that is not UTF-8 text, or is missing, is not watched and does not stop the file', async (t) => {
  const w = await shareWorld(t, {
    noStart: true,
    source: (core) => createMetaShareSource({ meta: core.meta, values: core.share.values, shapeOf: (platform) => SHAPES[platform] }),
  });
  w.core.vault.put('openai/binary', 1, Uint8Array.from([0xff, 0xfe, 0x00, 0x80]));
  w.core.meta.putKey(row('openai/binary', 'openai', 'OPENAI_BINARY_KEY', 'admin', 1));
  w.core.meta.putKey(row('openai/missing', 'openai', 'OPENAI_MISSING_KEY', 'admin', 1));
  await w.writer.start();
  const body = JSON.parse(Buffer.from((JSON.parse((await w.core.call('/api/share', { token: w.core.enrol('mc', 'control') })).body) as { body_b64: string }).body_b64, 'base64').toString('utf8')) as {
    coverage: { name: string; tier: string }[];
    entries: unknown[];
  };
  assert.deepEqual(body.coverage.map((c) => `${c.name}:${c.tier}`), ['OPENAI_BINARY_KEY:none', 'OPENAI_MISSING_KEY:none']);
  assert.equal(body.entries.length, 0);
});
