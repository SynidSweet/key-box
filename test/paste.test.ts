// KBOX-12: the phone paste flow. The paste, with its passkey assertion and device-key signature over the paste challenge, IS the approval of one
// action. Real core, real approver proofs; the paste platform's verifier accepts only the values a test names.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { bytesOf, canary } from './kit/index.ts';
import { PASTE_PLATFORM, pasteValue, routesWorld } from './support/routes-world.ts';
import type { PasteView, RoutesWorld } from './support/routes-world.ts';

const DAY = 24 * 3600_000;
const HEX = 'a'.repeat(32);
const KEYREF = `${PASTE_PLATFORM}/shop/ANTHROPIC_KEY`;
const add = (scope: string[] = ['admin']) => ({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', projects: ['shop'], scope: { items: scope } });

async function openTask(w: RoutesWorld, body: object = add()): Promise<string> {
  const reply = await w.api('/api/keys', { json: body });
  assert.equal(reply.status, 202, reply.body);
  return (reply.json() as { paste_task_id: string }).paste_task_id;
}
const render = async (w: RoutesWorld, id: string, cookie?: string) => {
  const c = cookie ?? (await w.view());
  const reply = await w.call(`/p/${id}`, { cookie: c });
  assert.equal(reply.status, 200, reply.body);
  return { view: reply.json() as PasteView & { phrase: string; lines: string[]; platform_link?: string }, cookie: c, body: reply.body };
};
const submit = (w: RoutesWorld, id: string, cookie: string | undefined, value: string, proof: unknown) => w.call(`/p/${id}`, { json: { value, proof }, ...(cookie === undefined ? {} : { cookie }) });
/** The pushes about a task: a token's first use from a new network also pushes, and is not one. */
const pastePushes = (w: RoutesWorld) => w.push.sent.filter((p) => p.kind !== 'new_network');
const nothingStored =(w: RoutesWorld): void => {
  assert.equal(w.rotation.store.key(KEYREF), undefined, 'no key row');
  assert.throws(() => w.parts.vault.lend(KEYREF, 1), 'no value in the vault');
};

test('KBOX-12 a paste without the device signature is refused and stores nothing', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, cookie } = await render(w, id);
  w.accepted.add(pasteValue(HEX));
  const proof = { ...w.pasteProof(view), device_signature: Buffer.alloc(64).toString('base64url') };
  assert.equal((await submit(w, id, cookie, pasteValue(HEX), proof)).status, 403);
  nothingStored(w);
  assert.equal((await w.call(`/p/${id}`, { cookie })).status, 200, 'the task is still pending');
});

test('KBOX-12 an assertion for another paste id is refused and stores nothing', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, cookie } = await render(w, id);
  w.accepted.add(pasteValue(HEX));
  assert.equal((await submit(w, id, cookie, pasteValue(HEX), w.pasteProof(view, 'apr_AAAAAAAAAAAAAAAA'))).status, 403);
  nothingStored(w);
});

test('KBOX-12 a reused nonce is refused: the first attempt failed its value check and still spent it', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, cookie } = await render(w, id);
  const proof = w.pasteProof(view);
  assert.equal((await submit(w, id, cookie, 'pk-short', proof)).status, 422);
  w.accepted.add(pasteValue(HEX));
  assert.equal((await submit(w, id, cookie, pasteValue(HEX), proof)).status, 403, 'the same proof, the same nonce');
  nothingStored(w);
});

test('KBOX-12 a paste without a view session is refused and stores nothing, and the page shows no phrase without one', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, cookie } = await render(w, id);
  assert.match(await bodyOf(w, id, cookie), /blue kettle/, 'with a view session the page shows the owner phrase');
  w.accepted.add(pasteValue(HEX));
  const refused = await submit(w, id, undefined, pasteValue(HEX), w.pasteProof(view));
  assert.equal(refused.status, 401);
  const bare = await w.call(`/p/${id}`);
  assert.equal(bare.status, 401);
  assert.equal(`${refused.body}${bare.body}`.includes('blue kettle'), false, 'the phrase is in no response made without a view session');
  nothingStored(w);
});
const bodyOf = async (w: RoutesWorld, id: string, cookie: string): Promise<string> => (await w.call(`/p/${id}`, { cookie })).body;

const REPLACEMENTS: readonly (readonly [name: string, replace: (w: RoutesWorld) => unknown])[] = [
  ['a wider scope', (w) => w.api('/api/keys', { json: add(['admin', 'wider']) })],
  ['another name', (w) => w.api('/api/keys', { json: { ...add(), name: 'OTHER_KEY' } })],
  ['mark_admin added', (w) => w.rotation.paste.open({ action: { kind: 'add_key', platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', projects: ['shop'], scope: { items: ['admin'] }, mark_admin: true }, requester: { kind: 'token', label: 'mission-control' } })],
];

for (const [name, replace] of REPLACEMENTS) {
  test(`KBOX-12 an action replaced between render and POST (${name}) refuses the old page's paste and stores nothing; a new render works`, async (t) => {
    const w = await routesWorld(t);
    const id = await openTask(w);
    const old = await render(w, id);
    w.accepted.add(pasteValue(HEX));
    const oldProof = w.pasteProof(old.view);
    await replace(w);
    assert.equal((await submit(w, id, old.cookie, pasteValue(HEX), oldProof)).status, 403, 'the digest and nonce of the old render no longer apply');
    nothingStored(w);
    assert.equal(w.rotation.store.key(`${PASTE_PLATFORM}/shop/OTHER_KEY`), undefined);
    const fresh = await render(w, id, old.cookie);
    assert.notEqual(fresh.view.digest_b64 + fresh.view.nonce_b64, old.view.digest_b64 + old.view.nonce_b64);
    assert.equal((await submit(w, id, old.cookie, pasteValue(HEX), w.pasteProof(fresh.view))).status, 201);
  });
}

test('KBOX-12 a 15-byte value is refused, and a 16-byte value with a failing shape is refused; the task stays and the retry works', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  for (const [value, why] of [
    [`pk-${'a'.repeat(12)}`, 'too_short'],
    [`pk-${'a'.repeat(13)}`, 'bad_shape'],
    [`pk-${'g'.repeat(32)}`, 'bad_shape'],
    [`xx-${HEX}`, 'bad_shape'],
    [`${pasteValue(HEX)}\n`, 'bad_shape'],
  ] as const) {
    const { view, cookie } = await render(w, id);
    w.accepted.add(value);
    const reply = await submit(w, id, cookie, value, w.pasteProof(view));
    assert.equal(reply.status, 422, value);
    assert.equal((reply.json() as { error: { detail: { code: string } } }).error.detail.code, why);
    assert.equal(reply.body.includes(value.trim()), false, 'the refusal never echoes the value');
  }
  nothingStored(w);
  const { view, cookie } = await render(w, id);
  w.accepted.add(pasteValue(HEX));
  assert.equal((await submit(w, id, cookie, pasteValue(HEX), w.pasteProof(view))).status, 201);
});

test('KBOX-12 a value the platform verifier rejects is refused with its names-only reason and stores nothing', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, cookie } = await render(w, id);
  const reply = await submit(w, id, cookie, pasteValue(HEX), w.pasteProof(view));
  assert.equal(reply.status, 422);
  assert.equal((reply.json() as { error: { detail: { code: string } } }).error.detail.code, 'verifier_rejected');
  nothingStored(w);
});

test('KBOX-12 and KBOX-2 a good value is stored, verified and settles the task as an approval; the canary is absent from every response and surface', async (t) => {
  const w = await routesWorld(t);
  const c = canary(16);
  const value = pasteValue(Buffer.from(c.bytes).toString('hex'));
  w.accepted.add(value);
  const id = await openTask(w);
  const { view, cookie, body: viewBody } = await render(w, id);
  const stored = await submit(w, id, cookie, value, w.pasteProof(view));
  assert.equal(stored.status, 201);
  assert.deepEqual(stored.json(), { status: 'stored', keyref: KEYREF });
  assert.equal(Buffer.from(await bytesOf(w.parts.vault.lend(KEYREF, 1))).toString('utf8'), value, 'the vault holds it');
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.class, 'admin');
  assert.equal((await w.call(`/p/${id}`, { cookie })).status, 404, 'the task is settled');
  assert.equal(w.parts.meta.snapshot().approvals.length, 0, 'no approval row: the paste was the approval');
  const decided = w.parts.events.after(0).filter((e) => e.kind === 'approval.decided');
  assert.deepEqual(decided.map((e) => [e.data['approval_id'], e.data['decision']]), [[id, 'approved']]);
  const files = ['meta.db', 'meta.db-wal'].flatMap((f) => {
    try {
      return [readFileSync(join(w.stateDir, f))];
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') return [];
      throw error;
    }
  });
  c.assertAbsent({
    'paste response': stored.body,
    'task page': viewBody,
    'refused-value page': (await w.call(`/p/${id}`, { cookie })).body,
    queue: JSON.stringify(await w.queue()),
    events: JSON.stringify(w.parts.events.after(0)),
    audit: JSON.stringify(w.parts.audit.read(0).entries),
    push: JSON.stringify(w.push.sent),
    journal: w.journal.join('\n'),
    ...Object.fromEntries(files.map((f, i) => [`database file ${i}`, f])),
  });
});

test('KBOX-12 no response of the paste flow holds a URL to the box; the page carries the adapter link and the fixed rule', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const { view, body } = await render(w, id);
  assert.equal(/box\.example|keys\.box/.test(body), false);
  assert.equal(view.platform_link, 'https://platform.example/keys');
  assert.ok(view.lines.includes('Only paste where you see your phrase.'));
  const words = view.lines.join('\n');
  for (const named of [PASTE_PLATFORM, 'ANTHROPIC_KEY', 'shop', 'Scope: admin', 'mission-control']) assert.ok(words.includes(named), `the page names ${named}`);
  const listed = await w.call('/app/pastes', { cookie: await w.view() });
  assert.deepEqual((listed.json() as { pastes: { paste_id: string }[] }).pastes.map((p) => p.paste_id), [id]);
  assert.equal(pastePushes(w).length, 1, 'one push for the task');
  assert.equal(pastePushes(w)[0]?.kind, 'add_key');
  assert.equal(JSON.stringify(w.push.sent).includes('http'), false);
});

test('KBOX-7 a paste task sits in the add_key slot: another token is refused naming it, the same token replaces it with no second push, and it expires at 14 days', async (t) => {
  const w = await routesWorld(t);
  const id = await openTask(w);
  const other = await w.call('/api/keys', { token: w.token('other-control', 'control'), json: add(['admin', 'x']) });
  assert.equal(other.status, 409);
  assert.deepEqual((other.json() as { error: { detail: unknown } }).error.detail, { pending_approval_id: id });
  const again = await w.api('/api/keys', { json: add(['admin', 'y']) });
  assert.equal((again.json() as { paste_task_id: string }).paste_task_id, id);
  assert.equal(pastePushes(w).length, 1);
  w.clock.advance(14 * DAY - 1);
  assert.equal((await w.call(`/p/${id}`, { cookie: await w.view() })).status, 200, 'still there at 14 days minus 1 ms');
  w.clock.advance(1);
  assert.equal((await w.call(`/p/${id}`, { cookie: await w.view() })).status, 404, 'expired at 14 days');
  assert.equal(w.parts.events.after(0).filter((e) => e.kind === 'approval.decided' && e.data['decision'] === 'expired').length, 1);
});

test('KBOX-12 pasting a new value for an admin key rotates it: the paste is the approval, the new value is a new generation, and the old one is retired once the platform rejects it', async (t) => {
  const w = await routesWorld(t);
  const first = pasteValue('1'.repeat(32));
  const second = pasteValue('2'.repeat(32));
  w.accepted.add(first);
  const addId = await openTask(w);
  const a = await render(w, addId);
  assert.equal((await submit(w, addId, a.cookie, first, w.pasteProof(a.view))).status, 201);
  const rotation = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(rotation.status, 202);
  const rotId = (rotation.json() as { paste_task_id: string }).paste_task_id;
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status, 'awaiting_paste');
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined, 'nothing runs before the paste');
  w.accepted.add(second);
  const r = await render(w, rotId, a.cookie);
  assert.equal((await submit(w, rotId, a.cookie, second, w.pasteProof(r.view))).status, 201);
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.gen(KEYREF, 2)?.status, 'current');
  assert.equal(w.rotation.store.gen(KEYREF, 1)?.status, 'grace');
  assert.equal(Buffer.from(await bytesOf(w.parts.vault.lend(KEYREF, 2))).toString('utf8'), second);
  w.clock.advance(60 * 60_000);
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.gen(KEYREF, 1)?.status, 'grace', 'the platform still accepts the old value: the box cannot revoke a pasted key, so it is not retired');
  w.accepted.delete(first);
  w.clock.advance(60 * 60_000);
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.gen(KEYREF, 1)?.status, 'retired');
});

test('KBOX-12 the paste page keeps the field when the box refuses, and empties it only after the key is stored', () => {
  const source = readFileSync(new URL('../src/web/paste.js', import.meta.url), 'utf8').split('\n');
  const assigns = source.map((line, i) => [i, line] as const).filter(([, line]) => /byId\('value'\)\.value\s*=[^=]/.test(line));
  assert.equal(assigns.length, 1, 'the field is written in one place');
  const sendCall = source.findIndex((line) => line.includes('await call(`/p/'));
  assert.ok(sendCall >= 0 && (assigns[0]?.[0] ?? -1) > sendCall, 'only after the call that the box answered');
  assert.match(assigns[0]?.[1] ?? '', /=\s*''/);
});
