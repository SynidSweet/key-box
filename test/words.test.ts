// KBOX-8: the box writes the words. A table renders every action kind from a fixture and compares with the fixed sentences;
// the reason is set apart as inert text; every page names the requesting token; the titles (push and meta use them) are pinned.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ACTION_KINDS, parseAction } from '../src/pure/actions.ts';
import type { Action } from '../src/pure/actions.ts';
import { actionDigest } from '../src/pure/challenge.ts';
import { renderPage } from '../src/pure/words.ts';

const H = (c: string): string => c.repeat(64);
const NO_COVERAGE = 'This key has no watch coverage: a stray copy of it on your computer would not be noticed.';
const BY_TOKEN = 'Asked for by the machine token ctl-1.';

/** Each kind: a fixture, its pinned title, and its fixed sentences (before the requester line). */
const TABLE: readonly [fixture: Record<string, unknown>, title: string, sentences: readonly string[]][] = [
  [{ kind: 'add_key', platform: 'openai', name: 'OPENAI_API_KEY', projects: ['shop', 'blog'], scope: { items: ['model.request'] } }, 'Add a key on openai: OPENAI_API_KEY', ['Add the openai key OPENAI_API_KEY for shop, blog.', 'Scope: model.request.']],
  [{ kind: 'delete_key', keyref: 'openai-admin' }, 'Delete the key openai-admin', ['Delete the key openai-admin at its platform.']],
  [{ kind: 'rotate_key', keyref: 'openai-admin' }, 'Change the key openai-admin', ['Change the key openai-admin for a new one.']],
  [{ kind: 'grant', keyref: 'openai-admin', machine: 'ws-1' }, 'Let ws-1 use openai-admin', ['Let the machine ws-1 use the key openai-admin.']],
  [{ kind: 'revoke_grant', keyref: 'openai-admin', machine: 'ws-1' }, 'Stop ws-1 using openai-admin', ['Stop the machine ws-1 from using the key openai-admin.']],
  [{ kind: 'add_destination', keyref: 'stripe', destination: { kind: 'vercel_env', target: 'prj_1', environments: ['production'] } }, 'Add a place for stripe', ['Put the key stripe into the Vercel environment variable prj_1 (production).']],
  [{ kind: 'remove_destination', keyref: 'stripe', destination: { kind: 'workstation', target: '' } }, 'Remove a place of stripe', ['Take the key stripe out of your computer.']],
  [{ kind: 'set_allow_rules', keyref: 'gcp', rules: [{ op: 'fs_doc', params: { project: 'p1' } }, { op: 'gcs_list', params: {} }] }, 'Change what gcp may be used for', ['Let the relay pass only these requests with the key gcp:', 'fs_doc (project = p1)', 'gcs_list']],
  [{ kind: 'set_schedule', keyref: 'stripe', rotate_every_days: 30, grace_hours: 24 }, 'Change the schedule of stripe', ['Change the key stripe every 30 days, and switch the old one off 24 hours later.']],
  [{ kind: 'demote', keyref: 'stripe' }, 'Lower the class of stripe', ['Lower the class of the key stripe, so it changes without asking you.']],
  [{ kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'shop.example.com' }, 'Vercel domain change on shop', ['Add the domain shop.example.com to the Vercel project shop.']],
  [{ kind: 'vercel_set_team_setting', setting: 'sensitive', value: 'on' }, 'Vercel team setting sensitive', ['Set the Vercel team setting sensitive to "on".']],
  // FORCED-FLIP: as of the spec revision 4 approver_add names the new keys by hash and its page carries the fingerprint line.
  [{ kind: 'approver_add', cose_sha256: H('e'), device_sha256: H('f') }, 'Add an approver', ['Add another approver: a new phone with its own passkey and device key.', 'The new phone\'s fingerprint could not be made here: do not approve.']],
  [{ kind: 'approver_remove', approver_id: 'ap-AAAAAAAAAA' }, 'Remove an approver', ['Remove the approver ap-AAAAAAAAAA.']],
  [
    { kind: 'install_update', install: H('a'), commit: 'b'.repeat(40), base: H('c') },
    'Install key box version aaaaaaaaaaaa',
    [
      'Install key box version aaaaaaaaaaaa (commit bbbbbbbbbbbb) over version cccccccccccc',
      'Agents wrote this version and only agents checked it. Any change can take every key, and this page cannot tell whether it is safe.',
      'These limits do not stop an approved update that is malicious.',
    ],
  ],
  [{ kind: 'enrol', label: 'laptop', token_sha256: H('d'), address: '198.51.100.7' }, 'Enrol a machine for relay', ['enrol laptop for relay (request seen from 198.51.100.7; the label and the address are not checked)']],
];

const action = (fixture: Record<string, unknown>): Action => {
  const parsed = parseAction(fixture);
  assert.ok(parsed.ok, JSON.stringify(fixture));
  return parsed.value;
};

test('KBOX-8 the table covers every action kind exactly once', () => {
  assert.deepEqual(TABLE.map(([f]) => f['kind']).sort(), [...ACTION_KINDS].sort());
});

test('KBOX-8 every kind renders its pinned title and its fixed sentences, then names the requesting token', () => {
  for (const [fixture, title, sentences] of TABLE) {
    const page = renderPage(action(fixture), { requester: { kind: 'token', label: 'ctl-1' } });
    assert.equal(page.title, title, String(fixture['kind']));
    assert.deepEqual(page.lines, [...sentences, BY_TOKEN], String(fixture['kind']));
  }
});

test('KBOX-8 the other domain moves are stated in the box\'s words', () => {
  const remove = renderPage(action({ kind: 'vercel_set_domain', project: 'shop', op: 'remove', domain: 'a.example.com' }), { requester: { kind: 'box' } });
  assert.equal(remove.lines[0], 'Remove the domain a.example.com from the Vercel project shop.');
  const move = renderPage(action({ kind: 'vercel_set_domain', project: 'shop', op: 'move', domain: 'a.example.com', to_project: 'blog' }), { requester: { kind: 'box' } });
  assert.equal(move.lines[0], 'Move the domain a.example.com from the Vercel project shop to blog.');
  assert.equal(move.lines[1], 'Asked for by the box itself (a schedule or a platform expiry).');
});

test('KBOX-8 KBOX-57 an add_key page names the location in the box\'s words, each field it names, after the scope', () => {
  const base = { kind: 'add_key', platform: 'supabase', name: 'SUPABASE_KEY', projects: ['shop'], scope: { items: [] } };
  const both = renderPage(action({ ...base, location: { region: 'us', project: 'abcdefghijabcdefghij' } }), { requester: { kind: 'box' } });
  assert.deepEqual(both.lines.slice(0, 3), ['Add the supabase key SUPABASE_KEY for shop.', 'Scope: none.', 'Where the platform holds it: region us, project abcdefghijabcdefghij.']);
  const one = renderPage(action({ ...base, location: { project: 'abcdefghijabcdefghij' } }), { requester: { kind: 'box' } });
  assert.equal(one.lines[2], 'Where the platform holds it: project abcdefghijabcdefghij.');
});

test('KBOX-9 KBOX-57 the location is inside the action digest: the same add_key at another location has another digest', () => {
  const base = { kind: 'add_key', platform: 'supabase', name: 'SUPABASE_KEY', projects: ['shop'], scope: { items: [] } };
  const here = actionDigest(action({ ...base, location: { project: 'abcdefghijabcdefghij' } }));
  assert.notDeepEqual(here, actionDigest(action({ ...base, location: { project: 'zzzzzzzzzzzzzzzzzzzz' } })));
  assert.notDeepEqual(here, actionDigest(action(base)));
});

test('KBOX-8 a reason with markup, a link and a canary is one separate inert line, and the other lines are unchanged', () => {
  const canary = 'CANARY-7f3a9c';
  const text = `<script>alert(1)</script> see https://evil.example/x?k=1 [click](javascript:x) ${canary}`;
  for (const [fixture] of TABLE) {
    const a = action(fixture);
    const plain = renderPage(a, { requester: { kind: 'token', label: 'ctl-1' } });
    const withReason = renderPage(a, { requester: { kind: 'token', label: 'ctl-1' }, reason: { agent: 'claude', text } });
    assert.equal(withReason.title, plain.title);
    assert.deepEqual(withReason.lines, [...plain.lines, `Reason given by ctl-1/claude (not checked): ${text}`], String(fixture['kind']));
    assert.equal(withReason.title.includes(canary), false);
  }
});

test('KBOX-8 a page for a key without watch coverage says so; a covered key\'s page does not', () => {
  const a = action({ kind: 'rotate_key', keyref: 'stripe' });
  for (const coverage of ['none', null] as const) assert.ok(renderPage(a, { requester: { kind: 'box' }, coverage }).lines.includes(NO_COVERAGE), String(coverage));
  for (const coverage of ['windowed', 'anchored'] as const) assert.equal(renderPage(a, { requester: { kind: 'box' }, coverage }).lines.includes(NO_COVERAGE), false, coverage);
});

test('KBOX-8 the requester line for the box, an enrol request and an approver', () => {
  const a = action({ kind: 'approver_add', cose_sha256: H('e'), device_sha256: H('f') }); // FORCED-FLIP: as of the spec revision 4
  assert.equal(renderPage(a, { requester: { kind: 'approver', approverId: 'ap-BBBBBBBBBB' } }).lines.at(-1), 'Asked for in the app by the approver ap-BBBBBBBBBB.');
  assert.equal(renderPage(a, { requester: { kind: 'enrol', address: '198.51.100.7' } }).lines.at(-1), 'Asked for by an enrol request that carried no token.');
});

test('KBOX-8 an approver_add the box asks for says a new phone registered with a code from this app, while the generic box sentence stays as it was', () => {
  const add = action({ kind: 'approver_add', cose_sha256: H('e'), device_sha256: H('f') });
  const page = renderPage(add, { requester: { kind: 'box' }, fingerprint: 'option busy together cheese describe match' });
  assert.ok(page.lines.includes('Asked for by the box because a new phone registered with a code from this app.'), page.lines.join(' | '));
  assert.ok(!page.lines.some((l) => l.includes('a schedule or a platform expiry')));
  const other = renderPage(action({ kind: 'demote', keyref: 'stripe' }), { requester: { kind: 'box' } });
  assert.ok(other.lines.includes('Asked for by the box itself (a schedule or a platform expiry).'));
});

test('KBOX-8 an approver_add page hands the six words over as data beside the line that names them, and none when they could not be made', () => {
  const add = action({ kind: 'approver_add', cose_sha256: H('e'), device_sha256: H('f') });
  const words = 'option busy together cheese describe match';
  const page = renderPage(add, { requester: { kind: 'box' }, fingerprint: words });
  assert.equal(page.fingerprint?.words, words);
  assert.equal(page.fingerprint?.label, 'Compare with the new phone');
  assert.equal(page.lines[page.fingerprint?.at ?? -1], `Compare with the new phone: ${words}`, 'the line it stands for');
  assert.equal(renderPage(add, { requester: { kind: 'box' } }).fingerprint, undefined);
});

const BOX = { requester: { kind: 'box' } } as const;

test('KBOX-60 a set_schedule page adds the apps line only for grace 0 on a key an app holds; any other schedule or key keeps the one sentence', () => {
  const noGrace = action({ kind: 'set_schedule', keyref: 'stripe', rotate_every_days: 30, grace_hours: 0 });
  const withGrace = action({ kind: 'set_schedule', keyref: 'stripe', rotate_every_days: 30, grace_hours: 1 });
  const apps = 'Apps still holding the old key fail until they redeploy.';
  assert.deepEqual(renderPage(noGrace, { ...BOX, runtimeDestination: true }).lines.slice(0, 2), ['Change the key stripe every 30 days, and switch the old one off 0 hours later.', apps]);
  assert.equal(renderPage(noGrace, BOX).lines.includes(apps), false, 'no runtime destination');
  assert.equal(renderPage(withGrace, { ...BOX, runtimeDestination: true }).lines.includes(apps), false, 'a grace is given');
});

test('KBOX-60 a demote page says what the fall to ordinary ends, and that a master stays admin; with no class told it keeps the one sentence', () => {
  const page = (fallsTo?: 'ordinary' | 'admin' | 'master') => renderPage(action({ kind: 'demote', keyref: 'stripe' }), { ...BOX, ...(fallsTo === undefined ? {} : { fallsTo }) }).lines.slice(0, -1);
  const lower = 'Lower the class of the key stripe, so it changes without asking you.';
  assert.deepEqual(page('ordinary'), [lower, 'Machines granted it lose relay use, and the leak check on your workstations stops looking for its value. Its allow rules are kept.']);
  assert.deepEqual(page('admin'), [lower, 'It stays an admin key.']);
  assert.deepEqual(page(), [lower]);
});
