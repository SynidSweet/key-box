// KBOX-20: recovery of the approver. This file holds the root half (kb-code makes the code, root checks it), the unit text,
// and core's half through the TrustPort. Times come from a FakeClock.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { FakeClock, runNode, seededRandom, tempDir } from './kit/index.ts';
import { directives, words } from './kit/index.ts';
import { codeHash, parseWordlist } from '../src/pure/codes.ts';
import { createCodeRoot } from '../src/shell/console.ts';
import { softApprover } from './kit/approver.ts';
import type { SoftApprover } from './kit/approver.ts';
import { RP, approveWorld, challenges, newApproverBody, registerAt, wire } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';

const WORDLIST = parseWordlist(readFileSync(new URL('../src/data/wordlist.txt', import.meta.url), 'utf8'));
const MINUTE = 60_000;

async function root(t: import('node:test').TestContext, seed = 5) {
  const dir = join(await tempDir(t), 'codes');
  const clock = new FakeClock(1_700_000_000_000);
  const sink: string[] = [];
  const codes = createCodeRoot({ dir, sink: (text) => void sink.push(text), random: seededRandom(seed), clock, wordlist: WORDLIST });
  const lastCode = (): string => {
    const line = sink.at(-1) ?? '';
    const found = /([a-z]+(?: [a-z]+){11})/.exec(line);
    assert.ok(found, 'the sink got a 12-word code');
    return found[1] ?? '';
  };
  return { dir, clock, sink, codes, lastCode };
}

test('KBOX-20 no recovery code exists until a boot is seen', async (t) => {
  const { dir, codes, sink } = await root(t);
  assert.deepEqual(codes.check('recovery', 'abandon '.repeat(12), { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'no_code' });
  assert.deepEqual(sink, []);
  assert.equal(readdirSync(join(dir, '..')).includes('codes') && readdirSync(dir).includes('recovery.hash'), false);
});

test('KBOX-20 a core restart in the same boot writes no new code and the first stays valid; a new boot voids it', async (t) => {
  const { codes, sink, lastCode } = await root(t);
  assert.equal(codes.writeRecoveryCode('boot-a'), 'written');
  const first = lastCode();
  assert.equal(codes.writeRecoveryCode('boot-a'), 'same_boot');
  assert.equal(sink.length, 1, 'no second code on the console');
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-a', trustExists: true }), { ok: true });
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-b', trustExists: true }), { ok: false, code: 'stale_boot' });
  assert.equal(codes.writeRecoveryCode('boot-b'), 'written');
  assert.notEqual(lastCode(), first);
  assert.deepEqual(codes.check('recovery', first, { bootId: 'boot-b', trustExists: true }), { ok: false, code: 'wrong_code' }, 'the old code is void');
});

test('KBOX-20 the recovery code is valid at 30 minutes and refused at 30 minutes plus 1 ms', async (t) => {
  for (const [after, verdict] of [[30 * MINUTE, { ok: true }], [30 * MINUTE + 1, { ok: false, code: 'expired' }]] as const) {
    const { codes, clock, lastCode } = await root(t);
    codes.writeRecoveryCode('boot-a');
    clock.advance(after);
    assert.deepEqual(codes.check('recovery', lastCode(), { bootId: 'boot-a', trustExists: true }), verdict, `${after} ms`);
  }
});

test('KBOX-20 a wrong code is refused and the code stays valid; a used code is refused the second time', async (t) => {
  const { codes, lastCode } = await root(t);
  codes.writeRecoveryCode('boot-a');
  const code = lastCode();
  const wrong = code.split(' ').reverse().join(' ');
  assert.deepEqual(codes.check('recovery', wrong, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('recovery', 'not words', { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('recovery', code.toUpperCase().replaceAll(' ', '   '), { bootId: 'boot-a', trustExists: true }), { ok: true }, 'case and spacing are normalised');
  codes.consume('recovery');
  assert.deepEqual(codes.check('recovery', code, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'no_code' });
});

test('KBOX-20 KBOX-49 root keeps only the hash, in a 0700 directory with 0600 files that the keybox user cannot read', async (t) => {
  const { dir, codes, lastCode } = await root(t);
  codes.writeRecoveryCode('boot-a');
  const recoveryCode = lastCode();
  assert.equal(codes.writeSetupCode(false), 'written');
  const setupCode = lastCode();
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  for (const f of readdirSync(dir)) assert.equal(statSync(join(dir, f)).mode & 0o777, 0o600, f);
  assert.deepEqual(readdirSync(dir).sort(), ['recovery.hash', 'setup.hash']);
  const kept = JSON.parse(readFileSync(join(dir, 'recovery.hash'), 'utf8')) as Record<string, unknown>;
  assert.deepEqual(kept, { hash: codeHash(recoveryCode), boot_id: 'boot-a', written_at: 1_700_000_000_000 });
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'setup.hash'), 'utf8')), { hash: codeHash(setupCode), written_at: 1_700_000_000_000 });
  for (const f of readdirSync(dir)) {
    const body = readFileSync(join(dir, f), 'utf8');
    assert.equal(body.includes(recoveryCode) || body.includes(setupCode), false, `no words in ${f}`);
  }
});

test('KBOX-49 the setup code is refused by root once trust.json exists, even when it is right; a wrong one leaves it valid', async (t) => {
  const { codes, lastCode } = await root(t);
  assert.equal(codes.writeSetupCode(false), 'written');
  const code = lastCode();
  assert.deepEqual(codes.check('setup', code, { bootId: 'boot-a', trustExists: true }), { ok: false, code: 'trust_exists' });
  assert.deepEqual(codes.check('setup', code.split(' ').slice(1).join(' '), { bootId: 'boot-a', trustExists: false }), { ok: false, code: 'wrong_code' });
  assert.deepEqual(codes.check('setup', code, { bootId: 'boot-a', trustExists: false }), { ok: true });
  assert.equal(codes.writeSetupCode(true), 'trust_exists', 'no setup code once trust.json exists');
});

test('KBOX-49 the code is 12 words from the 2048-word BIP-39 English list, 11 bits each (BIP-39 published vectors)', async (t) => {
  // trezor/python-mnemonic vectors.json, the reference vectors of BIP-39: entropy 00..00 gives "abandon x11 about" and
  // 7f..7f gives "legal winner ... yellow". Their 132 bits are the 128 entropy bits and 4 checksum bits (SHA-256, first nibble).
  const { createHash } = await import('node:crypto');
  const { codeFromBytes } = await import('../src/pure/codes.ts');
  const bits132 = (entropy: Buffer): Uint8Array => Uint8Array.from([...entropy, (createHash('sha256').update(entropy).digest()[0] ?? 0) & 0xf0]);
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0)), WORDLIST), `${'abandon '.repeat(11)}about`);
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0x7f)), WORDLIST), 'legal winner thank year wave sausage worth useful legal winner thank yellow');
  assert.equal(codeFromBytes(bits132(Buffer.alloc(16, 0x80)), WORDLIST), 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above');
  assert.equal(WORDLIST.length, 2048);
  void t;
});

test('KBOX-20 kb-code writes the code to the console sink only: not to stdout, stderr, or any other file', async (t) => {
  const dir = await tempDir(t);
  const device = join(dir, 'console');
  writeFileSync(device, '');
  const bootFile = join(dir, 'boot_id');
  writeFileSync(bootFile, 'c0ffee00-0000-4000-8000-000000000001\n');
  const config = join(dir, 'runtime.config.json');
  writeFileSync(config, JSON.stringify({ console_device: device }));
  const codesDir = join(dir, 'codes');
  const env = `KB_CODES_DIR=${codesDir}`;
  const run = runNode(['--input-type=module', '-e', `process.env.KB_CODES_DIR=${JSON.stringify(codesDir)};process.env.KB_BOOT_ID_FILE=${JSON.stringify(bootFile)};process.env.KB_RUNTIME_CONFIG=${JSON.stringify(config)};process.env.KB_TRUST_FILE=${JSON.stringify(join(dir, 'trust.json'))};process.argv[2]='recovery';await import(${JSON.stringify(new URL('../src/cli/kb-code.ts', import.meta.url).pathname)});`], dir);
  assert.equal(run.status, 0, run.stderr);
  const shown = readFileSync(device, 'utf8');
  const code = /([a-z]+(?: [a-z]+){11})/.exec(shown)?.[1];
  assert.ok(code !== undefined, 'the console got the code');
  for (const [name, text] of [['stdout', run.stdout], ['stderr', run.stderr], ['env', env]] as const) assert.equal(text.includes(code), false, name);
  for (const f of readdirSync(codesDir)) assert.equal(readFileSync(join(codesDir, f), 'utf8').includes(code), false, f);
  const again = runNode(['--input-type=module', '-e', `process.env.KB_CODES_DIR=${JSON.stringify(codesDir)};process.env.KB_BOOT_ID_FILE=${JSON.stringify(bootFile)};process.env.KB_RUNTIME_CONFIG=${JSON.stringify(config)};process.env.KB_TRUST_FILE=${JSON.stringify(join(dir, 'trust.json'))};process.argv[2]='recovery';await import(${JSON.stringify(new URL('../src/cli/kb-code.ts', import.meta.url).pathname)});`], dir);
  assert.equal(again.status, 0, again.stderr);
  assert.equal(readFileSync(device, 'utf8'), shown, 'a second run in the same boot writes no new code');
});

test('KBOX-20 the kb-code unit (not core) has tty, a DeviceAllow for the configured console device only, and PrivateDevices=no', () => {
  const deploy = new URL('../deploy/', import.meta.url).pathname;
  const config = JSON.parse(readFileSync(join(deploy, 'runtime.config.json'), 'utf8')) as { console_device: string };
  const unit = directives(readFileSync(join(deploy, 'kb-code.service'), 'utf8'), 'Service');
  assert.deepEqual(words(unit.get('SupplementaryGroups')), ['tty']);
  assert.deepEqual(words(unit.get('DeviceAllow')), [config.console_device, 'w']);
  assert.deepEqual(unit.get('PrivateDevices'), ['no']);
  assert.deepEqual(unit.get('User'), ['root']);
  assert.deepEqual(unit.get('Type'), ['oneshot']);
  for (const name of readdirSync(deploy).filter((f) => f.endsWith('.service') && f !== 'kb-code.service')) {
    const other = directives(readFileSync(join(deploy, name), 'utf8'), 'Service');
    assert.equal(other.get('DeviceAllow'), undefined, name);
    assert.equal(other.get('SupplementaryGroups'), undefined, name);
  }
});

// --- core's half: /recover through the TrustPort ------------------------------------------------------------------------

test('KBOX-20 recovery makes the new approver the only one; root is asked first, the push goes out next while the old approvers still stand, then the table changes', async (t) => {
  const w = await approveWorld(t);
  const second = await w.addApprover();
  const seen: { atRoot?: readonly string[]; atPush?: readonly string[] } = {};
  w.trust.onApply = (r) => {
    if (r.change === 'recovery') seen.atRoot = w.core.approvers.ids();
  };
  w.push.onSend = (m) => {
    if (m.kind === 'recovery') seen.atPush = w.core.approvers.ids();
  };
  const code = w.recoveryCode();
  const reply = await registerAt(w, '/recover', code, softApprover());
  assert.equal(reply.status, 201, reply.body);
  const fresh = (reply.json() as { approver_id: string }).approver_id;
  assert.deepEqual([...(seen.atRoot ?? [])].sort(), [w.ownerId, second.approverId].sort(), 'root is asked while core still has the old table');
  assert.deepEqual([...(seen.atPush ?? [])].sort(), [w.ownerId, second.approverId].sort(), 'the push goes out before anyone is revoked');
  assert.deepEqual(w.core.approvers.ids(), [fresh]);
  assert.deepEqual(w.trust.copy?.approvers.map((a) => a.id), [fresh], 'trust.json holds the new approver only');
  const actions = w.parts.audit.read(0).entries.map((e) => e.action);
  assert.ok(actions.includes('recovery.used'));
  assert.equal(actions.filter((a) => a === 'approver.removed').length, 2);
});

test('KBOX-20 a recovery code root refuses changes nothing, whether the code is wrong, used, or root refuses for its own reason', async (t) => {
  const w = await approveWorld(t);
  const before = w.core.approvers.ids();
  const code = w.recoveryCode();
  const wrong = code.split(' ').reverse().join(' ');
  assert.equal((await registerAt(w, '/recover', wrong, softApprover())).status, 403);
  assert.equal(w.trust.calls.at(-1)?.change, 'recovery', 'core relays the code to root and does not judge it');
  w.trust.refuseNext('io_error');
  assert.equal((await registerAt(w, '/recover', code, softApprover())).status, 403);
  assert.deepEqual(w.core.approvers.ids(), before);
  assert.equal(w.push.sent.some((m) => m.kind === 'recovery'), false, 'nobody is told of a recovery that did not happen');
  assert.equal(w.parts.audit.read(0).entries.some((e) => e.action === 'recovery.used'), false);
  assert.equal((await registerAt(w, '/recover', code, softApprover())).status, 201, 'the right code is still valid after the refusals');
  assert.equal((await registerAt(w, '/recover', code, softApprover())).status, 403, 'and refused on second use');
});

test('KBOX-20 after recovery the new approver can approve and open a view, and an old one can do neither, its open view included', async (t) => {
  const w = await approveWorld(t);
  const oldCookie = await w.view();
  const newcomer = softApprover();
  assert.equal((await registerAt(w, '/recover', w.recoveryCode(), newcomer)).status, 201);
  assert.equal((await w.call('/app/queue', { cookie: oldCookie })).status, 401, 'the old view session ends');
  const n = await w.nonce('view');
  assert.equal((await w.call('/app/view', { json: { proof: wire(n, w.owner.prove(challenges.view(n), RP)) } })).status, 403);
  const opened = w.propose({ kind: 'revoke_grant', keyref: 'openai/admin', machine: 'ws-1' });
  const item = (await w.queue(newcomer)).find((q) => q.approval_id === opened.approval_id);
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item, w.owner))).status, 403, 'the old approver cannot approve');
  const fresh = (await w.queue(newcomer)).find((q) => q.approval_id === opened.approval_id);
  assert.ok(fresh);
  assert.equal((await w.decide(fresh.approval_id, 'approve', w.proofFor(fresh, newcomer))).status, 200, 'the new one can');
});

test('KBOX-20 the recovery code (a canary) is absent from core\'s database files, WAL, journal, audit, events and responses', async (t) => {
  const w = await approveWorld(t);
  const code = w.recoveryCode();
  w.trust.refuseNext('io_error');
  const refused = await registerAt(w, '/recover', code, softApprover());
  const reply = await registerAt(w, '/recover', code, softApprover());
  assert.equal(reply.status, 201);
  const surfaces: [string, string][] = readdirSync(w.stateDir).map((f) => [f, readFileSync(join(w.stateDir, f)).toString('latin1')]);
  surfaces.push(['responses', refused.body + reply.body], ['journal', w.journal.join('\n')], ['audit', JSON.stringify(w.parts.audit.read(0).entries)], ['events', JSON.stringify(w.parts.events.after(0))]);
  assert.ok(surfaces.length > 4, 'the state directory holds the databases');
  const head = code.split(' ').slice(0, 3).join(' ');
  for (const [name, body] of surfaces) assert.equal(body.includes(code) || body.includes(head), false, `code in ${name}`);
  const used = w.parts.audit.read(0).entries.find((e) => e.action === 'recovery.used');
  assert.ok(used !== undefined);
  assert.deepEqual(used.detail, {}, 'recovery.used carries no text');
});

test('KBOX-20 approver_add and approver_remove go to root first: core\'s table is unchanged when root is asked and stays unchanged when root refuses', async (t) => {
  const w = await approveWorld(t);
  const atRoot: (readonly string[])[] = [];
  w.trust.onApply = () => void atRoot.push(w.core.approvers.ids());
  const second = await w.addApprover();
  assert.deepEqual(atRoot.at(-1), [w.ownerId], 'approver_add: root is asked before core adds');
  assert.equal(w.trust.calls.at(-1)?.change, 'approver_add');
  assert.deepEqual([...w.core.approvers.ids()].sort(), [w.ownerId, second.approverId].sort());

  const removal = w.propose({ kind: 'approver_remove', approver_id: second.approverId }, 'box');
  const item = (await w.queue()).find((q) => q.approval_id === removal.approval_id);
  assert.ok(item);
  w.trust.refuseNext('io_error');
  const refused = await w.decide(item.approval_id, 'approve', w.proofFor(item));
  assert.equal(refused.status, 200, refused.body);
  assert.equal((refused.json() as { result: string }).result, 'failed');
  assert.deepEqual([...w.core.approvers.ids()].sort(), [w.ownerId, second.approverId].sort(), 'a refused removal leaves the table');

  const again = w.propose({ kind: 'approver_remove', approver_id: second.approverId }, 'box');
  const item2 = (await w.queue()).find((q) => q.approval_id === again.approval_id);
  assert.ok(item2);
  assert.equal((await w.decide(item2.approval_id, 'approve', w.proofFor(item2))).status, 200);
  assert.deepEqual([...(atRoot.at(-1) ?? [])].sort(), [w.ownerId, second.approverId].sort(), 'approver_remove: root is asked before core removes');
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId]);
  assert.deepEqual(w.trust.copy?.approvers.map((a) => a.id), [w.ownerId]);
});

test('KBOX-20 a refused approver_add registration leaves core\'s table unchanged and the registration code spent', async (t) => {
  const w = await approveWorld(t);
  const cookie = await w.view();
  const opened = await w.call('/app/propose-approver-add', { method: 'POST', cookie });
  const id = (opened.json() as { approval_id: string }).approval_id;
  const item = (await w.queue()).find((q) => q.approval_id === id);
  assert.ok(item);
  const code = ((await w.decide(id, 'approve', w.proofFor(item))).json() as { registration_code: string }).registration_code;
  w.trust.refuseNext('io_error');
  assert.equal((await registerAt(w, '/recover/register', code, softApprover())).status, 403);
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId]);
  assert.equal((await registerAt(w, '/recover/register', code, softApprover())).status, 403, 'the code is spent by the attempt root refused');
});

// --- the approver_add registration code: it ends with the approval, one way or another (KBOX-53, KBOX-20) -------------------

/** Proposes approver_add from the owner's view session, approves it as `by`, and returns the approval id and its registration code. */
async function approvedAdd(w: World, by: SoftApprover = w.owner): Promise<{ readonly id: string; readonly code: string }> {
  const opened = await w.call('/app/propose-approver-add', { method: 'POST', cookie: await w.view(by) });
  const id = (opened.json() as { approval_id: string }).approval_id;
  const item = (await w.queue(by)).find((q) => q.approval_id === id);
  assert.ok(item);
  const approved = await w.decide(id, 'approve', w.proofFor(item, by));
  assert.equal(approved.status, 200, approved.body);
  return { id, code: (approved.json() as { registration_code: string }).registration_code };
}

/** What the audit says each approver_add approval ended as: `[approval id, result, reason]` for every `approval.executed` row. */
const outcomes = (w: World): [string, unknown, unknown][] =>
  w.parts.audit.read(0).entries.filter((e) => e.action === 'approval.executed').map((e) => [e.ref, e.detail['result'], e.detail['reason_code']]);

const addCalls = (w: World): number => w.trust.calls.filter((c) => c.change === 'approver_add').length;

test('KBOX-53 an approver_add whose registration root refuses ends as failed with root_refused, and one that registers ends as done', async (t) => {
  const w = await approveWorld(t);
  const refused = await approvedAdd(w);
  w.trust.refuseNext('io_error');
  assert.equal((await registerAt(w, '/recover/register', refused.code, softApprover())).status, 403);
  assert.deepEqual(outcomes(w), [[refused.id, 'failed', 'root_refused']]);
  const good = await approvedAdd(w);
  assert.equal((await registerAt(w, '/recover/register', good.code, softApprover())).status, 201);
  assert.deepEqual(outcomes(w).at(-1), [good.id, 'done', 'ok']);
});

test('KBOX-53 an approver_add registration refused for its own keys (not the code) ends the approval as failed too', async (t) => {
  const w = await approveWorld(t);
  const add = await approvedAdd(w);
  const stranger = softApprover();
  const n = await w.nonce('register');
  const body = { code: add.code, approver: { ...newApproverBody(stranger) }, proof: wire(n, softApprover().prove(challenges.register(n), RP)), phrase: 'blue kettle' };
  assert.equal((await w.call('/recover/register', { json: body })).status, 403, 'the proof is not by the keys sent');
  assert.deepEqual(outcomes(w), [[add.id, 'failed', 'proof_refused']]);
});

test('KBOX-53 a registration code that the owner never uses ends the approval as failed at 10 minutes, seen by the next sweep and by a late attempt', async (t) => {
  const w = await approveWorld(t);
  const add = await approvedAdd(w);
  w.clock.advance(10 * MINUTE);
  await w.queue();
  assert.deepEqual(outcomes(w), [], 'still open at 10 minutes');
  w.clock.advance(1);
  await w.queue();
  assert.deepEqual(outcomes(w), [[add.id, 'failed', 'code_expired']]);
  assert.equal((await registerAt(w, '/recover/register', add.code, softApprover())).status, 403);
  assert.equal(addCalls(w), 0, 'root is never asked about an expired code');
  const late = await approvedAdd(w);
  w.clock.advance(10 * MINUTE + 1);
  assert.equal((await registerAt(w, '/recover/register', late.code, softApprover())).status, 403, 'a late attempt is refused');
  assert.deepEqual(outcomes(w).at(-1), [late.id, 'failed', 'code_expired']);
});

test('KBOX-53 a second approved approver_add replaces the first: the first code is dead and its approval ends as failed', async (t) => {
  const w = await approveWorld(t);
  const first = await approvedAdd(w);
  const second = await approvedAdd(w);
  assert.deepEqual(outcomes(w), [[first.id, 'failed', 'superseded']]);
  assert.equal((await registerAt(w, '/recover/register', first.code, softApprover())).status, 403);
  assert.equal((await registerAt(w, '/recover/register', second.code, softApprover())).status, 201);
});

test('KBOX-53 removing the approver who approved an approver_add cancels the registration code: root is not asked and no device is added', async (t) => {
  const w = await approveWorld(t);
  const second = await w.addApprover();
  const add = await approvedAdd(w);
  const calls = addCalls(w);
  const removal = w.propose({ kind: 'approver_remove', approver_id: w.ownerId }, 'box');
  const item = (await w.queue(second.approver)).find((q) => q.approval_id === removal.approval_id);
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item, second.approver))).status, 200);
  assert.deepEqual(w.core.approvers.ids(), [second.approverId]);
  assert.equal((await registerAt(w, '/recover/register', add.code, softApprover())).status, 403);
  assert.equal(addCalls(w), calls, 'root was not asked');
  assert.deepEqual(w.core.approvers.ids(), [second.approverId], 'no device was added');
  assert.deepEqual(outcomes(w).filter(([id]) => id === add.id), [[add.id, 'failed', 'cancelled']]);
});

test('KBOX-53 a recovery cancels the registration code of an approver_add the old approvers approved: the code registers nothing', async (t) => {
  const w = await approveWorld(t);
  const add = await approvedAdd(w);
  const calls = addCalls(w);
  const newcomer = softApprover();
  assert.equal((await registerAt(w, '/recover', w.recoveryCode(), newcomer)).status, 201);
  assert.equal((await registerAt(w, '/recover/register', add.code, softApprover())).status, 403);
  assert.equal(addCalls(w), calls, 'root was not asked');
  assert.equal(w.core.approvers.ids().length, 1, 'only the recovered approver is registered');
  assert.deepEqual(outcomes(w), [[add.id, 'failed', 'cancelled']]);
});

test('KBOX-53 removing some other approver leaves the registration code alone: the proof that opened it is still good', async (t) => {
  const w = await approveWorld(t);
  const second = await w.addApprover();
  const add = await approvedAdd(w);
  const removal = w.propose({ kind: 'approver_remove', approver_id: second.approverId }, 'box');
  const item = (await w.queue()).find((q) => q.approval_id === removal.approval_id);
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item))).status, 200);
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId]);
  assert.equal((await registerAt(w, '/recover/register', add.code, softApprover())).status, 201);
  assert.deepEqual(outcomes(w).filter(([id]) => id === add.id), [[add.id, 'done', 'ok']]);
});
