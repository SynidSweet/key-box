// J5 (kernel-approve): recovery after a reboot. The box has an owner; the host reboots (a new boot_id); the real kb-code
// process writes a recovery code to the console device; a new phone recovers with it at /recover; the old phone can no longer
// open a view or approve, the new one can; the code works once and the boot before it left no usable code.
// Core runs in this process with the fake TrustPort over root's real code store, because the real port (kb-install's trust
// requests) is the update unit's: that half of the journey is UNVERIFIED here.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { softApprover } from '../kit/approver.ts';
import { runNode, tempDir } from '../kit/index.ts';
import { RP, approveWorld, challenges, registerAt, wire } from '../support/approve-world.ts';

const KB_CODE = new URL('../../src/cli/kb-code.ts', import.meta.url).pathname;

test('J5 recovery after a reboot: kb-code writes the code to the console, a new phone recovers with it, the old phone is shut out', async (t) => {
  const dir = await tempDir(t);
  const bootFile = join(dir, 'boot_id');
  const device = join(dir, 'console');
  const config = join(dir, 'runtime.config.json');
  const codesDir = join(dir, 'codes');
  writeFileSync(bootFile, '11111111-1111-4111-8111-111111111111\n');
  writeFileSync(device, '');
  writeFileSync(config, JSON.stringify({ console_device: device }));
  const bootId = (): string => readFileSync(bootFile, 'utf8').trim();
  const w = await approveWorld(t, { codes: { dir: codesDir, bootId } });

  const kbCode = (): { status: number | null; stdout: string; stderr: string } => {
    const env = { KB_CODES_DIR: codesDir, KB_BOOT_ID_FILE: bootFile, KB_RUNTIME_CONFIG: config, KB_TRUST_FILE: join(dir, 'trust.json') };
    const run = runNode(['--input-type=module', '-e', `Object.assign(process.env, ${JSON.stringify(env)});process.argv[2]='recovery';await import(${JSON.stringify(KB_CODE)});`], dir);
    return run;
  };
  const consoleCodes = (): string[] => [...readFileSync(device, 'utf8').matchAll(/([a-z]+(?: [a-z]+){11})/g)].map((m) => m[1] ?? '');
  /** kb-code stamps the code with the host clock; the box's fake clock is moved to just after that moment. */
  const catchUp = (): void => {
    const writtenAt = (JSON.parse(readFileSync(join(codesDir, 'recovery.hash'), 'utf8')) as { written_at: number }).written_at;
    w.clock.advance(Math.max(0, writtenAt - w.clock.now()) + 60_000);
  };

  // The first boot's code, never used.
  assert.equal(kbCode().status, 0);
  const firstBoot = consoleCodes().at(-1) ?? '';
  // The host reboots.
  writeFileSync(bootFile, '22222222-2222-4222-8222-222222222222\n');
  const run = kbCode();
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout.trim(), 'kb-code: written');
  const code = consoleCodes().at(-1) ?? '';
  assert.notEqual(code, firstBoot);
  assert.equal(run.stdout.includes(code) || run.stderr.includes(code), false, 'the code is on the console only');
  assert.equal(kbCode().stdout.trim(), 'kb-code: same_boot', 'a core or unit restart in the same boot writes no new code');
  catchUp();

  const oldCookie = await w.view();
  assert.equal((await registerAt(w, '/recover', firstBoot, softApprover())).status, 403, 'the code of the boot before is void');
  const phone = softApprover();
  const recovered = await registerAt(w, '/recover', code, phone);
  assert.equal(recovered.status, 201, recovered.body);
  assert.equal((await registerAt(w, '/recover', code, softApprover())).status, 403, 'the code works once');

  assert.equal((await w.call('/app/queue', { cookie: oldCookie })).status, 401);
  const n = await w.nonce('view');
  assert.equal((await w.call('/app/view', { json: { proof: wire(n, w.owner.prove(challenges.view(n), RP)) } })).status, 403, 'the old phone cannot open a view');
  const opened = w.propose({ kind: 'revoke_grant', keyref: 'openai/admin', machine: 'ws-1' });
  const item = (await w.queue(phone)).find((q) => q.approval_id === opened.approval_id);
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item, phone))).status, 200, 'the new phone approves');
  assert.ok(w.push.sent.some((m) => m.kind === 'recovery'), 'the old phone was told first');
});
