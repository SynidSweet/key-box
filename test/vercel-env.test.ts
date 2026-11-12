// KBOX-36, KBOX-16: the Vercel destination `vercel-env` (sensitive environment variables) and its redeployer, over the fake of api.vercel.com.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { DestinationTarget } from '../src/ports/destination.ts';
import type { AdapterHttp, HttpRequest, HttpResponse } from '../src/ports/http.ts';
import { HttpTransportError } from '../src/ports/http.ts';
import { admitDestination } from '../src/pure/class.ts';
import { destinationContract } from './contracts/destination.contract.ts';
import { redeployerContract } from './contracts/redeployer.contract.ts';
import { PROJECT, lentText, master, vercelWorld } from './support/vercel-world.ts';

const world = await vercelWorld();
const { fake, http, kit } = world;
const destination = kit.destination;
const redeployer = kit.redeployer;
assert.ok(redeployer !== undefined, 'the vercel-env kit carries a redeployer');
const target: DestinationTarget = { kind: 'vercel-env', id: PROJECT };
const sentSince = (n: number): string[] => http.sent.slice(n).map((s) => `${s.method} ${s.target}`);
const envOf = (name: string): { type: string; value: string; target: readonly string[] } | undefined => fake.envs.get(PROJECT)?.find((e) => e.key === name);

destinationContract('vercel', () => {
  fake.reset();
  return { destination, target, master: master(), valueOne: lentText('vcp_KboxTestFakeValueOne'), valueTwo: lentText('vcp_KboxTestFakeValueTwo'), has: (name) => envOf(name) !== undefined };
});
redeployerContract('vercel', () => {
  fake.reset();
  return { redeployer, target, master: master(), failNext: () => fake.failNextDeploy() };
});

// ---------------------------------------------------------------- destination

test('KBOX-36 the destination is vercel-env, write-only (runtime readable) and needs a redeploy', () => {
  assert.equal(destination.kind, 'vercel-env');
  assert.deepEqual(destination.properties(), { readableBy: 'runtime', needsRedeploy: true });
  assert.deepEqual(world.entry.destinations?.map((d) => d.destination.kind), ['vercel-env']);
});

test('KBOX-16 KBOX-36 every class is admitted, because the value is only ever pushed as a sensitive variable the API never reads back', () => {
  const { readableBy } = destination.properties();
  for (const klass of ['ordinary', 'admin', 'master'] as const) assert.equal(admitDestination(klass, readableBy), true, klass);
});

test('KBOX-36 push upserts a sensitive variable for production and preview: POST /v10/projects/{id}/env?upsert=true with key, value, type and target', async () => {
  fake.reset();
  const before = http.sent.length;
  const outcome = await destination.push(target, 'STRIPE_KEY', lentText('vcp_KboxTestFakeSecretValue'), 'admin', master());
  assert.equal(outcome.outcome, 'applied');
  assert.deepEqual(sentSince(before), [`POST /v10/projects/${PROJECT}/env?upsert=true`]);
  const body: unknown = JSON.parse(Buffer.from(http.sent[before]?.body ?? []).toString('utf8'));
  assert.deepEqual(body, { key: 'STRIPE_KEY', value: 'vcp_KboxTestFakeSecretValue', type: 'sensitive', target: ['production', 'preview'] });
  assert.equal(http.sent[before]?.headers['authorization'], `Bearer ${'vcp_KboxTestFakeMaster' + 'M'.repeat(20)}`);
  assert.equal(envOf('STRIPE_KEY')?.type, 'sensitive');
});

test('KBOX-16 KBOX-36 no push of any name or value ever creates an encrypted or plain variable', async () => {
  fake.reset();
  for (const name of ['A', 'B_C', 'lower']) await destination.push(target, name, lentText(`vcp_KboxTestFake${name}`), 'admin', master());
  assert.deepEqual([...new Set((fake.envs.get(PROJECT) ?? []).map((e) => e.type))], ['sensitive']);
});

test('KBOX-36 the project id and the name are encoded as path text and body text', async () => {
  fake.reset();
  const before = http.sent.length;
  const odd: DestinationTarget = { kind: 'vercel-env', id: 'a b/c?d' };
  const outcome = await destination.push(odd, 'N"AME\n', lentText('vcp_KboxTestFakeValue'), 'admin', master());
  assert.deepEqual(sentSince(before), ['POST /v10/projects/a%20b%2Fc%3Fd/env?upsert=true']);
  assert.equal(outcome.outcome, 'refused', 'the fake has no such project: 404');
  const body = JSON.parse(Buffer.from(http.sent[before]?.body ?? []).toString('utf8')) as { key: string };
  assert.equal(body.key, 'N"AME\n');
});

test('KBOX-2 KBOX-36 the receipt names the variable (its id, one per name) and holds no part and no digest of either value', async () => {
  fake.reset();
  const one = await destination.push(target, 'K', lentText('vcp_KboxTestFakeOne'), 'admin', master());
  const two = await destination.push(target, 'K', lentText('vcp_KboxTestFakeTwo'), 'admin', master());
  const other = await destination.push(target, 'L', lentText('vcp_KboxTestFakeOne'), 'admin', master());
  assert.ok(one.outcome === 'applied' && two.outcome === 'applied' && other.outcome === 'applied');
  assert.equal(one.version, two.version, 'the same variable, the same receipt');
  assert.notEqual(one.version, other.version, 'another variable, another receipt');
  assert.equal(one.version, fake.envs.get(PROJECT)?.find((e) => e.key === 'K')?.id);
  const seen = JSON.stringify([one, two, other]);
  for (const text of ['vcp_KboxTestFakeOne', 'vcp_KboxTestFakeTwo']) {
    const bytes = Buffer.from(text);
    for (const form of [text, bytes.toString('hex'), bytes.toString('base64'), createHash('sha256').update(bytes).digest('hex').slice(0, 16)]) assert.equal(seen.includes(form), false, form);
  }
  assert.equal(fake.envs.get(PROJECT)?.filter((e) => e.key === 'K').length, 1, 'upsert: one variable, not two');
});

test('KBOX-36 push answers refused only for an answer that says nothing was applied (400, 401, 403, 404, 409, 422), unknown for the rest', async () => {
  fake.reset();
  for (const status of [400, 401, 403, 404, 409, 422]) {
    fake.forceStatus(status);
    assert.deepEqual(await destination.push(target, 'K', lentText('vcp_KboxTestFakeV'), 'admin', master()), { outcome: 'refused' }, String(status));
  }
  for (const status of [429, 500, 502, 503, 504]) {
    fake.forceStatus(status);
    assert.deepEqual(await destination.push(target, 'K', lentText('vcp_KboxTestFakeV'), 'admin', master()), { outcome: 'unknown' }, String(status));
  }
  assert.equal(envOf('K'), undefined);
});

test('KBOX-36 a push with no answer, a cut answer or a 200 that names no variable is unknown: the destination may hold the value', async () => {
  fake.reset();
  fake.cutAnswers(true);
  assert.deepEqual(await destination.push(target, 'K', lentText('vcp_KboxTestFakeV'), 'admin', master()), { outcome: 'unknown' });
  fake.cutAnswers(false);
  await fake.setDown(true);
  assert.deepEqual(await destination.push(target, 'K', lentText('vcp_KboxTestFakeV'), 'admin', master()), { outcome: 'unknown' });
  await fake.setDown(false);
  const noId = world.entryOver({ ...http, request: (): Promise<HttpResponse> => Promise.resolve({ status: 200, headers: {}, body: Buffer.from('{"created":{}}') }) });
  assert.deepEqual(await noId.destinations?.[0]?.destination.push(target, 'K', lentText('vcp_KboxTestFakeV'), 'admin', master()), { outcome: 'unknown' });
});

test('KBOX-36 remove lists the variables, deletes every one with that key by id, and leaves the others', async () => {
  fake.reset();
  await destination.push(target, 'GONE', lentText('vcp_KboxTestFakeA'), 'admin', master());
  await destination.push(target, 'STAYS', lentText('vcp_KboxTestFakeB'), 'admin', master());
  const before = http.sent.length;
  await destination.remove(target, 'GONE', master());
  const calls = sentSince(before);
  assert.equal(calls[0], `GET /v10/projects/${PROJECT}/env`);
  assert.match(calls[1] ?? '', new RegExp(`^DELETE /v9/projects/${PROJECT}/env/env_fake\\d+$`));
  assert.equal(calls.length, 2);
  assert.deepEqual(fake.envs.get(PROJECT)?.map((e) => e.key), ['STAYS']);
});

test('KBOX-36 remove of a name that is not there, or in a project that is not there, counts as done and deletes nothing', async () => {
  fake.reset();
  const before = http.sent.length;
  await destination.remove(target, 'NEVER', master());
  await destination.remove({ kind: 'vercel-env', id: 'prj_missing' }, 'NEVER', master());
  assert.equal(sentSince(before).filter((c) => c.startsWith('DELETE')).length, 0);
});

test('KBOX-36 remove treats a delete answered 404 as done (listed, then deleted by someone else) and fails on every other refusal or outage', async () => {
  fake.reset();
  await destination.push(target, 'K', lentText('vcp_KboxTestFakeA'), 'admin', master());
  const raced = (status: number): AdapterHttp => ({ request: (req: HttpRequest): Promise<HttpResponse> => (req.method === 'DELETE' ? Promise.resolve({ status, headers: {}, body: Buffer.from('{}') }) : http.request(req)) });
  const remover = (status: number): Promise<void> | undefined => world.entryOver({ ...http, ...raced(status) }).destinations?.[0]?.destination.remove(target, 'K', master());
  await remover(404);
  await assert.rejects(async () => remover(403), /vercel: rejected/);
  await assert.rejects(async () => remover(500), /vercel: server_error/);
  for (const status of [401, 403]) {
    fake.forceStatus(status);
    await assert.rejects(() => destination.remove(target, 'K', master()), /vercel: rejected/, `list ${status}`);
  }
  fake.forceStatus(undefined);
  await fake.setDown(true);
  await assert.rejects(() => destination.remove(target, 'K', master()), /vercel: unreachable/);
  await fake.setDown(false);
  assert.ok(envOf('K') !== undefined, 'nothing was deleted by the failures');
});

// ---------------------------------------------------------------- redeployer

test('KBOX-36 redeploy finds the production deployment that is ready and posts deploymentId, name and target to /v13/deployments?forceNew=1', async () => {
  fake.reset();
  const before = http.sent.length;
  const ref = await redeployer.redeploy(target, master());
  const calls = sentSince(before);
  assert.equal(calls[0], `GET /v6/deployments?projectId=${PROJECT}&target=production&state=READY&limit=1`);
  assert.equal(calls[1], 'POST /v13/deployments?forceNew=1');
  assert.deepEqual(JSON.parse(Buffer.from(http.sent[before + 1]?.body ?? []).toString('utf8')), { name: `${PROJECT}-name`, deploymentId: `dpl_seed_${PROJECT}`, target: 'production' });
  assert.match(ref, /^dpl_fake\d+$/);
});

test('KBOX-36 ready waits on the clock for a build to settle: it pauses between polls and says ready', async () => {
  fake.reset();
  const slow = await vercelWorld({ buildPolls: 3 });
  const ref = await slow.kit.redeployer?.redeploy(target, master());
  assert.ok(ref !== undefined);
  assert.equal(await slow.kit.redeployer?.ready(ref, master()), 'ready');
  assert.deepEqual(slow.pauses, [5000, 5000, 5000]);
  assert.equal(slow.clock.now(), 15000);
});

test('KBOX-36 ready says failed for a build that ends in error, and for a deploy still not settled when the deadline passes', async () => {
  fake.reset();
  fake.failNextDeploy();
  const bad = await redeployer.redeploy(target, master());
  const pausesBefore = world.pauses.length;
  assert.equal(await redeployer.ready(bad, master()), 'failed');
  assert.equal(world.pauses.length - pausesBefore, 2, 'an error ends the wait at once: it does not wait out the deadline');
  const stuck = await vercelWorld({ buildPolls: 1_000_000 });
  const ref = await stuck.kit.redeployer?.redeploy(target, master());
  assert.ok(ref !== undefined);
  const started = stuck.clock.now();
  assert.equal(await stuck.kit.redeployer?.ready(ref, master()), 'failed');
  const waited = stuck.clock.now() - started;
  assert.ok(waited >= 15 * 60_000 && waited < 15 * 60_000 + 5000, `waited ${waited} ms`);
});

test('KBOX-4 KBOX-36 ready for an unknown or vanished deploy is failed, never a throw about adapter memory, and a fresh redeployer answers for a deploy from the DeployRef and the master alone', async () => {
  fake.reset();
  assert.equal(await redeployer.ready('dpl_unknown', master()), 'failed');
  const ref = await redeployer.redeploy(target, master());
  assert.equal(await redeployer.ready(ref, master()), 'ready');
  const fresh = world.entryOver(http).destinations?.[0]?.redeployer;
  assert.ok(fresh !== undefined && fresh !== redeployer);
  assert.equal(await fresh.ready(ref, master()), 'ready', 'a finished deploy asked again, by a redeployer that never started it');
});

test('KBOX-36 redeploy with no ready production deployment, or against a refusing or unreachable platform, throws a fixed error and starts nothing', async () => {
  fake.reset();
  const before = http.sent.length;
  await assert.rejects(() => redeployer.redeploy({ kind: 'vercel-env', id: 'prj_missing' }, master()), /vercel: no_deployment/);
  assert.equal(sentSince(before).some((c) => c.startsWith('POST')), false);
  fake.forceStatus(403);
  await assert.rejects(() => redeployer.redeploy(target, master()), /vercel: rejected/);
  fake.forceStatus(undefined);
  await fake.setDown(true);
  await assert.rejects(() => redeployer.redeploy(target, master()), /vercel: unreachable/);
  await fake.setDown(false);
});

test('KBOX-36 ready that loses the platform mid-wait throws unreachable, and a refused poll is failed', async () => {
  fake.reset();
  const ref = await redeployer.redeploy(target, master());
  await fake.setDown(true);
  await assert.rejects(() => redeployer.ready(ref, master()), /vercel: unreachable/);
  await fake.setDown(false);
  const again = await redeployer.redeploy(target, master());
  fake.forceStatus(404);
  assert.equal(await redeployer.ready(again, master()), 'failed');
});

test('KBOX-36 a transport failure is a HttpTransportError at the port and nothing of it reaches the adapter\'s error', async () => {
  const refusing = world.entryOver({ sent: [], request: (): Promise<HttpResponse> => Promise.reject(new HttpTransportError('refused')) });
  const failure: unknown = await refusing.destinations?.[0]?.redeployer?.redeploy(target, master()).then(() => undefined, (e: unknown) => e);
  assert.ok(failure instanceof Error);
  assert.equal(failure instanceof HttpTransportError, false);
  assert.equal(failure.cause, undefined);
});


// ---------------------------------------------------------------- review fixes (adapters batch 1)

test('KBOX-2 KBOX-36 the receipt of a push is the variable id and nothing derived from the value: no digest, no part of it, the same id for a repeated push of the same variable', async () => {
  fake.reset();
  const valueText = 'vcp_KboxTestFakeReceiptValue';
  const first = await destination.push(target, 'K', lentText(valueText), 'admin', master());
  const again = await destination.push(target, 'K', lentText('vcp_KboxTestFakeOther'), 'admin', master());
  assert.ok(first.outcome === 'applied' && again.outcome === 'applied');
  const id = fake.envs.get(PROJECT)?.find((e) => e.key === 'K')?.id;
  assert.equal(first.version, id, 'the receipt is the variable id, which finds the push again');
  assert.equal(again.version, id);
  const digest = createHash('sha256').update(valueText).digest('hex');
  assert.equal(first.version.includes(digest.slice(0, 8)), false);
  assert.doesNotMatch(first.version, /[0-9a-f]{16}/);
});

// ---------------------------------------------------------------- S2 ports: class at push, ready from the DeployRef and the master alone

test('KBOX-36 push types the variable by the key class: sensitive for admin and master, encrypted for ordinary', async () => {
  fake.reset();
  for (const klass of ['admin', 'master', 'ordinary'] as const) await destination.push(target, `K_${klass}`, lentText('vcp_KboxTestFakeV'), klass, master());
  assert.deepEqual(
    ['K_admin', 'K_master', 'K_ordinary'].map((name) => envOf(name)?.type),
    ['sensitive', 'sensitive', 'encrypted'],
  );
  assert.deepEqual(envOf('K_ordinary')?.target, ['production', 'preview']);
});

test('KBOX-4 KBOX-36 ready works in a fresh redeployer (a new process) from the DeployRef and the master alone', async () => {
  const slow = await vercelWorld({ buildPolls: 2 });
  const ref = await slow.kit.redeployer?.redeploy(target, master());
  assert.ok(ref !== undefined);
  const fresh = slow.entryOver(slow.http).destinations?.[0]?.redeployer;
  assert.ok(fresh !== undefined && fresh !== slow.kit.redeployer);
  assert.equal(await fresh.ready(ref, master()), 'ready');
  assert.deepEqual(slow.pauses, [5000, 5000]);
});

test('KBOX-36 a fresh redeployer takes the ready deadline from the ready call: a deploy still building after 15 minutes is failed', async () => {
  const stuck = await vercelWorld({ buildPolls: 1_000_000 });
  const ref = await stuck.kit.redeployer?.redeploy(target, master());
  assert.ok(ref !== undefined);
  stuck.clock.advance(60_000);
  const fresh = stuck.entryOver(stuck.http).destinations?.[0]?.redeployer;
  const started = stuck.clock.now();
  assert.equal(await fresh?.ready(ref, master()), 'failed');
  const waited = stuck.clock.now() - started;
  assert.ok(waited >= 15 * 60_000 && waited < 15 * 60_000 + 5000, `waited ${waited} ms`);
});
