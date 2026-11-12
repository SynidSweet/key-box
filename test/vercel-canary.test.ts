// KBOX-14, KBOX-2: a key the Vercel adapter lends or receives never shows in an error, a returned receipt or a printed value, even when the
// platform's own answer quotes it (a 403 whose message holds the presented token, a create response carrying the new one).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import type { Canary } from './kit/index.ts';
import { bytesOf, canary, lent } from './kit/index.ts';
import { PROJECT, lentText, vercelWorld } from './support/vercel-world.ts';

const hexOf = (c: Canary): string => Buffer.from(c.bytes).toString('hex');
const tokenOf = (c: Canary): string => `vcp_${hexOf(c)}`;

/** Everything a caller or a log could print of a thrown value. */
function surfacesOf(error: unknown): Record<string, string> {
  assert.ok(error instanceof Error, 'a failure is an Error');
  return { message: error.message, stack: error.stack ?? '', inspected: inspect(error, { depth: 10 }), json: JSON.stringify(error), cause: inspect(error.cause, { depth: 10 }) };
}

const failure = (run: () => Promise<unknown>): Promise<unknown> => run().then(() => undefined, (e: unknown) => e);

test('KBOX-14 a master the platform refuses, quoted back in the 403 message, is in no error of the issuer, lister, destination or redeployer', async () => {
  const c = canary(24);
  const world = await vercelWorld();
  const bad = lent(Buffer.from(tokenOf(c)), 'master:1');
  const target = { kind: 'vercel-env', id: PROJECT } as const;
  const dest = world.kit.destination;
  const runs: Record<string, () => Promise<unknown>> = {
    issue: () => world.issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_a', bad),
    revoke: () => world.issuer.revoke('t', bad),
    list: () => world.lister.list(bad),
    listAt: () => world.lister.listAt({ project: PROJECT }, bad),
    remove: () => dest.remove(target, 'K', bad),
    redeploy: () => world.kit.redeployer?.redeploy(target, bad) ?? Promise.reject(new Error('no redeployer')),
  };
  for (const [name, run] of Object.entries(runs)) {
    for (const status of [undefined, 401, 403, 500]) {
      world.fake.forceStatus(status);
      const error = await failure(run);
      assert.ok(error !== undefined, `${name} ${String(status)} fails`);
      c.assertAbsent(surfacesOf(error));
    }
  }
  world.fake.forceStatus(undefined);
  const verdict = await world.verifier.verify(bad, { platform: 'vercel' });
  c.assertAbsent({ verdict });
  const outcome = await dest.push(target, 'K', lentText('vcp_KboxTestFakeV'), bad);
  c.assertAbsent({ outcome: JSON.stringify(outcome) });
});

test('KBOX-14 a create response carrying the canary gives a Lent that prints as its label, a key id that is not the value, and no error holds it afterwards', async () => {
  const c = canary(24);
  const world = await vercelWorld({ mint: () => tokenOf(c) });
  const made = await world.issuer.issue({ scope: { projectId: PROJECT } }, 'kbox_a', lentLabelled());
  c.assertAbsent({ printed: String(made.value), json: JSON.stringify(made), inspected: inspect(made, { depth: 10 }), id: made.platformKeyId });
  assert.equal(Buffer.from(await bytesOf(made.value)).toString('utf8'), tokenOf(c), 'the value is still usable inside use()');
  // The new token, used as a master and refused (the platform quotes it), leaks nowhere either.
  world.fake.forceStatus(403);
  for (const run of [() => world.lister.list(made.value), () => world.issuer.revoke('t', made.value), () => world.issuer.issue({ scope: {} }, 'kbox_b', made.value)]) {
    c.assertAbsent(surfacesOf(await failure(run)));
  }
  world.fake.forceStatus(undefined);
  world.fake.cutAnswers(true);
  c.assertAbsent(surfacesOf(await failure(() => world.issuer.issue({ scope: {} }, 'kbox_c', lentLabelled()))));
});

function lentLabelled() {
  return lentText('vcp_KboxTestFakeMasterMMMMMMMMMMMMMMMMMMMM', 'master:1');
}

test('KBOX-14 a value pushed to the destination is in no receipt, refusal or error, whichever way the platform answers', async () => {
  const c = canary(24);
  const world = await vercelWorld();
  const value = lent(Buffer.from(tokenOf(c)), 'k:1');
  const target = { kind: 'vercel-env', id: PROJECT } as const;
  const master = lentLabelled();
  for (const status of [undefined, 400, 403, 409, 500]) {
    world.fake.forceStatus(status);
    c.assertAbsent({ outcome: JSON.stringify(await world.kit.destination.push(target, 'K', value, master)) });
  }
  world.fake.forceStatus(undefined);
  c.assertAbsent({ outcome: JSON.stringify(await world.kit.destination.push(target, 'K', value, master)) });
  world.fake.cutAnswers(true);
  c.assertAbsent({ outcome: JSON.stringify(await world.kit.destination.push(target, 'K', value, master)) });
  world.fake.cutAnswers(false);
  await world.fake.setDown(true);
  c.assertAbsent({ outcome: JSON.stringify(await world.kit.destination.push(target, 'K', value, master)) });
  await world.fake.setDown(false);
});
