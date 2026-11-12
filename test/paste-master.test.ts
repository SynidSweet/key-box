// KBOX-58 on the paste flow: a verifier that declares `needsMaster` is handed the master KBOX-57 chooses for the key, resolved when the
// pasted value is checked; no other verifier is handed one, and none causes a master lookup. Real core and approver proofs, the paste
// test world; only the verifier and the master the source chooses are planted at the platform source port.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { VerifyTarget, Verifier } from '../src/ports/issuer.ts';
import { bytesOf, lent } from './kit/index.ts';
import { PASTE_PLATFORM, pasteValue, routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';

const HEX = 'a'.repeat(32);
const MASTER_VALUE = 'stored-master-value';
const NO_MASTER = { ok: false, code: 'no_master' } as const;

interface Seen {
  readonly target: VerifyTarget;
  /** The master's value as the verifier read it, when a master member was handed. */
  readonly masterValue: string | undefined;
  /** How many master lookups the source had answered when this call arrived. */
  readonly lookupsBefore: number;
}

/** A paste world whose verifier records what it is asked and answers `ok` for the accepted value only when it got the master it needs. */
async function worldWith(t: Parameters<typeof routesWorld>[0], options: { needsMaster: boolean; masterStored: boolean }): Promise<{ w: RoutesWorld; seen: Seen[]; lookups: () => number }> {
  const seen: Seen[] = [];
  let lookups = 0;
  const w = await routesWorld(t, {
    source: (real) => ({
      ...real,
      platform: (id) => {
        const kit = real.platform(id);
        if (id !== PASTE_PLATFORM || kit === undefined) return kit;
        const verifier: Verifier = {
          ...(options.needsMaster ? { needsMaster: true as const } : {}),
          verify: async (key, target) => {
            const masterValue = target.master === undefined ? undefined : Buffer.from(await bytesOf(target.master)).toString('utf8');
            seen.push({ target, masterValue, lookupsBefore: lookups });
            const accepted = w.accepted.has(Buffer.from(await bytesOf(key)).toString('utf8'));
            if (options.needsMaster && masterValue === undefined) return 'unreachable';
            return accepted ? 'ok' : 'rejected';
          },
        };
        return { ...kit, verifier };
      },
      master: () => {
        lookups += 1;
        return options.masterStored ? { ok: true, value: lent(Buffer.from(MASTER_VALUE, 'utf8'), 'master') } : NO_MASTER;
      },
    }),
  });
  return { w, seen, lookups: () => lookups };
}

async function pasteOnce(w: RoutesWorld): Promise<{ status: number; code: string | undefined }> {
  const reply = await w.api('/api/keys', { json: { platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', projects: ['shop'], scope: { items: ['admin'] } } });
  assert.equal(reply.status, 202, reply.body);
  const id = (reply.json() as { paste_task_id: string }).paste_task_id;
  const cookie = await w.view();
  const page = await w.call(`/p/${id}`, { cookie });
  assert.equal(page.status, 200, page.body);
  w.accepted.add(pasteValue(HEX));
  const posted = await w.call(`/p/${id}`, { cookie, json: { value: pasteValue(HEX), proof: w.pasteProof(page.json() as Parameters<RoutesWorld['pasteProof']>[0]) } });
  const detail = (posted.json() as { error?: { detail?: { code?: string } } }).error?.detail?.code;
  return { status: posted.status, code: detail };
}

test('KBOX-58 a pasted value is checked by a needsMaster verifier with the stored master lent to it, and the paste goes on', async (t) => {
  const { w, seen } = await worldWith(t, { needsMaster: true, masterStored: true });
  const done = await pasteOnce(w);
  assert.equal(done.status, 201, `refused with ${done.code}`);
  const first = seen[0];
  assert.ok(first !== undefined, 'the verifier was asked');
  assert.equal(first.masterValue, MASTER_VALUE, 'the first ask (the paste check) lent the stored master');
});

test('KBOX-58 a verifier without needsMaster is handed no master member and the paste flow looks no master up for it', async (t) => {
  const { w, seen } = await worldWith(t, { needsMaster: false, masterStored: true });
  const done = await pasteOnce(w);
  assert.equal(done.status, 201, `refused with ${done.code}`);
  const first = seen[0];
  assert.ok(first !== undefined, 'the verifier was asked');
  assert.equal('master' in first.target, false, 'no master member');
  assert.equal(first.lookupsBefore, 0, 'no master lookup before the paste check');
});

test('KBOX-58 a needsMaster verifier with no master to choose is asked without one, and its unreachable answer refuses the paste verifier_unreachable', async (t) => {
  const { w, seen } = await worldWith(t, { needsMaster: true, masterStored: false });
  const done = await pasteOnce(w);
  assert.equal(done.status, 422);
  assert.equal(done.code, 'verifier_unreachable');
  assert.equal(seen.length, 1);
  assert.equal('master' in (seen[0]?.target ?? {}), false, 'no master member');
});
