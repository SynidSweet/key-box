// KBOX-51 step 10 (as amended by revoke-proof): end a key at its platform (revoke, retire or the owner), then hear the platform's word. A 404 is not
// its word. The word is the verifier that applies to the key (KBOX-58) rejecting the value (the vault still holds it), or, where no verifier applies or
// the vault no longer holds the value, a complete listing of the key's recorded location showing the id absent or disabled; never the lister because a
// verifier that applies is unreachable. The word ends a run; it is not proof of death and marks nothing dead: only the proven revoked evidence
// (`confirmRevoked`, KBOX-62), seen twice, retires a generation. One home for the new key's end on a failed run, the old key's end after the grace, the
// orphan found by reconcile, a deletion's batch and the proof watch.
import type { KeyKind } from '../ports/issuer.ts';
import type { KeyLocation, Lent, PlatformId, PlatformKeyId } from '../ports/types.ts';
import { confirmDead } from '../pure/rotation-machine.ts';
import type { Evidence } from '../pure/rotation-machine.ts';
import { tryLend, verifierFor, verifyTargetOf } from './rotation-ports.ts';
import type { PlatformKit } from './rotation-ports.ts';
import type { Vault } from '../ports/vault.ts';
import type { GenRow, KeyHead, KeyInfo } from './rotation-store.ts';

type Settled<T> = { readonly ok: true; readonly value: T } | { readonly ok: false };

/** An adapter call as a result: what it threw is the adapter's own text and may hold a key, so it is dropped here. */
async function settled<T>(call: () => Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, value: await call() };
  } catch {
    return { ok: false };
  }
}

export interface RevokeTarget {
  readonly kit: PlatformKit;
  readonly platform: PlatformId;
  /** Null for a key the box did not make (pasted): the entry's retirer or the owner ends it (`enderOf`), and the verifier is watched. */
  readonly id: PlatformKeyId | null;
  /** The region and project recorded with the key: only a complete listing of exactly there can confirm it gone. */
  readonly at: KeyLocation;
  /** The key's stored scope items: with `at`, what decides whether the platform's verifier applies to it (KBOX-58). */
  readonly scopeItems: readonly string[];
  /** The value, when the vault holds it: the verifier tests it. */
  readonly value: Lent | undefined;
  readonly master: Lent;
  /** The key's stored verify hint (KBOX-40), given to the verifier that confirms it dead. */
  readonly hint?: string;
}

/**
 * Who ends a key at step 10 (KBOX-51): the issuer for a generation the box made (it has a platform key id), else the entry's retirer for a
 * pasted one, else the owner. Whoever it is, the platform's word (`platformSaysRefused`) ends a run and proven evidence (`confirmRevoked`) retires.
 */
export type Ender = 'issuer' | 'retirer' | 'owner';
export const enderOf = (kit: PlatformKit, id: PlatformKeyId | null): Ender => (id !== null ? 'issuer' : kit.retirer !== undefined ? 'retirer' : 'owner');

/**
 * Ends it where someone can (the issuer or the retirer, their answers and failures dropped), then asks the platform's ordinary answer. True when
 * that answer says the value no longer works; not proof of death, it marks nothing dead (KBOX-51 step 10 as amended).
 */
export async function revokeAndConfirm(target: RevokeTarget): Promise<boolean> {
  await end(target);
  return platformSaysRefused(target);
}

/** The target a stored generation is ended and asked about with: its id, recorded location, value (when the vault holds it) and the key's hint. */
export function revokeTargetOf(vault: Pick<Vault, 'lend'>, head: Pick<KeyHead, 'keyref' | 'platform'>, info: KeyInfo | undefined, kit: PlatformKit, gen: Pick<GenRow, 'gen' | 'platformKeyId' | 'location'>, master: Lent): RevokeTarget {
  const value = tryLend(vault, head.keyref, gen.gen);
  return {
    kit,
    platform: head.platform,
    id: gen.platformKeyId,
    at: gen.location,
    scopeItems: info?.scopeItems ?? [],
    value: value.ok ? value.value : undefined,
    master,
    ...(info?.verifyHint === undefined ? {} : { hint: info.verifyHint }),
  };
}

/** Ends it where someone can: the issuer's revoke, else the retirer's retire; their answers and failures are dropped (only the evidence counts). */
export async function end(target: RevokeTarget): Promise<void> {
  const { id, kit, value } = target;
  const { issuer, retirer } = kit;
  switch (enderOf(kit, id)) {
    case 'issuer':
      if (id !== null && issuer !== undefined) await settled(() => issuer.revoke(id, target.master));
      return;
    case 'retirer':
      if (retirer !== undefined && value !== undefined) await settled(() => retirer.retire(value, target.at, target.master));
      return;
    case 'owner':
      return;
  }
}

/**
 * KBOX-62: how a deletion can prove a generation revoked, by the kit's proven evidence (`revoked`): the verifier when it applies to the key,
 * answers statuses (`answerStatus`) and the vault holds the value; else a complete listing while the generation has a platform key id and the
 * listing may be used (`listing`: never for a master's own current generation, whose value is what a listing needs); else none.
 */
export function revokedPath(kit: PlatformKit, key: KeyKind, id: PlatformKeyId | null, valueHeld: boolean, listing: boolean): 'verifier' | 'lister' | undefined {
  const verifier = verifierFor(kit, key);
  if (kit.revoked?.statuses !== undefined && verifier?.answerStatus !== undefined && valueHeld) return 'verifier';
  if (kit.revoked?.lister === true && kit.lister !== undefined && id !== null && listing) return 'lister';
  return undefined;
}

/**
 * KBOX-62: whether the generation is proven revoked now, on proven evidence only: the verifier's answer status among the statuses a probe proved
 * mean revoked (a 403, a 404, a network error or any other answer is "not confirmed"), else a complete listing of its recorded location without
 * its id (or with it disabled). The path is `revokedPath`'s; with none nothing is confirmed.
 */
export async function confirmRevoked(target: RevokeTarget, listing: boolean): Promise<boolean> {
  const { kit, id, value } = target;
  const key = { scopeItems: target.scopeItems, at: target.at };
  switch (revokedPath(kit, key, id, value !== undefined, listing)) {
    case 'verifier': {
      const verifier = verifierFor(kit, key);
      const statuses = kit.revoked?.statuses ?? [];
      if (verifier?.answerStatus === undefined || value === undefined) return false;
      const ask = verifier.answerStatus.bind(verifier);
      const asked = verifyTargetOf(verifier, { platform: target.platform, at: target.at, ...(target.hint === undefined ? {} : { hint: target.hint }) }, target.master);
      const answer = await settled(() => ask(value, asked));
      return answer.ok && statuses.includes(answer.value);
    }
    case 'lister': {
      const lister = kit.lister;
      if (lister === undefined || id === null) return false;
      const listed = await settled(() => lister.listAt(target.at, target.master));
      return confirmDead({ by: 'lister', id, at: target.at, listing: listed.ok ? listed.value : undefined });
    }
    case undefined:
      return false;
  }
}

/** The platform's word after an end call: what it says now (the verifier's mapping, else a listing), not what the end call answered. */
async function platformSaysRefused(target: RevokeTarget): Promise<boolean> {
  const { kit, id, value } = target;
  const verifier = verifierFor(kit, { scopeItems: target.scopeItems, at: target.at });
  if (verifier !== undefined && value !== undefined) {
    const asked = verifyTargetOf(verifier, { platform: target.platform, at: target.at, ...(target.hint === undefined ? {} : { hint: target.hint }) }, target.master);
    const verdict = await settled(() => verifier.verify(value, asked));
    const evidence: Evidence = { by: 'verifier', verdict: verdict.ok ? verdict.value : 'unreachable' };
    return confirmDead(evidence);
  }
  if (kit.lister !== undefined && id !== null) {
    const lister = kit.lister;
    const listing = await settled(() => lister.listAt(target.at, target.master));
    return confirmDead({ by: 'lister', id, at: target.at, listing: listing.ok ? listing.value : undefined });
  }
  return false;
}
