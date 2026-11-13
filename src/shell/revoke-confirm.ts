// KBOX-51 step 10: end a key at its platform (revoke, retire or the owner), then CONFIRM it is dead. A 404 is not proof. The proof is the verifier that
// applies to the key (KBOX-58) rejecting the value (the vault still holds it), or, where no verifier applies or the vault no longer holds the value, a
// complete listing of the key's recorded location showing the id absent or disabled; never the lister because a verifier that applies is unreachable.
// One home for the new key's revoke on a failed run, the old key's revoke after the grace, and the orphan found by reconcile.
import type { KeyKind } from '../ports/issuer.ts';
import type { KeyLocation, Lent, PlatformId, PlatformKeyId } from '../ports/types.ts';
import { confirmDead } from '../pure/rotation-machine.ts';
import type { Evidence } from '../pure/rotation-machine.ts';
import { verifierFor, verifyTargetOf } from './rotation-ports.ts';
import type { PlatformKit } from './rotation-ports.ts';

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
 * pasted one, else the owner. Whoever it is, only the verifier rejecting the value marks it dead (`confirm`).
 */
export type Ender = 'issuer' | 'retirer' | 'owner';
export const enderOf = (kit: PlatformKit, id: PlatformKeyId | null): Ender => (id !== null ? 'issuer' : kit.retirer !== undefined ? 'retirer' : 'owner');

/** Ends it where someone can (the issuer or the retirer, their answers and failures dropped) and confirms. True only when the old value is proven dead. */
export async function revokeAndConfirm(target: RevokeTarget): Promise<boolean> {
  await end(target);
  return confirm(target);
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

/** The evidence after a revoke: what the platform says now, not what the revoke call answered. */
async function confirm(target: RevokeTarget): Promise<boolean> {
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
