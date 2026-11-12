// KBOX-51 step 10: end a key at its platform (revoke, retire or the owner), then CONFIRM it is dead. A 404 is not proof. The proof is the verifier rejecting the
// value (the vault still holds it), or, where the platform has no verifier call, a complete listing of the key's recorded location showing
// the id absent or disabled. One home for the new key's revoke on a failed run, the old key's revoke after the grace, and the orphan found by reconcile.
import type { KeyLocation, Lent, PlatformId, PlatformKeyId } from '../ports/types.ts';
import { confirmDead } from '../pure/rotation-machine.ts';
import type { Evidence } from '../pure/rotation-machine.ts';
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
  const { id, kit, value } = target;
  const { issuer, retirer } = kit;
  switch (enderOf(kit, id)) {
    case 'issuer':
      if (id !== null && issuer !== undefined) await settled(() => issuer.revoke(id, target.master));
      break;
    case 'retirer':
      if (retirer !== undefined && value !== undefined) await settled(() => retirer.retire(value, target.at, target.master));
      break;
    case 'owner':
      break;
  }
  return confirm(target);
}

/** The evidence after a revoke: what the platform says now, not what the revoke call answered. */
async function confirm(target: RevokeTarget): Promise<boolean> {
  const { kit, id, value } = target;
  if (kit.verifier !== undefined && value !== undefined) {
    const verifier = kit.verifier;
    const verdict = await settled(() => verifier.verify(value, { platform: target.platform, at: target.at, ...(target.hint === undefined ? {} : { hint: target.hint }) }));
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
