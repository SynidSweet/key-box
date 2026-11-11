// KBOX-51 step 10: revoke a key at its platform, then CONFIRM it is dead. A 404 is not proof. The proof is the verifier rejecting the
// value (the vault still holds it), or, where the platform has no verifier call, the lister showing the id nowhere. One home for the
// new key's revoke on a failed run, the old key's revoke after the grace, and the orphan found by reconcile.
import type { Lent, PlatformId, PlatformKeyId } from '../ports/types.ts';
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
  /** Null for a key the box did not make (pasted): there is nothing to revoke here, only to watch. */
  readonly id: PlatformKeyId | null;
  /** The value, when the vault holds it: the verifier tests it. */
  readonly value: Lent | undefined;
  readonly master: Lent;
}

/** Revokes (when the box can) and confirms. True only when the old value is proven dead. */
export async function revokeAndConfirm(target: RevokeTarget): Promise<boolean> {
  const { id, kit } = target;
  const issuer = kit.issuer;
  if (id !== null && issuer !== undefined) await settled(() => issuer.revoke(id, target.master));
  return confirm(target);
}

/** The evidence after a revoke: what the platform says now, not what the revoke call answered. */
async function confirm(target: RevokeTarget): Promise<boolean> {
  const { kit, id, value } = target;
  if (kit.verifier !== undefined && value !== undefined) {
    const verifier = kit.verifier;
    const verdict = await settled(() => verifier.verify(value, { platform: target.platform }));
    const evidence: Evidence = { by: 'verifier', verdict: verdict.ok ? verdict.value : 'unreachable' };
    return confirmDead(evidence);
  }
  if (kit.lister !== undefined && id !== null) {
    const lister = kit.lister;
    const listed = await settled(() => lister.list(target.master));
    return confirmDead({ by: 'lister', id, listed: listed.ok ? listed.value : undefined });
  }
  return false;
}
