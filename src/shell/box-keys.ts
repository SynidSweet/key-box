// KBOX-55: the masters the box makes itself (Google's signing key), made once at core start. Core calls this when the box has its identity
// (KB_DOMAIN and KB_OIDC_AUDIENCE set) and the rotation store is open, after rotation opens and before the server listens. No approval and no
// paste task: like the share key, the key grants nothing until the owner makes a pool and provider in their own project that trust the box.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { BoxMadeKey, PlatformEntry } from '../ports/platform.ts';
import type { Random } from '../ports/random.ts';
import type { Vault } from '../ports/vault.ts';
import { boxKeyrefOf } from './rotation-ports.ts';
import type { RotationStore } from './rotation-store.ts';

export interface BoxKeyDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot' | 'putKey'>;
  readonly vault: Pick<Vault, 'put'>;
  readonly store: Pick<RotationStore, 'gens' | 'topGen' | 'putKeyInfo' | 'putGen'>;
  readonly random: Random;
  readonly clock: Clock;
  readonly audit: Audit;
}

/** The schedule a box-made key starts with (KBOX-55): the master default, and one hour of grace for the old generation. */
const ROTATE_EVERY_DAYS = 90;
const GRACE_HOURS = 1;

/**
 * Makes each registered box-made key that has no `current` generation. Another master row of the same platform (left from old data) stops
 * it: two masters would make the box's identity ambiguous, so nothing is written and `box_key.conflict` is audited. Otherwise the value is drawn
 * and stored as generation G (the highest so far plus 1), then, in this order and each safe to repeat: the key row if absent, the rotation
 * record dated now (without which the key never falls due), and generation G as `current`. A crash before the last write leaves no current
 * generation, so the next start makes the key again; the value it leaves behind was never published.
 */
export function ensureBoxKeys(deps: BoxKeyDeps): void {
  for (const entry of deps.registry) {
    if (entry.boxKey !== undefined) ensureBoxKey(deps, entry.id, entry.boxKey);
  }
}

function ensureBoxKey(deps: BoxKeyDeps, platform: string, box: BoxMadeKey): void {
  const keyref = boxKeyrefOf(platform, box);
  if (deps.store.gens(keyref).some((g) => g.status === 'current')) return;
  const rows = deps.meta.snapshot().keys;
  if (rows.some((k) => k.platform === platform && k.class === 'master' && k.keyref !== keyref)) {
    deps.audit.append({ action: 'box_key.conflict', subject: keyref, at: deps.clock.now() });
    return;
  }
  const gen = deps.store.topGen(keyref) + 1;
  const value = box.generate(deps.random);
  try {
    deps.vault.put(keyref, gen, value);
  } finally {
    value.fill(0);
  }
  if (!rows.some((k) => k.keyref === keyref)) {
    deps.meta.putKey({
      keyref,
      platform,
      name: box.name,
      projects: [],
      class: 'master',
      status: 'works',
      gen_current: gen,
      schedule: { rotate_every_days: ROTATE_EVERY_DAYS, grace_hours: GRACE_HOURS, next_due_at: null, expires_at: null },
      coverage: null,
      last_use_at: null,
    });
  }
  deps.store.putKeyInfo(keyref, { scopeItems: [], location: {}, rotatedAt: deps.clock.now(), markAdmin: false });
  deps.store.putGen({ keyref, gen, status: 'current', platformKeyId: null, location: {} });
  deps.audit.append({ action: 'key.issued', subject: keyref, at: deps.clock.now() });
}
