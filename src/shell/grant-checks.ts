// KBOX-24: core's side of the grant check. A key is checked when its platform has a grant check that applies to the key's stored scope; at
// proposal time a grant of such a key is refused unless the check passes; daily, every granted such key is checked again and one that fails is
// suspended (its grants removed) with exactly one notice. A key the check does not apply to (a Google API key) is never checked or suspended.
// Every way the check cannot be made refuses: fail closed. The platform's verdict code is checked before it reaches a reply or a row.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaKey, MetaStore } from '../ports/meta.ts';
import type { GrantCheck, GrantVerdict, PlatformEntry, StoredKey } from '../ports/platform.ts';
import type { KeyLocation, PlatformId } from '../ports/types.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError, DETAIL_CODE } from '../pure/errors.ts';
import type { MasterResult } from './rotation-ports.ts';

export interface GrantChecksDeps {
  readonly registry: readonly PlatformEntry[];
  readonly meta: Pick<MetaStore, 'snapshot' | 'removeGrant'>;
  /** A key's stored scope and location (`readKeyInfo` over meta.db): what decides whether the check applies, and where the master is chosen. */
  readonly keyInfo: (keyref: string) => StoredKey | undefined;
  /** KBOX-57: the platform's master for a key at its stored location with its stored scope (the platform source's `master`). */
  readonly master: (platform: PlatformId, at: KeyLocation, items: readonly string[]) => MasterResult;
  readonly audit: Audit;
  readonly events: Pick<EventLog, 'append'>;
  readonly clock: Clock;
}

export interface GrantChecks {
  /** KBOX-24 at proposal time: resolves when the action may be proposed; throws `rejected` with the refusal's code otherwise. */
  atProposal(action: Action): Promise<void>;
  /** KBOX-24 daily: suspends each granted key that no longer passes, with one notice per key. */
  daily(): Promise<void>;
}

const PASS: GrantVerdict = { verdict: 'pass' };
const refused = (code: string): GrantVerdict => ({ verdict: 'refused', code });

/** Whether the check applies to these items; an `appliesTo` that throws counts as applies (fail closed). */
function applies(check: GrantCheck, items: readonly string[]): boolean {
  try {
    return check.appliesTo(items);
  } catch {
    return true;
  }
}

export function createGrantChecks(deps: GrantChecksDeps): GrantChecks {
  const checkOf = (platform: PlatformId): GrantCheck | undefined => deps.registry.find((e) => e.id === platform)?.grantCheck;

  /** The verdict on one key; a key whose platform has no check, or whose stored scope it does not apply to, passes. Nothing else lets a key through. */
  const verdictOn = async (key: MetaKey): Promise<GrantVerdict> => {
    const check = checkOf(key.platform);
    if (check === undefined) return PASS;
    const stored = deps.keyInfo(key.keyref);
    // Without the stored scope it cannot be told whether the check applies: refused.
    if (stored === undefined) return refused('grant_check_no_key_info');
    if (!applies(check, stored.scopeItems)) return PASS;
    const master = deps.master(key.platform, stored.location, stored.scopeItems);
    if (!master.ok) return refused(`grant_check_${master.code}`);
    let verdict: GrantVerdict;
    try {
      verdict = await check.check({ keyref: key.keyref, at: stored.location }, master.value);
    } catch {
      return refused('grant_check_failed');
    }
    return verdict.verdict === 'refused' && !DETAIL_CODE.test(verdict.code) ? refused('grant_check_failed') : verdict;
  };

  const keyOf = (keyref: string): MetaKey | undefined => deps.meta.snapshot().keys.find((k) => k.keyref === keyref);

  return {
    async atProposal(action) {
      if (action.kind !== 'grant') return;
      const key = keyOf(action.keyref);
      if (key === undefined) return;
      const verdict = await verdictOn(key);
      if (verdict.verdict === 'refused') throw new ApiError('rejected', verdict.code);
    },
    async daily() {
      const granted = deps.meta.snapshot().keys.filter((k) => k.grants.length > 0 && checkOf(k.platform) !== undefined);
      for (const key of granted) {
        const verdict = await verdictOn(key);
        if (verdict.verdict === 'pass') continue;
        for (const grant of key.grants) deps.meta.removeGrant(key.keyref, grant.machine);
        deps.audit.append({ action: 'grant.suspended', subject: key.keyref, at: deps.clock.now(), detail: { code: verdict.code } });
        deps.events.append('box.notice', { code: 'grant_suspended', text: 'grant suspended' });
      }
    },
  };
}
