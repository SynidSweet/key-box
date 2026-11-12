import type { KeyLister, PlatformKeyInfo } from '../../src/ports/issuer.ts';
import type { Lent } from '../../src/ports/types.ts';

/**
 * Every key a lister's master sees, through its platform-wide `list`. A lister without one (Google: no master sees the whole platform) has
 * nothing to call here and a test that asked is wrong: it throws `no list`.
 */
export function listAll(lister: KeyLister, master: Lent): Promise<PlatformKeyInfo[]> {
  const { list } = lister;
  if (list === undefined) throw new Error('no list');
  return list.call(lister, master);
}
