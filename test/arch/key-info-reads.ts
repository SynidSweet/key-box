// KBOX-41: a key's stored record reaches an adapter only through `RegistryDeps.keyInfo`, and only the Google minter reads it: it takes a keyref
// and reads that key's own target, so no other adapter code can turn a keyref (or a caller's choice of one) into another key's scope. Any
// property access, element access or destructuring named `keyInfo` on a value typed RegistryDeps (a Pick of it included) anywhere in src/
// outside src/platforms/google/minter.ts is refused.
import type { Violation } from './violation.ts';
import { checkMemberReads } from './member-reads.ts';

export const checkKeyInfoReads = (root: string): Promise<Violation[]> =>
  checkMemberReads(root, {
    member: 'keyInfo',
    owners: new Set(['RegistryDeps']),
    exempt: new Set(['src/platforms/google/minter.ts']),
    code: 'keyinfo-read',
    says: "reads RegistryDeps' keyInfo outside the Google minter",
  });
