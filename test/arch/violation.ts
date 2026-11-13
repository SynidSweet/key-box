// The closed set of things the architecture checks can find. A test asserts on the code, never on prose.
export type ViolationCode =
  // KBOX-27
  | 'dependencies-key'
  | 'dev-dependency-set'
  | 'dev-dependency-range'
  | 'types-node-major'
  | 'tsconfig-types'
  | 'tsconfig-option'
  | 'tsconfig-include'
  | 'node-module-stub'
  | 'lockfile-missing'
  | 'node-modules-not-ignored'
  | 'node-modules-tracked'
  | 'src-imports-dev-package'
  | 'import-specifier'
  | 'ts-runtime-syntax'
  | 'strip-line-count'
  | 'strip-reparse'
  | 'typecheck'
  | 'count-any'
  | 'count-non-null'
  | 'count-ts-ignore'
  | 'count-ts-expect-error'
  | 'count-ts-nocheck'
  | 'count-eslint-disable'
  | 'count-noqa'
  // KBOX-28
  | 'pure-import'
  | 'pure-global'
  // KBOX-6: kb-install's code is loaded before its first step
  | 'cli-dynamic-import'
  // KBOX-6: kb-install writes only under the spec's paths
  | 'install-write-path'
  | 'layer-import'
  | 'import-cycle'
  | 'silent-catch'
  // KBOX-56
  | 'migration-not-additive'
  // KBOX-35
  | 'kit-shares-verifier'
  // KBOX-42
  | 'probe-missing'
  | 'unverified-list'
  | 'probe-item-missing'
  // KBOX-58: a kit's or entry's verifier is read only through verifierFor
  | 'verifier-read'
  // KBOX-41: RegistryDeps' keyInfo is read only by the Google minter
  | 'keyinfo-read'
| 'verifier-read'
  // KBOX-51, KBOX-62, KBOX-55: only the proof watch, a deletion and a box-made revoke retire a generation
  | 'retire-writer'
  // KBOX-23
  | 'adapter-imports-registry'
  // the checks could not read the tree they were given
  | 'unreadable';

export interface Violation {
  readonly code: ViolationCode;
  readonly file: string;
  readonly detail: string;
}
