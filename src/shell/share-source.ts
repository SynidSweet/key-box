// KBOX-33: the share source over the box's own metadata. For every admin and master key row it reads the current generation's value
// (through the ShareValues port) and pairs it with the adapter's shape for the key's platform. A key that has no shape yet (no
// adapter registered), no stored value, or a value that is not UTF-8 text is listed with no value and so is not watched. The
// generations a rotation retired follow the current one with `retired: true` (what rotate records, through `generations`): one in
// grace still has its value in the vault and is watched; one the rotation has revoked has none (the vault retires the value with
// the key), so it is listed and not watched. "Box generated" is not yet known: every value is `pasted`, which holds it to the strict
// shape check.
import type { MetaStore } from '../ports/meta.ts';
import type { ShareSource, ShareValues } from '../ports/share.ts';
import type { KeyShape } from '../ports/types.ts';
import type { ShareKey } from '../pure/share-build.ts';
import type { GenRow } from './rotation-store.ts';

export interface MetaShareSourceDeps {
  readonly meta: Pick<MetaStore, 'snapshot'>;
  readonly values: ShareValues;
  /** The adapter's `shape` for a platform, or undefined while none is registered. */
  shapeOf(platform: string): KeyShape | undefined;
  /** The generations the rotation store holds for a key. Absent where nothing rotates: only current generations are listed. */
  readonly generations?: (keyref: string) => readonly Pick<GenRow, 'gen' | 'status'>[];
}

/** The project a key with no project is listed under. */
const NO_PROJECT = '-';

/** The generations of a key that were live and are not the current one: in grace, or revoked and retired. A pending or failed one never was. */
function retiredGenerations(rows: readonly Pick<GenRow, 'gen' | 'status'>[], current: number): number[] {
  return rows
    .filter((row) => row.gen !== current && (row.status === 'grace' || row.status === 'retired'))
    .map((row) => row.gen)
    .sort((a, b) => a - b);
}

export function createMetaShareSource(deps: MetaShareSourceDeps): ShareSource {
  return {
    async keys() {
      const out: ShareKey[] = [];
      for (const key of deps.meta.snapshot().keys) {
        if (key.class === 'ordinary') continue;
        const shape = deps.shapeOf(key.platform);
        const gens = [{ gen: key.gen_current, retired: false }, ...retiredGenerations(deps.generations?.(key.keyref) ?? [], key.gen_current).map((gen) => ({ gen, retired: true }))];
        // A row may list a project twice; the file holds one entry set per project, name and generation.
        const projects = key.projects.length === 0 ? [NO_PROJECT] : [...new Set(key.projects)];
        for (const { gen, retired } of gens) {
          const value = shape === undefined ? '' : await deps.values.text(key.keyref, gen);
          for (const project of projects) out.push({ project, name: key.name, gen, retired, shape, origin: 'pasted', value });
        }
      }
      return out;
    },
  };
}
