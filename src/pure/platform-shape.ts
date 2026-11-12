// KBOX-23, KBOX-40: the one source of a platform's key shape. A platform that issues states it in its capabilities; one that does not (a
// paste-only platform) states it on its registry entry. Works on an entry and on the kit built from it.
import type { Issuer } from '../ports/issuer.ts';
import type { KeyShape } from '../ports/types.ts';

export interface ShapeSource {
  readonly id?: string;
  readonly issuer?: Issuer;
  readonly shape?: KeyShape;
}

export const shapeOf = (source: Pick<ShapeSource, 'issuer' | 'shape'> | undefined): KeyShape | undefined => source?.issuer?.capabilities().shape ?? source?.shape;

/** The shape of the registered platform with this id, or undefined for one that is not registered. */
export const shapeOfPlatform = (registry: readonly ShapeSource[], platform: string): KeyShape | undefined => shapeOf(registry.find((e) => e.id === platform));
