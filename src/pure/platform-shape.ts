// KBOX-23, KBOX-40, KBOX-58: the one source of a platform's key shape, and of a key's. A platform that issues states it in its capabilities (and
// may state the shape of a key of another kind, `shapeFor`); one that does not (a paste-only platform) states it on its registry entry. Works on an
// entry and on the kit built from it.
import type { Issuer, KeyKind } from '../ports/issuer.ts';
import type { KeyClass, KeyLocation, KeyShape, Scope } from '../ports/types.ts';

export interface ShapeSource {
  readonly issuer?: Issuer;
  readonly shape?: KeyShape;
}

export const shapeOf = (source: Pick<ShapeSource, 'issuer' | 'shape'> | undefined): KeyShape | undefined => source?.issuer?.capabilities().shape ?? source?.shape;

/** KBOX-58: the shape of one key, by its stored scope items and location: the issuer's `shapeFor` when it names one, else the platform's shape. */
export const shapeOfKey = (source: Pick<ShapeSource, 'issuer' | 'shape'> | undefined, key: KeyKind): KeyShape | undefined =>
  source?.issuer?.capabilities().shapeFor?.({ items: key.scopeItems }, key.at) ?? shapeOf(source);

export interface ClassSource {
  readonly issuer?: Issuer;
  readonly classify?: (scope: Scope, at: KeyLocation) => KeyClass;
}

/** KBOX-40, KBOX-15: the one source of a platform's key class. An issuer classifies its own scopes; a platform with no issuer states `classify`. */
export function classifierOf(source: ClassSource | undefined): ((scope: Scope, at: KeyLocation) => KeyClass) | undefined {
  const issuer = source?.issuer;
  return issuer === undefined ? source?.classify : (scope, at) => issuer.capabilities().classify(scope, at);
}
