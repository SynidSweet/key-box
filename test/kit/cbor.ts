// The least CBOR a COSE key needs: small integers, byte strings and maps. Written here so the soft
// authenticator shares nothing with src/pure (KBOX-35).
function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  throw new RangeError(`cbor test helper: ${n} is too large`);
}

export type CborValue = number | Uint8Array | ReadonlyMap<number, CborValue>;

export function cborEncode(value: CborValue): Uint8Array {
  if (typeof value === 'number') {
    return Uint8Array.from(value >= 0 ? head(0, value) : head(1, -1 - value));
  }
  if (value instanceof Uint8Array) {
    return Uint8Array.from([...head(2, value.length), ...value]);
  }
  const parts: number[] = head(5, value.size);
  for (const [k, v] of value) parts.push(...cborEncode(k), ...cborEncode(v));
  return Uint8Array.from(parts);
}
