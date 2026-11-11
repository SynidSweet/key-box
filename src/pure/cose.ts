// KBOX-49: the only CBOR the box parses is one COSE_Key at registration: EC2, P-256, ES256, with small-integer labels and
// integer or byte-string values. Anything else (another key type, an extra or repeated member, a float, a tag, a text
// string, an indefinite length, trailing bytes) is refused. A refusal says nothing about the input.
import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/** A P-256 public key as its two 32-byte coordinates. */
export interface Es256PublicKey {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
}

export type KeyParse = { readonly ok: true; readonly key: Es256PublicKey } | { readonly ok: false };

const refused = { ok: false } as const;
const COORD = 32;

type Item = { readonly kind: 'int'; readonly value: number } | { readonly kind: 'bytes'; readonly value: Uint8Array };

class Reader {
  #at = 0;
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  get done(): boolean {
    return this.#at === this.bytes.length;
  }

  #byte(): number | undefined {
    const b = this.bytes[this.#at];
    if (b !== undefined) this.#at += 1;
    return b;
  }

  /** A head's argument: immediate, or one or two following bytes, minimally encoded. */
  #argument(info: number): number | undefined {
    if (info < 24) return info;
    if (info === 24) {
      const n = this.#byte();
      return n !== undefined && n >= 24 ? n : undefined;
    }
    if (info === 25) {
      const hi = this.#byte();
      const lo = this.#byte();
      if (hi === undefined || lo === undefined) return undefined;
      const n = (hi << 8) | lo;
      return n >= 256 ? n : undefined;
    }
    return undefined;
  }

  head(): { readonly major: number; readonly argument: number } | undefined {
    const b = this.#byte();
    if (b === undefined) return undefined;
    const argument = this.#argument(b & 0x1f);
    return argument === undefined ? undefined : { major: b >> 5, argument };
  }

  take(n: number): Uint8Array | undefined {
    if (this.#at + n > this.bytes.length) return undefined;
    const out = this.bytes.slice(this.#at, this.#at + n);
    this.#at += n;
    return out;
  }

  item(): Item | undefined {
    const h = this.head();
    if (h === undefined) return undefined;
    if (h.major === 0) return { kind: 'int', value: h.argument };
    if (h.major === 1) return { kind: 'int', value: -1 - h.argument };
    if (h.major === 2) {
      const value = this.take(h.argument);
      return value === undefined ? undefined : { kind: 'bytes', value };
    }
    return undefined;
  }
}

const LABELS = { kty: 1, alg: 3, crv: -1, x: -2, y: -3 } as const;
const EC2 = 2;
const ES256 = -7;
const P256 = 1;

/** Decodes exactly one COSE_Key map of EC2 P-256 ES256, with nothing after it, whose point is on the curve. */
export function decodeCoseEs256(bytes: Uint8Array): KeyParse {
  const reader = new Reader(bytes);
  const map = reader.head();
  if (map === undefined || map.major !== 5 || map.argument !== Object.keys(LABELS).length) return refused;
  const members = new Map<number, Item>();
  for (let i = 0; i < map.argument; i += 1) {
    const label = reader.item();
    const value = reader.item();
    if (label?.kind !== 'int' || value === undefined || members.has(label.value)) return refused;
    members.set(label.value, value);
  }
  if (!reader.done) return refused;
  const int = (label: number): number | undefined => {
    const m = members.get(label);
    return m?.kind === 'int' ? m.value : undefined;
  };
  const coord = (label: number): Uint8Array | undefined => {
    const m = members.get(label);
    return m?.kind === 'bytes' && m.value.length === COORD ? m.value : undefined;
  };
  if (int(LABELS.kty) !== EC2 || int(LABELS.alg) !== ES256 || int(LABELS.crv) !== P256) return refused;
  const x = coord(LABELS.x);
  const y = coord(LABELS.y);
  if (x === undefined || y === undefined) return refused;
  return onCurve({ x, y });
}

/** An uncompressed P-256 point, `0x04 || x || y`, as WebCrypto exports a public key raw. */
export function parseRawPoint(bytes: Uint8Array): KeyParse {
  if (bytes.length !== 1 + 2 * COORD || bytes[0] !== 0x04) return refused;
  return onCurve({ x: bytes.slice(1, 1 + COORD), y: bytes.slice(1 + COORD) });
}

export function rawPoint(key: Es256PublicKey): Uint8Array {
  return Uint8Array.from([0x04, ...key.x, ...key.y]);
}

export function keyObject(key: Es256PublicKey): KeyObject {
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: Buffer.from(key.x).toString('base64url'), y: Buffer.from(key.y).toString('base64url') }, format: 'jwk' });
}

function onCurve(key: Es256PublicKey): KeyParse {
  try {
    keyObject(key);
    return { ok: true, key };
  } catch {
    return refused;
  }
}
