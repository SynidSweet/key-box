import { inspect } from 'node:util';
import type { Lent } from '../../src/ports/types.ts';

/** A Lent over fixed bytes that shows only its label whenever it is printed, stringified or inspected. */
export function lent(bytes: Uint8Array, label: string): Lent {
  const copy = Uint8Array.from(bytes);
  const shown = `[key ${label}]`;
  const handle: Lent = { use: (fn) => fn(Uint8Array.from(copy)) };
  Object.defineProperty(handle, 'toString', { value: () => shown });
  Object.defineProperty(handle, 'toJSON', { value: () => shown });
  Object.defineProperty(handle, inspect.custom, { value: () => shown });
  return handle;
}

/** The bytes behind a Lent, for a test that has to compare them. */
export const bytesOf = (l: Lent): Promise<Uint8Array> => l.use((b) => Promise.resolve(Uint8Array.from(b)));
