// KBOX-4: a Lent hands its bytes to one function and shows only its label everywhere else.
import type { Lent } from '../ports/types.ts';

const INSPECT = Symbol.for('nodejs.util.inspect.custom');

/** `read` gives a fresh copy of the bytes each time; the copy is wiped when `use` ends. */
export function makeLent(label: string, read: () => Uint8Array): Lent {
  const shown = `[key ${label}]`;
  const handle: Lent = {
    use: async (fn) => {
      const bytes = read();
      try {
        return await fn(bytes);
      } finally {
        bytes.fill(0);
      }
    },
  };
  Object.defineProperty(handle, 'toString', { value: () => shown });
  Object.defineProperty(handle, 'toJSON', { value: () => shown });
  Object.defineProperty(handle, INSPECT, { value: () => shown });
  return handle;
}
