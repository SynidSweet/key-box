// KBOX-29: untrusted input becomes a typed value at the edge, or a refusal that says nothing about the input.
import { AdapterError } from './errors.ts';

/** JSON text from an upstream platform. A failure is a fixed error: the text may hold a new key and is never quoted. */
export function parseUpstreamJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new AdapterError('bad_response');
  }
}
