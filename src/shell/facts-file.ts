// The bootstrap facts file (`/var/lib/keybox/bootstrap-facts.json`): names and numbers, never a gate and never a secret. kb-join and kb-bench
// both read-change-write it through this one function.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { decodeJsonBody } from '../pure/schemas.ts';

export type Json = Record<string, unknown>;
export const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Reads the facts file (an absent or unreadable one starts empty: facts are names and numbers, never a gate), changes it, and
 * replaces it whole, world-readable. */
export function updateFacts(path: string, change: (facts: Json) => void): void {
  const decoded = existsSync(path) ? decodeJsonBody(readFileSync(path)) : { ok: false as const };
  const facts: Json = decoded.ok && isObject(decoded.value) ? decoded.value : {};
  change(facts);
  mkdirSync(dirname(path), { recursive: true });
  const next = `${path}.new`;
  writeFileSync(next, `${JSON.stringify(facts)}\n`);
  chmodSync(next, 0o644);
  renameSync(next, path);
}
