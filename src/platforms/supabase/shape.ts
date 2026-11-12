// KBOX-37, KBOX-18: the formats and names of Supabase, one home. A project ref is 20 lower-case letters; a key id is a UUID; the platform key id
// the box keeps is `<ref>:<uuid>`, because a revoke and a listing need the project and the port gives them only the id.
import type { KeyShape, PlatformKeyId } from '../../ports/types.ts';

export const REF_LENGTH = 20;
export const PROJECT_REF = new RegExp(`^[a-z]{${REF_LENGTH}}$`);
const KEY_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** An edge-function secret name: not `SUPABASE_` (reserved), at most 256 characters, environment-variable shaped. */
export const SECRET_NAME = /^(?!SUPABASE_)[A-Za-z_][A-Za-z0-9_]{0,255}$/;
export const PASSWORD = /^[A-Za-z0-9_-]{43}$/;

/**
 * `sb_secret_` is VERIFIED; the length of what follows is not. UNVERIFIED (supabase.sb-secret-length): the core is assumed 20 to 64 characters of
 * base64url (the example key in the API file has a `_` inside its core). A wrong guess can only move a key between watch tiers (KBOX-18).
 */
export const SECRET_SHAPE: KeyShape = { prefix: 'sb_secret_', alphabet: 'base64url', coreLength: { min: 20, max: 64 }, random: true };

export const keyIdOf = (ref: string, id: string): PlatformKeyId => `${ref}:${id}`;

export function splitKeyId(platformKeyId: PlatformKeyId): { readonly ref: string; readonly id: string } | undefined {
  const [ref, id, ...more] = platformKeyId.split(':');
  if (ref === undefined || id === undefined || more.length > 0 || !PROJECT_REF.test(ref) || !KEY_UUID.test(id)) return undefined;
  return { ref, id };
}
