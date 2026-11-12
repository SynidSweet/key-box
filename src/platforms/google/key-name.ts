// KBOX-59: the one home of the name of an API key. A key is stored as `projects/<project>/locations/global/keys/<key id>`, composed from the
// STORED project and the key id Google answered, and never from text an answer carried: no answered project, location or number ever names the
// project of a call. `storedIdOf` is the one function that says whether an answered name is a key of the stored project: the issuer, the lister
// and the verifier all ask it. Pure apart from the project-number read it is handed.
import type { PlatformKeyId } from '../../ports/types.ts';
import { GOOGLE_ID } from './scope.ts';

/** A key id: lower-case letters, digits and hyphens, a hyphen never first, 1 to 63 characters (documentation; the generated form is UNVERIFIED, `google.apikeys-create-answer`). */
export const KEY_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** The id of a key in `project`: the form `platformKeyId` is stored in. */
export const composeId = (project: string, keyId: string): PlatformKeyId => `projects/${project}/locations/global/keys/${keyId}`;

/** A stored `platformKeyId` taken apart, or undefined for any other form (the whole string must match; nothing is trimmed). */
export function parseStoredId(id: string): { readonly project: string; readonly keyId: string } | undefined {
  const [projects, project, locations, location, keys, keyId, extra] = id.split('/');
  if (projects !== 'projects' || locations !== 'locations' || location !== 'global' || keys !== 'keys' || extra !== undefined) return undefined;
  return project !== undefined && keyId !== undefined && GOOGLE_ID.test(project) && KEY_ID.test(keyId) ? { project, keyId } : undefined;
}

/** What a name Google answered says, read apart and believed of nothing: each segment 1 to 64 characters without a slash. */
export interface AnsweredName {
  readonly project: string;
  readonly location: string;
  readonly keyId: string;
}

const SEGMENT = /^[^/]{1,64}$/;

/** An answered key name `projects/<p>/locations/<l>/keys/<k>` taken apart; anything else (no text, another shape, an extra segment) is undefined. */
export function parseAnsweredName(name: unknown): AnsweredName | undefined {
  if (typeof name !== 'string') return undefined;
  const [projects, project, locations, location, keys, keyId, extra] = name.split('/');
  if (projects !== 'projects' || locations !== 'locations' || keys !== 'keys' || extra !== undefined) return undefined;
  return project !== undefined && location !== undefined && keyId !== undefined && SEGMENT.test(project) && SEGMENT.test(location) && SEGMENT.test(keyId) ? { project, location, keyId } : undefined;
}

const NUMBER = /^[0-9]{1,20}$/;

/**
 * The stored id of the key an answer names, when it names a key of `project` (the stored one) and no other: the location is `global`, the key id
 * is of the key-id form, and the answer's project is the stored project's id, or digits equal to the number `numberOf` gives for the stored
 * project (read at most once by whoever built `numberOf`). Anything else is undefined. The id's project is the argument, never the answer's.
 */
export async function storedIdOf(name: unknown, project: string, numberOf: () => Promise<string | undefined>): Promise<PlatformKeyId | undefined> {
  const answered = parseAnsweredName(name);
  if (answered === undefined || answered.location !== 'global' || !KEY_ID.test(answered.keyId)) return undefined;
  if (answered.project === project) return composeId(project, answered.keyId);
  if (NUMBER.test(answered.project) && answered.project === (await numberOf())) return composeId(project, answered.keyId);
  return undefined;
}

/** `read` made once: the first ask reads, every later one is the same answer (the project number of one adapter call). */
export function numberReader(read: () => Promise<string | undefined>): () => Promise<string | undefined> {
  let pending: Promise<string | undefined> | undefined;
  return () => (pending ??= read());
}
