// KBOX-40: what an Anthropic key looks like, and what class a pasted one is. A paste-only platform states both on its entry (no issuer).
import type { KeyClass, KeyShape, Scope } from '../../ports/types.ts';

/** The prefix of an admin key, which can list and change the organization's keys (class master). */
export const ANTHROPIC_ADMIN_PREFIX = 'sk-ant-admin01-';

/**
 * Ordinary keys start `sk-ant-api03-`, admin keys `sk-ant-admin01-`; a shape has one prefix, so it is the common `sk-ant-`.
 * UNVERIFIED (anthropic.key-formats): the core is base64url and 40 to 256 characters; no document states a length. The shape cannot
 * tell a login token (`sk-ant-o...`, out of scope, S-349) from a key: the verifier refuses it, since `x-api-key` does not take one.
 */
export const ANTHROPIC_SHAPE: KeyShape = { prefix: 'sk-ant-', alphabet: 'base64url', coreLength: { min: 40, max: 256 }, random: true };

/** A key pasted with the scope item `admin` is the admin key (master, KBOX-40); any other is ordinary, which is not the box's business (no_issuer). */
export function classifyAnthropic(scope: Scope): KeyClass {
  const items = scope['items'];
  return Array.isArray(items) && items.includes('admin') ? 'master' : 'ordinary';
}
