// KBOX-39: what a scope means here. `items` are permission names (or `all`) plus two placement items: `region:<global|us>` and
// `service-account:<id>`. The class is read from the permission names in permissions.json; a name the file does not know counts as master
// (the enum can grow: fail closed).
import { readFileSync } from 'node:fs';
import type { KeyClass, Scope } from '../../ports/types.ts';
import { ElevenLabsError } from './api.ts';
import { isRegion } from './regions.ts';
import type { Region } from './regions.ts';

interface PermissionClasses {
  readonly master: readonly string[];
  readonly ordinary: readonly string[];
}

function loadPermissions(): PermissionClasses {
  const parsed: unknown = JSON.parse(readFileSync(new URL('./permissions.json', import.meta.url), 'utf8'));
  const names = (v: unknown): v is string[] => Array.isArray(v) && v.every((n): n is string => typeof n === 'string');
  if (typeof parsed !== 'object' || parsed === null || !('master' in parsed) || !('ordinary' in parsed) || !names(parsed.master) || !names(parsed.ordinary)) {
    throw new Error('src/platforms/elevenlabs/permissions.json must hold the lists "master" and "ordinary" of permission names');
  }
  return { master: parsed.master, ordinary: parsed.ordinary };
}

const PERMISSIONS = loadPermissions();
const REGION_ITEM = 'region:';
const ACCOUNT_ITEM = 'service-account:';
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,128}$/;

const itemsOf = (scope: Scope): string[] => {
  const items = scope['items'];
  return Array.isArray(items) ? items.filter((i): i is string => typeof i === 'string') : [];
};
const isPlacement = (item: string): boolean => item.startsWith(REGION_ITEM) || item.startsWith(ACCOUNT_ITEM);

/** KBOX-39: `all` or any master, unknown name is master; otherwise ordinary. */
export function classifyScope(scope: Scope): KeyClass {
  const asked = itemsOf(scope).filter((i) => !isPlacement(i));
  return asked.some((name) => name === 'all' || !PERMISSIONS.ordinary.includes(name)) ? 'master' : 'ordinary';
}

export interface ParsedScope {
  /** The create call's `permissions`: a list of names, or the string `all`. */
  readonly permissions: readonly string[] | 'all';
  readonly region: Region;
  readonly serviceAccount: string | undefined;
}

/** Refuses (before any call) a region that is not one of the two and a service-account id that is not a plain id. */
export function parseScope(scope: Scope): ParsedScope {
  const items = itemsOf(scope);
  const regions = items.filter((i) => i.startsWith(REGION_ITEM)).map((i) => i.slice(REGION_ITEM.length));
  const accounts = items.filter((i) => i.startsWith(ACCOUNT_ITEM)).map((i) => i.slice(ACCOUNT_ITEM.length));
  const [region = 'global'] = regions;
  const [serviceAccount] = accounts;
  if (regions.length > 1 || accounts.length > 1 || !isRegion(region) || (serviceAccount !== undefined && !ACCOUNT_ID.test(serviceAccount))) throw new ElevenLabsError('bad_scope');
  // UNVERIFIED (elevenlabs.empty-permissions): what the platform does with `permissions: []` (no scope named). Read as a key with no permission
  // (class ordinary); if it means all, the key is wider than its class says.
  const names = items.filter((i) => !isPlacement(i));
  return { permissions: names.includes('all') ? 'all' : names, region, serviceAccount };
}
