// KBOX-39: the workspace's service accounts and the keys each holds, read from `GET /v1/service-accounts`.
// ASSUMED (not a probe item): the answer is `{ "service-accounts": [ { service_account_user_id, name, "api-keys": [ { key_id, name, is_disabled } ] } ] }`.
// A key's own service account is found here, so a revoke needs only the key id.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { ElevenLabsError, call, expectJson, isRecord } from './api.ts';
import { REGIONS } from './regions.ts';
import type { Region } from './regions.ts';

export interface DirectoryKey {
  readonly keyId: string;
  readonly name: string;
  readonly disabled: boolean;
}

export interface ServiceAccount {
  readonly id: string;
  readonly keys: readonly DirectoryKey[];
}

const text = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

function parseKey(raw: unknown): DirectoryKey {
  if (!isRecord(raw)) throw new ElevenLabsError('malformed');
  const keyId = text(raw['key_id']);
  const disabled = raw['is_disabled'];
  if (keyId === undefined || (disabled !== undefined && typeof disabled !== 'boolean')) throw new ElevenLabsError('malformed');
  return { keyId, name: typeof raw['name'] === 'string' ? raw['name'] : '', disabled: disabled === true };
}

function parseAccount(raw: unknown): ServiceAccount {
  if (!isRecord(raw)) throw new ElevenLabsError('malformed');
  const id = text(raw['service_account_user_id']);
  const keys = raw['api-keys'] ?? [];
  if (id === undefined || !Array.isArray(keys)) throw new ElevenLabsError('malformed');
  return { id, keys: keys.map(parseKey) };
}

export async function readServiceAccounts(http: AdapterHttp, region: Region, master: Lent): Promise<ServiceAccount[]> {
  const body = expectJson(await call(http, region, 'GET', '/v1/service-accounts', master));
  const accounts = isRecord(body) ? body['service-accounts'] : undefined;
  if (!Array.isArray(accounts)) throw new ElevenLabsError('malformed');
  return accounts.map(parseAccount);
}

/**
 * Runs `read` in each region in turn. A region that refuses the master (a master belongs to one workspace) is skipped; a failure of any
 * other kind stops the run, since a region that could not be read proves nothing. Throws `rejected` when every region refused.
 */
export async function inEachRegion<T>(regions: readonly Region[], read: (region: Region) => Promise<T>): Promise<{ readonly region: Region; readonly value: T }[]> {
  const attempt = async (region: Region): Promise<{ readonly region: Region; readonly value: T } | 'refused'> => {
    try {
      return { region, value: await read(region) };
    } catch (e) {
      if (e instanceof ElevenLabsError && e.code === 'rejected') return 'refused';
      throw e;
    }
  };
  const attempts = await Promise.all(regions.map(attempt));
  const answered = attempts.flatMap((a) => (a === 'refused' ? [] : [a]));
  if (answered.length === 0) throw new ElevenLabsError('rejected');
  return answered;
}

export interface FoundKey {
  readonly region: Region;
  readonly serviceAccount: string;
}

/** Where the key `id` lives, or undefined when no region the master can read holds it. */
export async function locateKey(http: AdapterHttp, id: string, master: Lent): Promise<FoundKey | undefined> {
  const regions = await inEachRegion(REGIONS, (region) => readServiceAccounts(http, region, master));
  for (const { region, value } of regions) {
    const account = value.find((a) => a.keys.some((k) => k.keyId === id));
    if (account !== undefined) return { region, serviceAccount: account.id };
  }
  return undefined;
}
