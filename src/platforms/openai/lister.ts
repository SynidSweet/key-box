// KBOX-38, KBOX-51: the OpenAI key lister. A key is listed as `<project>/<key id>` under its name (the intent name it was made with), located at
// its project. A listing is complete only when every page of every project asked for was read.
import type { AdapterHttp } from '../../ports/http.ts';
import type { KeyListing, KeyLister, PlatformKeyInfo } from '../../ports/issuer.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import type { Json } from './client.ts';
import { ID, OpenAiError, idOf, readAll } from './client.ts';
import { keyIdOf } from './scope.ts';

const infoOf = (project: string, row: Json): PlatformKeyInfo | undefined => {
  const key = idOf(row['id']);
  return key === undefined ? undefined : { platformKeyId: keyIdOf(project, key), name: typeof row['name'] === 'string' ? row['name'] : '', location: { project } };
};

export function createOpenAiLister(http: AdapterHttp): KeyLister {
  /** The ids of every project, or the failure that stopped the read. */
  async function projects(master: Lent): Promise<{ readonly ids: readonly string[]; readonly complete: boolean; readonly failure: OpenAiError | undefined }> {
    const read = await readAll(http, master, '/v1/organization/projects');
    return { ids: read.rows.map((r) => idOf(r['id'])).filter((id) => id !== undefined), complete: read.failure === undefined, failure: read.failure };
  }

  /** The keys of one project. A project the platform does not have holds none, and says so completely. */
  async function keysOf(project: string, master: Lent): Promise<{ readonly keys: readonly PlatformKeyInfo[]; readonly failure: OpenAiError | undefined }> {
    const read = await readAll(http, master, `/v1/organization/projects/${project}/api_keys`);
    const keys = read.rows.map((r) => infoOf(project, r)).filter((k) => k !== undefined);
    return read.failure?.code === 'not_found' ? { keys: [], failure: undefined } : { keys, failure: read.failure };
  }

  return {
    async list(master: Lent): Promise<PlatformKeyInfo[]> {
      const listing = await this.listAt({}, master);
      if (!listing.complete) throw new OpenAiError('upstream_error');
      return [...listing.keys];
    },
    async listAt(at: KeyLocation, master: Lent): Promise<KeyListing> {
      let wanted: readonly string[];
      let complete = true;
      if (at.project === undefined) {
        const all = await projects(master);
        // A refused master is an error; any other failure of the project list only makes the listing incomplete.
        if (all.failure?.code === 'rejected') throw all.failure;
        wanted = all.ids;
        complete = all.complete;
      } else {
        if (!ID.test(at.project)) throw new OpenAiError('bad_scope');
        wanted = [at.project];
      }
      const keys: PlatformKeyInfo[] = [];
      for (const project of wanted) {
        const read = await keysOf(project, master);
        keys.push(...read.keys);
        if (read.failure?.code === 'rejected') throw read.failure;
        if (read.failure !== undefined) complete = false;
      }
      return { complete, at, keys };
    },
  };
}
