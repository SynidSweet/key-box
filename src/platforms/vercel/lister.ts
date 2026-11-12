// KBOX-36, KBOX-51: the Vercel lister, `GET /v6/user/tokens` page by page. The first page failing is an error; a later page failing ends the
// listing as incomplete, so absence from it proves nothing. A cursor seen twice ends it the same way.
import type { KeyListing, KeyLister, PlatformKeyInfo } from '../../ports/issuer.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import { recordOf, textOf } from './api.ts';
import type { VercelApi } from './api.ts';
import { VercelError, requireSuccess } from './errors.ts';

interface Token {
  readonly id: string;
  readonly name: string;
  readonly projectId?: string;
}

interface Page {
  readonly tokens: readonly Token[];
  readonly next: string | undefined;
}

function parsePage(json: unknown): Page {
  const reply = recordOf(json);
  const rows = reply?.['tokens'];
  if (!Array.isArray(rows)) throw new VercelError('malformed');
  const tokens = rows.map((row: unknown): Token => {
    const record = recordOf(row);
    const id = textOf(record?.['id']);
    if (id === undefined) throw new VercelError('malformed');
    const name = typeof record?.['name'] === 'string' ? record['name'] : '';
    const projectId = textOf(record?.['projectId']);
    return { id, name, ...(projectId === undefined ? {} : { projectId }) };
  });
  const next = recordOf(reply?.['pagination'])?.['next'];
  if (next === null || next === undefined) return { tokens, next: undefined };
  // Assumption with no probe row (the listing is read-only and a wrong cursor only ends it early): the cursor is a number the next request passes back as `until`; any other shape ends the listing.
  if (typeof next !== 'number' || !Number.isSafeInteger(next) || next < 0) throw new VercelError('malformed');
  return { tokens, next: String(next) };
}

interface Read {
  readonly tokens: readonly Token[];
  /** Why the listing stopped early; absent when every page was read. */
  readonly stopped?: VercelError;
}

async function readAll(api: VercelApi, master: Lent): Promise<Read> {
  const byId = new Map<string, Token>();
  const seen = new Set<string>();
  let cursor: string | undefined;
  let firstPage = true;
  for (;;) {
    try {
      const answer = await api.call({ method: 'GET', path: '/v6/user/tokens', ...(cursor === undefined ? {} : { query: `until=${cursor}` }) }, master);
      requireSuccess(answer.status);
      const page = parsePage(answer.json);
      firstPage = false;
      for (const token of page.tokens) byId.set(token.id, token);
      if (page.next === undefined) return { tokens: [...byId.values()] };
      if (seen.has(page.next)) return { tokens: [...byId.values()], stopped: new VercelError('malformed') };
      seen.add(page.next);
      cursor = page.next;
    } catch (error) {
      if (!(error instanceof VercelError) || firstPage) throw error;
      return { tokens: [...byId.values()], stopped: error };
    }
  }
}

const infoOf = (token: Token): PlatformKeyInfo => ({ platformKeyId: token.id, name: token.name, ...(token.projectId === undefined ? {} : { location: { project: token.projectId } }) });

export function createVercelLister(api: VercelApi): KeyLister {
  return {
    async list(master: Lent): Promise<PlatformKeyInfo[]> {
      const read = await readAll(api, master);
      if (read.stopped !== undefined) throw read.stopped;
      return read.tokens.map(infoOf);
    },
    async listAt(at: KeyLocation, master: Lent): Promise<KeyListing> {
      const read = await readAll(api, master);
      // A token known to belong to another project is not at this location; one whose project the listing does not say stays in, because
      // leaving it out could confirm a revoke that never happened.
      const here = read.tokens.filter((t) => at.project === undefined || t.projectId === undefined || t.projectId === at.project);
      return { complete: read.stopped === undefined, at, keys: here.map(infoOf) };
    },
  };
}
