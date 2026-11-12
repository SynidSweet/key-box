// KBOX-36, KBOX-57: what a Vercel token request means, parsed once where it enters. The project is the key's location (`at.project`), never a
// scope field or item: a token naming one is a project token, one without is team-wide. The scope's items carry at most one `team:<id>`, the
// team the token is made in; any other item is refused. A project or team that is present and not a plain id is refused: it must never fall
// through to a team-wide token.
import type { KeyLocation, Scope } from '../../ports/types.ts';
import { VercelError } from './errors.ts';

/** A Vercel id: 1 to 128 of letters, digits, `_`, `-` and `.`, neither starting nor ending with a dot. The entry's location pattern too. */
export const PLAIN_ID = /^[A-Za-z0-9_-](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9_-])?$/;
const TEAM_ITEM = 'team:';

export interface TokenRequest {
  readonly projectId?: string;
  readonly teamId?: string;
}

const isPlainId = (value: string | undefined): value is string => value !== undefined && PLAIN_ID.test(value);

function itemsOf(scope: Scope): readonly string[] {
  const items = scope['items'];
  if (items === undefined) return [];
  if (!Array.isArray(items)) throw new VercelError('bad_scope');
  return items;
}

/** The team of the scope's one `team:` item, if any; any other item, two teams, or a team that is not a plain id is `bad_scope`. */
function teamOf(scope: Scope): string | undefined {
  const items = itemsOf(scope);
  if (!items.every((i) => i.startsWith(TEAM_ITEM)) || items.length > 1) throw new VercelError('bad_scope');
  const [item] = items;
  if (item === undefined) return undefined;
  const team = item.slice(TEAM_ITEM.length);
  if (!isPlainId(team)) throw new VercelError('bad_scope');
  return team;
}

export function parseTokenRequest(scope: Scope, at: KeyLocation): TokenRequest {
  const teamId = teamOf(scope);
  if (at.project !== undefined && !isPlainId(at.project)) throw new VercelError('bad_scope');
  return { ...(at.project === undefined ? {} : { projectId: at.project }), ...(teamId === undefined ? {} : { teamId }) };
}

/** KBOX-36 classify, the adapter's own view: a token whose location names a project is ordinary, any other is master. The shell's KBOX-15 floor (`classify(scope, {})`) makes every Vercel token master until a later rule lets a confirmed project lower it. */
export const classifyScope = (_scope: Scope, at: KeyLocation): 'ordinary' | 'master' => (isPlainId(at.project) ? 'ordinary' : 'master');
