// KBOX-36: the scope of a Vercel token request, parsed once where it enters. `projectId` makes a project token (ordinary); a request without
// one makes a team-scoped master. A `projectId` that is present and not a plain id is refused: it must never fall through to a master token.
import type { Scope } from '../../ports/types.ts';
import { VercelError } from './errors.ts';

const PLAIN_ID = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/;

export interface TokenScope {
  readonly projectId?: string;
  readonly teamId?: string;
}

function plainId(value: string | readonly string[] | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !PLAIN_ID.test(value) || value.endsWith('.')) throw new VercelError('bad_scope');
  return value;
}

export function parseTokenScope(scope: Scope): TokenScope {
  const projectId = plainId(scope['projectId']);
  const teamId = plainId(scope['teamId']);
  return { ...(projectId === undefined ? {} : { projectId }), ...(teamId === undefined ? {} : { teamId }) };
}

/** KBOX-36 classify: a token made with a project id is ordinary, any other is master. */
export const classifyScope = (scope: Scope): 'ordinary' | 'master' => (typeof scope['projectId'] === 'string' ? 'ordinary' : 'master');
