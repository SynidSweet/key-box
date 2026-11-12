// KBOX-36, KBOX-13, KBOX-23: Vercel is `relayDenyOnly` in v1: no relay profile, and this pinned list of routes a relayed call must never
// reach. Each rule carries a concrete sample (the route's real method and a made-up id, from docs/probes/vercel.md) and, for each, the
// KBOX-13 canonicalisation variants. A sample that needs a query to pass the platform's validation keeps it on every variant.
import type { DenyRule, SampleRequest } from '../../ports/relay-profile.ts';
import { VERCEL_HOST } from './api.ts';

interface Route {
  readonly method: string;
  readonly path: string;
  readonly query?: string;
}

const withQuery = (path: string, query: string | undefined, extra?: string): string => {
  const all = [query, extra].filter((q): q is string => q !== undefined && q !== '').join('&');
  return all === '' ? path : `${path}?${all}`;
};

/** The route as the caller would send it, then the variants of the KBOX-13 table. */
function variantsOf(route: Route): SampleRequest[] {
  const { method, path, query } = route;
  const parts = path.split('/');
  const second = parts[2] ?? '';
  const escaped = [...parts.slice(0, 2), `%${second.charCodeAt(0).toString(16).toUpperCase()}${second.slice(1)}`, ...parts.slice(3)].join('/');
  const at = (p: string, extra?: string): string => `https://${VERCEL_HOST}${withQuery(p, query, extra)}`;
  return [
    { method, url: at(path) },
    { method, url: at(escaped) },
    { method, url: at(`${path}/`) },
    { method, url: at(path.replace('/', '//')) },
    { method, url: at(path.replace(/\/([^/]+)$/, '/x/../$1')) },
    { method, url: at(path.replace(/\/([^/]+)$/, '/%2e%2e/$1')) },
    { method, url: at(path.replace(/\/([^/]+)$/, '%2F$1')) },
    { method, url: at(`${path};x`) },
    { method, url: at(path, `_method=${method}`) },
    { method: 'GET', url: at(path, `%24method=${method}`) },
  ];
}

const rule = (id: string, ...routes: Route[]): DenyRule => ({ id, samples: routes.flatMap(variantsOf) });

// Every route below is VERIFIED in the probe report; the invite and protection-bypass routes are the corrected ones (probe 2026-11-12).
export const VERCEL_MUST_DENY: readonly DenyRule[] = [
  rule('user-tokens', { method: 'GET', path: '/v6/user/tokens' }, { method: 'POST', path: '/v3/user/tokens' }, { method: 'DELETE', path: '/v3/user/tokens/t' }),
  rule('project-env', { method: 'GET', path: '/v10/projects/p/env' }),
  rule('shared-env', { method: 'GET', path: '/v1/env/x' }),
  rule('integrations', { method: 'GET', path: '/v1/integrations/configurations', query: 'view=account' }),
  rule('team-members', { method: 'GET', path: '/v1/teams/t/members' }),
  rule('team-invites', { method: 'GET', path: '/v1/teams/t/invites' }),
  rule('team-invite-create', { method: 'POST', path: '/v2/teams/t/members' }),
  rule('deployments-create', { method: 'POST', path: '/v13/deployments' }),
  rule('protection-bypass', { method: 'PATCH', path: '/v1/projects/p/protection-bypass' }),
  rule('drains', { method: 'GET', path: '/v1/drains' }),
  rule('log-drains', { method: 'GET', path: '/v1/log-drains' }),
  rule('webhooks', { method: 'GET', path: '/v1/webhooks' }),
];
