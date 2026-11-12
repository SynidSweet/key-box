// KBOX-26: the Vercel operations in core. `createProject` is a route with no approval; `setDomain` and `setTeamSetting` are phone approvals whose
// executors run here, with the platform's single Vercel master, once (a crash after `approved` is `interrupted`, never run again: KBOX-60 F3).
// The adapter (src/platforms/vercel/operations.ts) makes the requests; this file chooses the master, checks the typed parameters at proposal and
// again at execution (F1), writes the names-only audit rows and maps every failure to its closed code.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { PlatformEntry, VercelMaster, VercelOperations } from '../ports/platform.ts';
import type { Action } from '../pure/actions.ts';
import { parseAction } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { PROJECT_NAME, text } from '../pure/schemas.ts';
import type { Parsed } from '../pure/schemas.ts';
import type { Approvals, Executor } from './approvals.ts';
import { parsedRoute, route } from './http.ts';
import type { Route } from './http.ts';
import { isRecord, only } from './routes-approve.ts';
import type { PlatformSource } from './rotation-ports.ts';

export interface VercelOpsDeps {
  readonly registry: readonly PlatformEntry[];
  /** The platform's master rows (KBOX-57); the one Vercel master is the only row. */
  readonly source: Pick<PlatformSource, 'masters'>;
  readonly audit: Audit;
  readonly clock: Pick<Clock, 'now'>;
}

export interface VercelOps {
  readonly executors: { readonly vercel_set_domain: Executor; readonly vercel_set_team_setting: Executor };
  /** F2: throws `ApiError` `rejected` with the reason code when the proposal must not open (a name that is no project name, a setting outside the list, no master). Other kinds pass. */
  precheck(action: Action): void;
  /** Creates a project with the master: `{project_id, name}` and nothing else; throws `ApiError` (`rejected` no master, `conflict`, `unavailable`). */
  createProject(name: string, actor: string): Promise<{ readonly project_id: string; readonly name: string }>;
}

type Found = { readonly ok: true; readonly master: VercelMaster; readonly operations: VercelOperations } | { readonly ok: false; readonly code: 'no_master' | 'master_ambiguous' };

export function createVercelOps(deps: VercelOpsDeps): VercelOps {
  const entry = deps.registry.find((e) => e.id === 'vercel');

  /** The platform's one master and the operations to run with it: none (or no Vercel entry) or two are refused, never guessed. */
  const masterOf = (): Found => {
    const [first, second] = deps.source.masters('vercel');
    if (first === undefined || entry?.operations === undefined) return { ok: false, code: 'no_master' };
    if (second !== undefined) return { ok: false, code: 'master_ambiguous' };
    return { ok: true, master: { value: first.value, items: first.items ?? [] }, operations: entry.operations };
  };

  const projectNamesOf = (action: Action): readonly string[] =>
    action.kind === 'vercel_set_domain' ? [action.project, ...(action.to_project === undefined ? [] : [action.to_project])] : [];

  /** What both a proposal and an execution check of a Vercel action say first: the typed parameters. The reason code, or undefined. */
  const refusalOf = (action: Action): string | undefined => {
    if (projectNamesOf(action).some((name) => !PROJECT_NAME.test(name))) return 'bad_name';
    if (action.kind !== 'vercel_set_team_setting') return undefined;
    const vetted = entry?.vetSetting?.(action.setting, action.value);
    return vetted === undefined || vetted === 'ok' ? undefined : vetted;
  };

  const precheck: VercelOps['precheck'] = (action) => {
    if (action.kind !== 'vercel_set_domain' && action.kind !== 'vercel_set_team_setting') return;
    const refused = refusalOf(action);
    if (refused !== undefined) throw new ApiError('rejected', refused);
    const found = masterOf();
    if (!found.ok) throw new ApiError('rejected', found.code);
  };

  const failed = (reason: string): Promise<{ readonly result: 'failed'; readonly reason: string }> => Promise.resolve({ result: 'failed', reason });

  const setDomain: Executor = async (approval) => {
    const action = approval.action;
    if (action.kind !== 'vercel_set_domain') return failed('wrong_kind');
    const refused = refusalOf(action);
    if (refused !== undefined) return failed(refused);
    const found = masterOf();
    if (!found.ok) return failed(found.code);
    const done = await found.operations.setDomain(found.master, { project: action.project, op: action.op, domain: action.domain, ...(action.to_project === undefined ? {} : { toProject: action.to_project }) });
    if (!done.ok) return failed(done.code);
    deps.audit.append({ action: 'vercel.domain_changed', subject: approval.approvalId, at: deps.clock.now(), detail: { project: action.project, op: action.op, domain: action.domain } });
    return { result: 'done' };
  };

  const setTeamSetting: Executor = async (approval) => {
    const action = approval.action;
    if (action.kind !== 'vercel_set_team_setting') return failed('wrong_kind');
    const refused = refusalOf(action);
    if (refused !== undefined) return failed(refused);
    const found = masterOf();
    if (!found.ok) return failed(found.code);
    const done = await found.operations.setTeamSetting(found.master, action.setting, action.value);
    if (!done.ok) return failed(done.code);
    // The value is a name the owner chose and the audit holds it, except a description (free text).
    deps.audit.append({
      action: 'vercel.team_setting_changed',
      subject: approval.approvalId,
      at: deps.clock.now(),
      detail: action.setting === 'description' ? { setting: action.setting } : { setting: action.setting, value: action.value },
    });
    return { result: 'done' };
  };

  const createProject: VercelOps['createProject'] = async (name, actor) => {
    const found = masterOf();
    if (!found.ok) throw found.code === 'no_master' ? new ApiError('rejected', 'no_master') : new ApiError('unavailable', found.code);
    const created = await found.operations.createProject(found.master, name);
    if (!created.ok) throw new ApiError(created.code);
    deps.audit.append({ action: 'vercel.project_created', subject: created.name, at: deps.clock.now(), actor, detail: { name: created.name } });
    return { project_id: created.projectId, name: created.name };
  };

  return { executors: { vercel_set_domain: setDomain, vercel_set_team_setting: setTeamSetting }, precheck, createProject };
}

export interface VercelRouteDeps {
  readonly ops: Pick<VercelOps, 'createProject'>;
  readonly approvals: Pick<Approvals, 'propose'>;
  /** The proposal check every proposal route runs before an approval opens (the core's whole chain). */
  readonly precheck: (action: Action) => Promise<void>;
}

/** The action of KBOX-53 from a body of its members without `kind`: a closed record, or nothing. */
const actionFrom =
  (kind: 'vercel_set_domain' | 'vercel_set_team_setting', required: readonly string[], optional: readonly string[]) =>
  (raw: unknown): Parsed<Action> => {
    if (!isRecord(raw) || !only(raw, required, optional)) return { ok: false };
    return parseAction({ ...raw, kind });
  };

/** KBOX-26: `POST /api/vercel/{projects,domains,settings}`, scope `control`. */
export function vercelRoutes(deps: VercelRouteDeps): Route[] {
  const propose = (kind: 'vercel_set_domain' | 'vercel_set_team_setting', required: readonly string[], optional: readonly string[], path: string): Route =>
    parsedRoute({
      method: 'POST',
      path,
      surface: 'api',
      scope: 'control',
      parse: actionFrom(kind, required, optional),
      handle: async ({ body, actor }) => {
        await deps.precheck(body);
        return { status: 201, json: deps.approvals.propose({ action: body, requester: { kind: 'token', label: actor } }) };
      },
    });
  return [
    route({
      method: 'POST',
      path: '/api/vercel/projects',
      surface: 'api',
      scope: 'control',
      body: { name: text(PROJECT_NAME) },
      handle: async ({ body, actor }) => ({ status: 201, json: await deps.ops.createProject(body.name, actor) }),
    }),
    propose('vercel_set_domain', ['project', 'op', 'domain'], ['to_project'], '/api/vercel/domains'),
    propose('vercel_set_team_setting', ['setting', 'value'], [], '/api/vercel/settings'),
  ];
}
