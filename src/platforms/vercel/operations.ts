// KBOX-26: the three named Vercel operations, run with the master and typed parameters: createProject, setDomain, setTeamSetting. Each is one
// request; every path piece goes through `segment()`; the master goes into the one call and is never kept. An answer is read for its status
// and, for a created project, its id: nothing else of Vercel's body is kept or passed on. Failures are the four fixed names.
import type { SettingRefusal, VercelFailureName, VercelMaster, VercelOperations, VercelOutcome } from '../../ports/platform.ts';
import { NOT_JSON, encodeJson, recordOf, segment, textOf } from './api.ts';
import type { ApiAnswer, ApiCall, VercelApi } from './api.ts';
import { VercelError, isSuccess } from './errors.ts';
import { teamOf } from './scope.ts';
import { teamSettingBody } from './team-settings.ts';

/** The failure name of a status: 404 not found, 409 a conflict, 401 and 403 forbidden, 429 and 5xx no usable answer; any other 4xx is the request not fitting Vercel's state. */
function failureOfStatus(status: number): VercelFailureName {
  if (status === 404) return 'vercel_not_found';
  if (status === 401 || status === 403) return 'vercel_forbidden';
  if (status === 429 || status >= 500 || status < 400) return 'unreachable';
  return 'vercel_conflict';
}

/** The name a thrown adapter failure stands for; a failure that is not the adapter's own is a bug and travels on. */
function failureOfError(error: unknown): VercelFailureName {
  if (!(error instanceof VercelError)) throw error;
  if (error.code === 'bad_scope') return 'vercel_not_found';
  if (error.code === 'bad_key' || error.code === 'rejected') return 'vercel_forbidden';
  return 'unreachable';
}

/** A project name that is a plain path piece (`segment` throws otherwise), as it is. */
const plainName = (name: string): string => {
  segment(name);
  return name;
};

type Sent = { readonly ok: true; readonly answer: ApiAnswer } | { readonly ok: false; readonly code: VercelFailureName };

export function createVercelOperations(api: VercelApi): VercelOperations {
  /**
   * Builds the request from the master's team (the one `team:` item; none for a personal account; a scope that names more throws `bad_scope`) and
   * hands `build` the `?teamId=` to add (the team patch names its team in the path instead). A path piece that is no plain name throws in `build`, before anything is sent.
   */
  const send = async (master: VercelMaster, build: (team: string | undefined, scoped: { readonly query?: string }) => ApiCall): Promise<Sent> => {
    try {
      const team = teamOf({ items: [...master.items] });
      const call = build(team, team === undefined ? {} : { query: `teamId=${encodeURIComponent(team)}` });
      return { ok: true, answer: await api.call(call, master.value) };
    } catch (error) {
      return { ok: false, code: failureOfError(error) };
    }
  };

  const outcome = (sent: Sent): VercelOutcome => {
    if (!sent.ok) return sent;
    const { status, json } = sent.answer;
    if (!isSuccess(status)) return { ok: false, code: failureOfStatus(status) };
    return json === NOT_JSON ? { ok: false, code: 'unreachable' } : { ok: true };
  };

  return {
    async createProject(master, name) {
      const sent = await send(master, (_team, scoped) => ({ method: 'POST', path: '/v11/projects', body: encodeJson({ name }), ...scoped }));
      if (!sent.ok) return { ok: false, code: 'unavailable' };
      const { status, json } = sent.answer;
      if (status === 409) return { ok: false, code: 'conflict' };
      const projectId = isSuccess(status) ? textOf(recordOf(json)?.['id']) : undefined;
      return projectId === undefined ? { ok: false, code: 'unavailable' } : { ok: true, projectId, name };
    },

    async setDomain(master, change) {
      const sent = await send(master, (_team, scoped) => {
        const project = segment(change.project);
        switch (change.op) {
          case 'add':
            return { method: 'POST', path: `/v10/projects/${project}/domains`, body: encodeJson({ name: change.domain }), ...scoped };
          case 'remove':
            return { method: 'DELETE', path: `/v9/projects/${project}/domains/${segment(change.domain)}`, ...scoped };
          case 'move':
            if (change.toProject === undefined) throw new VercelError('bad_scope');
            return { method: 'POST', path: `/v1/projects/${project}/domains/${segment(change.domain)}/move`, body: encodeJson({ projectId: plainName(change.toProject) }), ...scoped };
        }
      });
      return outcome(sent);
    },

    async setTeamSetting(master, setting, value): Promise<VercelOutcome | { readonly ok: false; readonly code: SettingRefusal }> {
      const body = teamSettingBody(setting, value);
      if (!body.ok) return body;
      const sent = await send(master, (team) => {
        if (team === undefined) throw new VercelError('bad_scope');
        return { method: 'PATCH', path: `/v2/teams/${segment(team)}`, body: encodeJson(body.body) };
      });
      return outcome(sent);
    },
  };
}
