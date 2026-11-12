// KBOX-8: the box writes the words. Every page sentence is fixed per action kind and filled only from the stored typed
// action; nothing mission control sends becomes page text except the requester's reason, which is set apart as unchecked
// plain text. The page is lines of plain text: the app shows each line as text, never as markup.
import type { Action, Destination } from './actions.ts';
import type { Requester } from './slots.ts';
import type { KeyLocation } from '../ports/types.ts';

/** The fixed sentences of the spec's "Fixed words" list that this unit's pages carry. */
export const FIXED = {
  update: 'Agents wrote this version and only agents checked it. Any change can take every key, and this page cannot tell whether it is safe.',
  egressLimits: 'These limits do not stop an approved update that is malicious.',
  noCoverage: 'This key has no watch coverage: a stray copy of it on your computer would not be noticed.',
  pasteWhere: 'Only paste where you see your phrase.',
  recoverReinstalled: 'The app was reinstalled or its data cleared: recover with the authenticator app on the same phone.',
  recoverLostPhone: "The phone is lost: recover with the authenticator app restored from your Google account on a new phone.",
  deviceKeyWarning: 'This phone keeps a device key that cannot be copied. If you reinstall the app or clear its data, you will need to recover.',
  withheld: 'response withheld: it carried a key',
  upstreamRefused: 'upstream refused the key',
} as const;

export const reasonLine = (machine: string, agent: string, text: string): string => `Reason given by ${machine}/${agent} (not checked): ${text}`;
export const enrolSentence = (label: string, address: string): string => `enrol ${label} for relay (request seen from ${address}; the label and the address are not checked)`;

const short = (h: string): string => h.slice(0, 12);

const where = (d: Destination): string => {
  const place = { vercel_env: 'the Vercel environment variable', gcp_secret: 'the Google Cloud secret', supabase_secret: 'the Supabase secret', workstation: 'your computer' }[d.kind];
  const target = d.target === '' ? '' : ` ${d.target}`;
  const envs = d.environments === undefined ? '' : ` (${d.environments.join(', ')})`;
  return `${place}${target}${envs}`;
};

/** The one-line title of each kind, used by the page, the push and `GET /api/meta` (printable ASCII). */
export function titleOf(action: Action): string {
  switch (action.kind) {
    case 'add_key':
      return `Add a key on ${action.platform}: ${action.name}`;
    case 'delete_key':
      return `Delete the key ${action.keyref}`;
    case 'rotate_key':
      return `Change the key ${action.keyref}`;
    case 'demote':
      return `Lower the class of ${action.keyref}`;
    case 'grant':
      return `Let ${action.machine} use ${action.keyref}`;
    case 'revoke_grant':
      return `Stop ${action.machine} using ${action.keyref}`;
    case 'add_destination':
      return `Add a place for ${action.keyref}`;
    case 'remove_destination':
      return `Remove a place of ${action.keyref}`;
    case 'set_allow_rules':
      return `Change what ${action.keyref} may be used for`;
    case 'set_schedule':
      return `Change the schedule of ${action.keyref}`;
    case 'vercel_set_domain':
      return `Vercel domain change on ${action.project}`;
    case 'vercel_set_team_setting':
      return `Vercel team setting ${action.setting}`;
    case 'approver_add':
      return 'Add an approver';
    case 'approver_remove':
      return 'Remove an approver';
    case 'install_update':
      return `Install key box version ${short(action.install)}`;
    case 'enrol':
      return 'Enrol a machine for relay';
  }
}

/** KBOX-57, KBOX-12: where the platform will hold the key, each field the location names (the action parser refuses an empty one). */
const locationLine = (at: KeyLocation): string =>
  `Where the platform holds it: ${[...(at.region === undefined ? [] : [`region ${at.region}`]), ...(at.project === undefined ? [] : [`project ${at.project}`])].join(', ')}.`;

function sentences(action: Action, ctx: PageContext): string[] {
  switch (action.kind) {
    case 'add_key':
      return [
        `Add the ${action.platform} key ${action.name} for ${action.projects.join(', ')}.`,
        `Scope: ${action.scope.items.length === 0 ? 'none' : action.scope.items.join(', ')}.`,
        ...(action.location === undefined ? [] : [locationLine(action.location)]),
      ];
    case 'delete_key':
      return [`Delete the key ${action.keyref} at its platform.`];
    case 'rotate_key':
      return [`Change the key ${action.keyref} for a new one.`];
    case 'demote':
      return [`Lower the class of the key ${action.keyref}, so it changes without asking you.`];
    case 'grant':
      return [`Let the machine ${action.machine} use the key ${action.keyref}.`];
    case 'revoke_grant':
      return [`Stop the machine ${action.machine} from using the key ${action.keyref}.`];
    case 'add_destination':
      return [`Put the key ${action.keyref} into ${where(action.destination)}.`];
    case 'remove_destination':
      return [`Take the key ${action.keyref} out of ${where(action.destination)}.`];
    case 'set_allow_rules':
      return [
        `Let the relay pass only these requests with the key ${action.keyref}:`,
        ...action.rules.map((r) => `${r.op}${Object.keys(r.params).length === 0 ? '' : ` (${Object.entries(r.params).map(([k, v]) => `${k} = ${v}`).join(', ')})`}`),
      ];
    case 'set_schedule':
      return [`Change the key ${action.keyref} every ${action.rotate_every_days} days, and switch the old one off ${action.grace_hours} hours later.`];
    case 'vercel_set_domain':
      return [
        action.op === 'add'
          ? `Add the domain ${action.domain} to the Vercel project ${action.project}.`
          : action.op === 'remove'
            ? `Remove the domain ${action.domain} from the Vercel project ${action.project}.`
            : `Move the domain ${action.domain} from the Vercel project ${action.project} to ${action.to_project ?? ''}.`,
      ];
    case 'vercel_set_team_setting':
      return [`Set the Vercel team setting ${action.setting} to "${action.value}".`];
    case 'approver_add':
      return ['Add another approver: a new phone with its own passkey and device key.', compareLine(ctx.fingerprint)];
    case 'approver_remove':
      return [`Remove the approver ${action.approver_id}.`];
    case 'install_update':
      return [`Install key box version ${short(action.install)} (commit ${short(action.commit)}) over version ${short(action.base)}`, ...changeLines(ctx.update), FIXED.update, FIXED.egressLimits];
    case 'enrol':
      return [enrolSentence(action.label, action.address)];
  }
}

function requesterLine(r: Requester, action: Action): string {
  switch (r.kind) {
    case 'token':
      return `Asked for by the machine token ${r.label}.`;
    case 'box':
      return action.kind === 'approver_add' ? 'Asked for by the box because a new phone registered with a code from this app.' : 'Asked for by the box itself (a schedule or a platform expiry).';
    case 'enrol':
      return 'Asked for by an enrol request that carried no token.';
    case 'approver':
      return `Asked for in the app by the approver ${r.approverId}.`;
  }
}

export interface Reason {
  readonly agent: string;
  readonly text: string;
}

/** What an update changes against the running release (KBOX-6): file counts and each pinned binary whose hash changes. */
export interface UpdateChanges {
  readonly added: number;
  readonly changed: number;
  readonly removed: number;
  readonly binaries: readonly { readonly name: string; readonly version: string; readonly sha256: string; readonly url: string }[];
}

export interface PageContext {
  readonly requester: Requester;
  readonly reason?: Reason;
  /** The coverage of the key the action is about; `null` until measured. Leave it out for an action about no stored key. */
  readonly coverage?: 'windowed' | 'anchored' | 'none' | null;
  /** approver_add: the 6-word fingerprint of the keys it names, the one the new phone shows (spec revision 4). */
  readonly fingerprint?: string;
  /** install_update: what it changes, counted against the running release. */
  readonly update?: UpdateChanges;
}

/** The approving phone compares this line with the new phone; without a fingerprint the page says not to approve. */
const COMPARE_LABEL = 'Compare with the new phone';
const compareLine = (fingerprint: string | undefined): string =>
  fingerprint === undefined ? 'The new phone\'s fingerprint could not be made here: do not approve.' : `${COMPARE_LABEL}: ${fingerprint}`;

/** The file counts and the binary changes of an update; nothing when they were not counted. */
function changeLines(update: UpdateChanges | undefined): string[] {
  if (update === undefined) return [];
  const files = `Files: ${update.added} added, ${update.changed} changed, ${update.removed} removed.`;
  if (update.binaries.length === 0) return [files, 'The Node and Caddy binaries stay as they are.'];
  return [files, ...update.binaries.map((b) => `New ${b.name} binary ${b.version} (sha256 ${short(b.sha256)}), official download ${b.url}`)];
}

/** The words to compare, as data: what to call them, the words, and the index of the line in `lines` that says them in a sentence. */
export interface Fingerprint {
  readonly label: string;
  readonly words: string;
  readonly at: number;
}

export interface Page {
  readonly title: string;
  readonly lines: readonly string[];
  /** Only an approver_add whose fingerprint could be made carries one. */
  readonly fingerprint?: Fingerprint;
}

/** The page of one approval: title, the kind's sentences, who asked, the coverage warning, and the reason set apart. */
export function renderPage(action: Action, ctx: PageContext): Page {
  const lines = [...sentences(action, ctx), requesterLine(ctx.requester, action)];
  if (ctx.coverage === 'none' || ctx.coverage === null) lines.push(FIXED.noCoverage);
  if (ctx.reason !== undefined) {
    const r = ctx.requester;
    const machine = r.kind === 'token' ? r.label : r.kind === 'approver' ? r.approverId : action.kind === 'enrol' ? action.label : 'box';
    lines.push(reasonLine(machine, ctx.reason.agent, ctx.reason.text));
  }
  const fingerprint = action.kind === 'approver_add' && ctx.fingerprint !== undefined ? { fingerprint: { label: COMPARE_LABEL, words: ctx.fingerprint, at: lines.indexOf(compareLine(ctx.fingerprint)) } } : {};
  return { title: titleOf(action), lines, ...fingerprint };
}
