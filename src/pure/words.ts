// KBOX-8: the box writes the words. Every page sentence is fixed per action kind and filled only from the stored typed
// action; nothing mission control sends becomes page text except the requester's reason, which is set apart as unchecked
// plain text. The page is lines of plain text: the app shows each line as text, never as markup.
import type { Action, Destination } from './actions.ts';
import { platformOfKeyref } from './class.ts';
import type { Requester } from './slots.ts';
import type { KeyClass, KeyLocation } from '../ports/types.ts';

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
  /** KBOX-60: a set_schedule with no grace, on a key an app's runtime holds. */
  noGraceApps: 'Apps still holding the old key fail until they redeploy.',
  /** KBOX-60: a demote that ends in ordinary: relay use ends (the grants go), the workstation leak check stops watching its value (the share file drops it), the allow rules stay. */
  demoteToOrdinary: 'Machines granted it lose relay use, and the leak check on your workstations stops looking for its value. Its allow rules are kept.',
  /** KBOX-60: a demote of a master whose scope still makes it an admin key. */
  demoteStaysAdmin: 'It stays an admin key.',
} as const;

/** KBOX-51 step 10 with neither a platform key id nor a retirer: the notice that asks the owner to end the old key (reason `owner_ends`). */
export const ownerEndsLine = (platform: string): string => `End the old key on ${platform}; the box watches for it to stop working.`;

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
      return [`Delete the key ${action.keyref} at its platform.`, ...deletionLines(ctx.deletion)];
    case 'rotate_key':
      return [`Change the key ${action.keyref} for a new one.`];
    case 'demote':
      return [`Lower the class of the key ${action.keyref}, so it changes without asking you.`, ...(ctx.fallsTo === 'ordinary' ? [FIXED.demoteToOrdinary] : ctx.fallsTo === 'admin' ? [FIXED.demoteStaysAdmin] : [])];
    case 'grant':
      return [`Let the machine ${action.machine} use the key ${action.keyref}.`];
    case 'revoke_grant':
      return [`Stop the machine ${action.machine} from using the key ${action.keyref}.`];
    case 'add_destination':
      return [`Put the key ${action.keyref} into ${where(action.destination)}.`];
    case 'remove_destination':
      return [`Take the key ${action.keyref} out of ${where(action.destination)}.`];
    case 'set_allow_rules':
      // KBOX-61: the empty list is the whole profile; it must not read as "only these" with nothing under it.
      if (action.rules.length === 0) return [`Let the relay pass every request the ${platformOfKeyref(action.keyref)} profile allows with the key ${action.keyref}.`];
      return [
        `Let the relay pass only these requests with the key ${action.keyref}:`,
        ...action.rules.map((r) => `${r.op}${Object.keys(r.params).length === 0 ? '' : ` (${Object.entries(r.params).map(([k, v]) => `${k} = ${v}`).join(', ')})`}`),
      ];
    case 'set_schedule':
      return [
        `Change the key ${action.keyref} every ${action.rotate_every_days} days, and switch the old one off ${action.grace_hours} hours later.`,
        ...(action.grace_hours === 0 && ctx.runtimeDestination === true ? [FIXED.noGraceApps] : []),
      ];
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
  /** demote (KBOX-60): the class the key falls to; absent when the box could not tell. */
  readonly fallsTo?: KeyClass;
  /** set_schedule (KBOX-60): the key has a destination the apps' runtime reads. */
  readonly runtimeDestination?: true;
  /** delete_key (KBOX-62): what the deletion does; absent when the box could not tell (no such key). */
  readonly deletion?: DeletionFacts;
}

/** KBOX-62: what a deletion of a stored key will do, as its page says it. */
export interface DeletionFacts {
  readonly platform: string;
  /** Who ends its live generations: every one the box (`box`), any the owner (`owner`), or none is live (`none`). */
  readonly ends: 'box' | 'owner' | 'none';
  /** Where apps read it from (its destinations' targets, names only). */
  readonly targets: readonly string[];
  /** Machines hold grants of it. */
  readonly grants: boolean;
  /** A key change of it is open (in grace, or ending its old key). */
  readonly midChange: boolean;
}

function deletionLines(facts: DeletionFacts | undefined): string[] {
  if (facts === undefined) return [];
  const ends = {
    box: `The box ends it on ${facts.platform}, waits until it stops working, then erases its copy.`,
    owner: `The box cannot end it on ${facts.platform} itself. You end it there; the box erases its copy once it stops working.`,
    none: 'It no longer works anywhere; the box only erases its copy.',
  }[facts.ends];
  return [
    ends,
    ...(facts.targets.length === 0 ? [] : [`Apps that read it from ${facts.targets.join(', ')} stop working.`]),
    ...(facts.grants ? ['Machines granted it lose relay use at once.'] : []),
    ...(facts.midChange ? ['It is in the middle of a key change; the new key and the old one are both ended.'] : []),
  ];
}

/**
 * KBOX-62, KBOX-22: the deletion's pushes, names only: `end` asks the owner to end a key only they can end; `unconfirmed` says the box could
 * not prove it ended yet. Never a value or a prefix.
 */
export function deletePush(which: 'end' | 'unconfirmed', name: string, platform: string): { readonly kind: 'delete_waiting'; readonly title: string } {
  const title =
    which === 'end'
      ? `End the key ${name} on ${platform}; the box erases its copy once it stops working.`
      : `The box could not end the key ${name} on ${platform} yet. End it there if you can; the box keeps checking.`;
  return { kind: 'delete_waiting', title };
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
