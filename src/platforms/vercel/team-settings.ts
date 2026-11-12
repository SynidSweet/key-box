// KBOX-26: the closed list of team settings the box may change, each with its value parser. The list is code: adding a setting is an update.
// A setting that could loosen a protection the box relies on (sensitive env, KBOX-36) or the owner set stays off the list.
// What Vercel takes for each value is UNVERIFIED (`vercel.team-settings`): the feedback switches are sent as `on`/`off`, the rest as the box names them.
import { DOMAIN_NAME } from '../../pure/actions.ts';
import type { SettingRefusal } from '../../ports/platform.ts';

type Body = Readonly<Record<string, unknown>>;
/** The request body for a value (exactly one setting as its only member), or undefined when the value does not parse. */
type Parser = (value: string) => Body | undefined;

const flag = (value: string): boolean | undefined => (value === 'true' ? true : value === 'false' ? false : undefined);
const DESCRIPTION = /^[\x20-\x7e]{1,140}$/;

/** A true/false value sent as Vercel's `on`/`off` string. */
const onOff =
  (member: string): Parser =>
  (value) => {
    const on = flag(value);
    return on === undefined ? undefined : { [member]: on ? 'on' : 'off' };
  };
const boolean =
  (member: string): Parser =>
  (value) => {
    const on = flag(value);
    return on === undefined ? undefined : { [member]: on };
  };

const SETTINGS: ReadonlyMap<string, Parser> = new Map<string, Parser>([
  ['enablePreviewFeedback', onOff('enablePreviewFeedback')],
  ['enableProductionFeedback', onOff('enableProductionFeedback')],
  ['hideIpAddresses', boolean('hideIpAddresses')],
  ['hideIpAddressesInLogDrains', boolean('hideIpAddressesInLogDrains')],
  [
    'remoteCaching.enabled',
    (value) => {
      const on = flag(value);
      return on === undefined ? undefined : { remoteCaching: { enabled: on } };
    },
  ],
  ['previewDeploymentSuffix', (value) => (DOMAIN_NAME.test(value) ? { previewDeploymentSuffix: value } : undefined)],
  ['description', (value) => (DESCRIPTION.test(value) ? { description: value } : undefined)],
]);

/** The one-member request body of a setting and value, or why it may not be sent. */
export function teamSettingBody(setting: string, value: string): { readonly ok: true; readonly body: Body } | { readonly ok: false; readonly code: SettingRefusal } {
  const parse = SETTINGS.get(setting);
  if (parse === undefined) return { ok: false, code: 'setting_not_listed' };
  const body = parse(value);
  return body === undefined ? { ok: false, code: 'bad_value' } : { ok: true, body };
}

/** The proposal's question: whether a setting is on the list and its value parses. */
export const vetTeamSetting = (setting: string, value: string): 'ok' | SettingRefusal => {
  const found = teamSettingBody(setting, value);
  return found.ok ? 'ok' : found.code;
};
