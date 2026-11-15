// release-v2 (KBOX-48): the setup file (`user-data`) a release publishes is deploy/cloud-init.yaml with the five release value lines
// of /root/keybox-release.env filled in and every other line byte-identical. Values are parsed here, at the edge.
import { DOMAIN_NAME } from './actions.ts';
import { RELEASE_HASH } from './release-hash.ts';

export const RELEASE_KEYS = ['KB_REPO', 'KB_DOMAIN', 'KB_COMMIT', 'KB_RELEASE', 'KB_TIME_FLOOR'] as const;
export type ReleaseKey = (typeof RELEASE_KEYS)[number];
export type ReleaseValues = Readonly<Record<ReleaseKey, string>>;

export type UserDataError = 'missing_value' | 'unknown_key' | 'bad_repo' | 'bad_domain' | 'bad_commit' | 'bad_release' | 'bad_time_floor' | 'template_lines';

export type Rendered = { readonly ok: true; readonly text: string } | { readonly ok: false; readonly error: UserDataError };
export type ReadValues = { readonly ok: true; readonly values: ReleaseValues } | { readonly ok: false; readonly error: UserDataError };

const ENV_FILE_HEADER = '  - path: /root/keybox-release.env';
const CONTENT_HEADER = '    content: |';
const VALUE_INDENT = '      ';

const CHECKS: Readonly<Record<ReleaseKey, { readonly accepts: (v: string) => boolean; readonly error: UserDataError }>> = {
  KB_REPO: { accepts: (v) => /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(v), error: 'bad_repo' },
  KB_DOMAIN: { accepts: (v) => DOMAIN_NAME.test(v), error: 'bad_domain' },
  KB_COMMIT: { accepts: (v) => /^[0-9a-f]{40}$/.test(v), error: 'bad_commit' },
  KB_RELEASE: { accepts: (v) => RELEASE_HASH.test(v), error: 'bad_release' },
  KB_TIME_FLOOR: { accepts: (v) => /^(0|[1-9][0-9]*)$/.test(v) && Number.isSafeInteger(Number(v)), error: 'bad_time_floor' },
};

const isKey = (k: string): k is ReleaseKey => (RELEASE_KEYS as readonly string[]).includes(k);

/** The line index of each key's value line in the env file's content block, or undefined unless there is exactly one per key. */
function valueLines(lines: readonly string[]): Readonly<Record<ReleaseKey, number>> | undefined {
  const header = lines.indexOf(ENV_FILE_HEADER);
  if (header < 0 || lines.indexOf(ENV_FILE_HEADER, header + 1) >= 0) return undefined;
  let i = header + 1;
  while (i < lines.length && lines[i] !== CONTENT_HEADER) i += 1;
  const found: Partial<Record<ReleaseKey, number[]>> = {};
  for (i += 1; i < lines.length && (lines[i] ?? '').startsWith(VALUE_INDENT); i += 1) {
    const name = (lines[i] ?? '').slice(VALUE_INDENT.length).split('=', 1)[0] ?? '';
    if (isKey(name)) (found[name] ??= []).push(i);
  }
  const at = {} as Record<ReleaseKey, number>;
  for (const key of RELEASE_KEYS) {
    const hits = found[key];
    if (hits?.length !== 1 || hits[0] === undefined) return undefined;
    at[key] = hits[0];
  }
  return at;
}

function parseValues(given: Readonly<Record<string, string>>): ReleaseValues | UserDataError {
  if (Object.keys(given).some((k) => !isKey(k))) return 'unknown_key';
  const out = {} as Record<ReleaseKey, string>;
  for (const key of RELEASE_KEYS) {
    const value = Object.hasOwn(given, key) ? given[key] : undefined;
    if (value === undefined) return 'missing_value';
    out[key] = value;
  }
  for (const key of RELEASE_KEYS) if (!CHECKS[key].accepts(out[key])) return CHECKS[key].error;
  return out;
}

/** `template` with the five value lines set from `values`; every other line is unchanged. */
export function renderUserData(template: string, values: Readonly<Record<string, string>>): Rendered {
  const parsed = parseValues(values);
  if (typeof parsed === 'string') return { ok: false, error: parsed };
  const lines = template.split('\n');
  const at = valueLines(lines);
  if (at === undefined) return { ok: false, error: 'template_lines' };
  for (const key of RELEASE_KEYS) lines[at[key]] = `${VALUE_INDENT}${key}=${parsed[key]}`;
  return { ok: true, text: lines.join('\n') };
}

/** The five values a setup file (or the template) holds, as written (not checked: the template holds placeholders). */
export function readReleaseValues(text: string): ReadValues {
  const lines = text.split('\n');
  const at = valueLines(lines);
  if (at === undefined) return { ok: false, error: 'template_lines' };
  const values = {} as Record<ReleaseKey, string>;
  for (const key of RELEASE_KEYS) values[key] = (lines[at[key]] ?? '').slice(VALUE_INDENT.length + key.length + 1);
  return { ok: true, values };
}
