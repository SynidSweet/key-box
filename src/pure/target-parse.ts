// KBOX-13 steps 3 and 4: the relay reads a request target once and refuses anything another parser could read differently.
// Rules match the decoded segments and query pairs; what goes upstream is their canonical re-encoding, so the path matched is
// the path sent. A refusal is a fixed code and never quotes the target.

import { NAME } from './schemas.ts';

export type TargetFailure = 'not_found' | 'bad_path' | 'bad_query';

export type QueryPair = readonly [name: string, value: string];

export interface RelayTarget {
  readonly keyref: string;
  /** The decoded path segments after the keyref. */
  readonly segments: readonly string[];
  /** The raw text of each segment, as the caller wrote it (the host check of a host-in-path profile needs it). */
  readonly rawSegments: readonly string[];
  readonly query: readonly QueryPair[];
}

export type TargetParse = { readonly ok: true; readonly value: RelayTarget } | { readonly ok: false; readonly code: TargetFailure };

/** KBOX-13: the address of a key is its keyref in one path segment with each `/` written `~`. */
export const relayAddressOf = (keyref: string): string => keyref.replaceAll('/', '~');

const HEX = /^[0-9A-Fa-f]{2}$/;
/** Printable ASCII without space. Anything else raw (control, space, DEL, non-ASCII) is refused. */
const isRawPrintable = (code: number): boolean => code > 0x20 && code < 0x7f;
const isControl = (code: number): boolean => code < 0x20 || code === 0x7f;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/** Decodes `%XX` escapes once. Undefined for a malformed escape or a decoded byte that is not ASCII. */
function decodeOnce(raw: string): string | undefined {
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw.charAt(i);
    if (ch !== '%') {
      out += ch;
      continue;
    }
    const hex = raw.slice(i + 1, i + 3);
    if (!HEX.test(hex)) return undefined;
    const code = parseInt(hex, 16);
    if (code >= 0x80) return undefined;
    out += String.fromCharCode(code);
    i += 2;
  }
  return out;
}

const rawRefused = (raw: string, forbidden: string): boolean => [...raw].some((ch) => !isRawPrintable(ch.charCodeAt(0)) || forbidden.includes(ch));

/** Encoded `/`, `\`, `.` in either case: never accepted in a path. */
const ENCODED_SEPARATOR = /%(2f|5c|2e)/i;
/** Decoded bytes a path segment may not hold: a control byte, `%` (a second decoding upstream), `;` (path parameters). */
const segmentRefused = (decoded: string): boolean => [...decoded].some((ch) => isControl(ch.charCodeAt(0)) || ch === '%' || ch === ';' || ch === '/' || ch === '\\');

function parsePath(rawPath: string): { readonly segments: string[]; readonly raw: string[] } | undefined {
  if (rawRefused(rawPath, '\\;#') || ENCODED_SEPARATOR.test(rawPath)) return undefined;
  if (rawPath === '') return { segments: [], raw: [] };
  const raw = rawPath.slice(1).split('/');
  const segments: string[] = [];
  for (const piece of raw) {
    if (piece === '' || piece === '.' || piece === '..') return undefined;
    const decoded = decodeOnce(piece);
    if (decoded === undefined || segmentRefused(decoded)) return undefined;
    segments.push(decoded);
  }
  return { segments, raw };
}

/** Decoded query text may not hold a control byte or the query's own delimiters. */
const queryTextRefused = (decoded: string): boolean => [...decoded].some((ch) => isControl(ch.charCodeAt(0)) || ch === '%' || ch === '&' || ch === '=');

function parseQueryText(rawQuery: string): QueryPair[] | undefined {
  if (rawRefused(rawQuery, ';#')) return undefined;
  if (rawQuery === '') return [];
  const pairs: QueryPair[] = [];
  const seen = new Set<string>();
  for (const item of rawQuery.split('&')) {
    const eq = item.indexOf('=');
    if (eq <= 0) return undefined;
    const name = decodeOnce(item.slice(0, eq));
    const value = decodeOnce(item.slice(eq + 1));
    if (name === undefined || value === undefined || name === '' || queryTextRefused(name) || queryTextRefused(value) || seen.has(name)) return undefined;
    seen.add(name);
    pairs.push([name, value]);
  }
  return pairs;
}

const PREFIX = '/r/';

/** The one parse of a relay target `/r/<address>/<path>?<query>`; the address is the keyref with each `/` written `~`. */
export function parseRelayTarget(target: string): TargetParse {
  if (!target.startsWith(PREFIX)) return { ok: false, code: 'not_found' };
  const hash = target.indexOf('#');
  const mark = target.indexOf('?');
  const pathEnd = mark < 0 ? target.length : mark;
  if (hash >= 0 && hash < pathEnd) return { ok: false, code: 'bad_path' };
  const rest = target.slice(PREFIX.length, pathEnd);
  const slash = rest.indexOf('/');
  const address = slash < 0 ? rest : rest.slice(0, slash);
  // The address is read raw, never decoded: a `%` is not in NAME, so an escaped `~` or `/` never routes.
  const keyref = address.replaceAll('~', '/');
  if (!NAME.test(keyref)) return { ok: false, code: 'not_found' };
  const path = parsePath(slash < 0 ? '' : rest.slice(slash));
  if (path === undefined) return { ok: false, code: 'bad_path' };
  const query = parseQueryText(mark < 0 ? '' : target.slice(mark + 1));
  if (query === undefined) return { ok: false, code: 'bad_query' };
  return { ok: true, value: { keyref, segments: path.segments, rawSegments: path.raw, query } };
}

/** RFC 3986 unreserved characters and the `extraLiteral` ones literal, every other byte `%XX` upper case. */
function encodeCanonical(text: string, extraLiteral: string): string {
  let out = '';
  for (const ch of text) {
    out += UNRESERVED.test(ch) || extraLiteral.includes(ch) ? ch : [...Buffer.from(ch, 'utf8')].map((b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join('');
  }
  return out;
}

/** Path characters kept literal (KBOX-13 step 3): Google routes a custom method (`documents:runQuery`) only on a literal colon. */
const PATH_LITERAL = ':@';

export const canonicalPath = (segments: readonly string[]): string => `/${segments.map((s) => encodeCanonical(s, PATH_LITERAL)).join('/')}`;

export const canonicalQuery = (pairs: readonly QueryPair[]): string => pairs.map(([name, value]) => `${encodeCanonical(name, '')}=${encodeCanonical(value, '')}`).join('&');
