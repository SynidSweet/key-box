// KBOX-9, KBOX-50: canonical JSON is RFC 8785 (JCS) restricted to integers: members sorted by UTF-16 code units, UTF-8,
// no floats, no null (an absent member is left out), no whitespace.

/** Thrown for a value that has no canonical form. The text is fixed: the value is never quoted. */
export class NotCanonical extends Error {
  constructor() {
    super('value cannot be written as canonical JSON');
    this.name = 'NotCanonical';
  }
}

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function quote(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new NotCanonical();
  return JSON.stringify(s);
}

function isPlain(v: object): boolean {
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

export function canonicalJson(value: unknown): string {
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new NotCanonical();
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  if (typeof value === 'object' && value !== null && isPlain(value)) {
    const members = Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${quote(k)}:${canonicalJson(v)}`);
    return `{${members.join(',')}}`;
  }
  throw new NotCanonical();
}
