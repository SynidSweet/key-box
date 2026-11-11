// Readers for the text of systemd files: a tmpfiles.d file and the `Key=Value` lines of a unit.

export interface TmpfilesLine {
  readonly type: string;
  readonly path: string;
  readonly mode: string;
  readonly user: string;
  readonly group: string;
}

export function parseTmpfiles(text: string): TmpfilesLine[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'))
    .map((l) => {
      const [type = '', path = '', mode = '', user = '', group = ''] = l.split(/\s+/);
      return { type, path, mode, user, group };
    });
}

/** `Key=Value` lines of one section; a repeated key keeps every value. */
export function directives(unit: string, section: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  let current = '';
  for (const raw of unit.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const header = /^\[(\w+)\]$/.exec(line);
    if (header !== null) {
      current = header[1] ?? '';
      continue;
    }
    const eq = line.indexOf('=');
    if (current === section && eq > 0) found.set(line.slice(0, eq), [...(found.get(line.slice(0, eq)) ?? []), line.slice(eq + 1)]);
  }
  return found;
}

export const words = (values: readonly string[] | undefined): string[] => (values ?? []).flatMap((v) => v.split(/\s+/)).filter((w) => w !== '');

/** The directives a unit must have and does not, as `Key=Value` text. */
export function missingDirectives(unit: string, expected: Readonly<Record<string, string>>): string[] {
  const service = directives(unit, 'Service');
  return Object.entries(expected).filter(([key, value]) => !(service.get(key) ?? []).includes(value)).map(([key, value]) => `${key}=${value}`);
}
