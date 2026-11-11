// KBOX-43: the client address as the box reads it from `X-KB-Client-Ip`, and the network it belongs to for "new network"
// checks: the /24 of an IPv4 address, the /48 of an IPv6 address.

export interface ClientAddress {
  /** The address as the header gave it. */
  readonly address: string;
  /** `203.0.113.0/24` or `2001:db8:1::/48`. */
  readonly network: string;
}

const MAX_LENGTH = 45;

export function parseIpv4(text: string): number[] | undefined {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (match === null) return undefined;
  const octets = match.slice(1, 5).map((o) => (o.length > 1 && o.startsWith('0') ? Number.NaN : Number(o)));
  return octets.every((o) => o >= 0 && o <= 255) ? octets : undefined;
}

function groupsOf(part: string, lastMayBeIpv4: boolean): number[] | undefined {
  if (part === '') return [];
  const tokens = part.split(':');
  const groups: number[] = [];
  for (const [i, token] of tokens.entries()) {
    if (/^[0-9A-Fa-f]{1,4}$/.test(token)) {
      groups.push(parseInt(token, 16));
    } else if (lastMayBeIpv4 && i === tokens.length - 1 && token.includes('.')) {
      const v4 = parseIpv4(token);
      if (v4 === undefined) return undefined;
      groups.push((v4[0] ?? 0) * 256 + (v4[1] ?? 0), (v4[2] ?? 0) * 256 + (v4[3] ?? 0));
    } else {
      return undefined;
    }
  }
  return groups;
}

/** The eight 16-bit groups of an IPv6 address, or undefined. */
export function parseIpv6(text: string): number[] | undefined {
  if (!/^[0-9A-Fa-f:.]+$/.test(text)) return undefined;
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  if (halves.length === 1) {
    const all = groupsOf(text, true);
    return all?.length === 8 ? all : undefined;
  }
  const head = groupsOf(halves[0] ?? '', false);
  const tail = groupsOf(halves[1] ?? '', true);
  if (head === undefined || tail === undefined) return undefined;
  const missing = 8 - head.length - tail.length;
  return missing >= 1 ? [...head, ...new Array<number>(missing).fill(0), ...tail] : undefined;
}

/** The first three groups, trailing zero groups left out, then `::`: one text per /48. */
function networkOf48(groups: readonly number[]): string {
  const prefix = groups.slice(0, 3);
  while (prefix[prefix.length - 1] === 0) prefix.pop();
  return `${prefix.map((g) => g.toString(16)).join(':')}::/48`;
}

export function parseClientAddress(header: string | undefined): ClientAddress | undefined {
  if (header === undefined || header.length === 0 || header.length > MAX_LENGTH) return undefined;
  const v4 = parseIpv4(header);
  if (v4 !== undefined) return { address: header, network: `${v4.slice(0, 3).join('.')}.0/24` };
  const groups = parseIpv6(header);
  if (groups === undefined) return undefined;
  const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
  if (mapped) {
    const [hi = 0, lo = 0] = groups.slice(6);
    return { address: header, network: `${hi >> 8}.${hi & 0xff}.${lo >> 8}.0/24` };
  }
  return { address: header, network: networkOf48(groups) };
}
