// KBOX-64 (N-M5): the one comparison of a Tailscale node name with the box's host. Tailscale's `Self.DNSName` may end in a dot and
// the host may be written in capitals; every caller uses this so none decides that for itself.

/** Drops ONE trailing dot and lowercases ASCII letters only. */
const normal = (name: string): string => (name.endsWith('.') ? name.slice(0, -1) : name).replace(/[A-Z]/g, (c) => c.toLowerCase());

export const sameHostName = (a: string, b: string): boolean => normal(a) === normal(b);
