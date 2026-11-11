// KBOX-6, KBOX-44, KBOX-48: runtime.lock, the tracked file that pins the Node and Caddy binaries. It is inside H, so H covers
// each binary's sha256; the binaries themselves sit outside the tar. One line per binary:
// `<name> <version> <arch> <sha256 of the installed binary> <official download url>`; `#` lines are comments.

export const BINARY_NAMES = ['node', 'caddy'] as const;
export type BinaryName = (typeof BINARY_NAMES)[number];

export interface PinnedBinary {
  readonly name: BinaryName;
  readonly version: string;
  readonly arch: string;
  readonly sha256: string;
  readonly url: string;
}

const LINE = /^(node|caddy) ([0-9]+\.[0-9]+\.[0-9]+) (arm64|x64) ([0-9a-f]{64}) (https:\/\/(?:nodejs\.org\/dist|github\.com\/caddyserver\/caddy\/releases\/download)\/[A-Za-z0-9._/-]{1,200})$/;

/** Each of the two binaries exactly once, from the official hosts only; anything else is no lock. */
export function parseRuntimeLock(text: string): readonly PinnedBinary[] | undefined {
  const out: PinnedBinary[] = [];
  for (const line of text.split('\n')) {
    if (line === '' || line.startsWith('#')) continue;
    const m = LINE.exec(line);
    if (m === null) return undefined;
    const [, name, version, arch, sha256, url] = m;
    if (name === undefined || version === undefined || arch === undefined || sha256 === undefined || url === undefined) return undefined;
    if (out.some((b) => b.name === name)) return undefined;
    out.push({ name: name as BinaryName, version, arch, sha256, url });
  }
  return BINARY_NAMES.every((n) => out.some((b) => b.name === n)) ? out : undefined;
}
