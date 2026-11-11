// KBOX-6: the one home of the release's content hash H and of the name and size rules a release tree obeys. The intake
// (core) and kb-install (root) both apply them: core to the tar it takes, kb-install again to the tree it reads from the
// descriptors it holds, so the checks at intake are not the only ones.
import { createHash } from 'node:crypto';

/** The limits of a release tree: 20 MiB of file bytes in all, 5,000 entries, 255-byte paths. */
export const RELEASE_LIMITS = { totalBytes: 20 * 1024 * 1024, entries: 5000, pathBytes: 255 } as const;

/** A release hash: SHA-256, lower-case hex. */
export const RELEASE_HASH = /^[0-9a-f]{64}$/;

const BACKSLASH = 0x5c;
const SLASH = 0x2f;
const utf8 = new TextDecoder('utf-8', { ignoreBOM: true });

const isControl = (b: number): boolean => b < 0x20 || b === 0x7f;

/** One path segment: non-empty, not `.` or `..`, valid UTF-8, no slash, backslash or control byte (NUL and newline included). */
export function checkSegment(raw: Uint8Array): string | undefined {
  if (raw.length === 0 || raw.length > RELEASE_LIMITS.pathBytes) return undefined;
  for (const b of raw) if (isControl(b) || b === BACKSLASH || b === SLASH) return undefined;
  // Valid UTF-8 exactly when decoding and encoding again gives the same bytes: an invalid or overlong sequence decodes to
  // U+FFFD, which encodes to other bytes.
  const segment = utf8.decode(raw);
  if (!Buffer.from(segment, 'utf8').equals(raw)) return undefined;
  return segment === '.' || segment === '..' ? undefined : segment;
}

/** A relative path of at most 255 bytes whose every segment passes `checkSegment`. */
export function checkPath(raw: Uint8Array): string | undefined {
  if (raw.length === 0 || raw.length > RELEASE_LIMITS.pathBytes) return undefined;
  const parts: string[] = [];
  let start = 0;
  for (let i = 0; i <= raw.length; i += 1) {
    if (i === raw.length || raw[i] === SLASH) {
      const segment = checkSegment(raw.subarray(start, i));
      if (segment === undefined) return undefined;
      parts.push(segment);
      start = i + 1;
    }
  }
  return parts.join('/');
}

export interface HashedFile {
  readonly path: string;
  /** The owner-execute bit: mode 0755 in the hash text, else 0644. */
  readonly executable: boolean;
  /** SHA-256 of the file's bytes, lower-case hex. */
  readonly sha256: string;
}

const byPathBytes = (a: HashedFile, b: HashedFile): number => Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8'));

/** One line per file, sorted bytewise by path: `<mode> <sha256 hex> <path>\n`. */
export function releaseText(files: readonly HashedFile[]): string {
  return [...files]
    .sort(byPathBytes)
    .map((f) => `${f.executable ? '0755' : '0644'} ${f.sha256} ${f.path}\n`)
    .join('');
}

/** H: SHA-256 of the release text. */
export function releaseHash(files: readonly HashedFile[]): string {
  return createHash('sha256').update(releaseText(files), 'utf8').digest('hex');
}

/** SHA-256 of one file's bytes, lower-case hex. */
export function fileSha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
