// KBOX-49, KBOX-20, KBOX-53: the setup, recovery and approver-registration codes: 12 words of the BIP-39 English list,
// 132 random bits (11 bits per word, most significant first). Only a hash is kept: SHA-256 of the lower-case words joined
// by single spaces. Nothing here logs or returns a code in an error.
import { createHash, timingSafeEqual } from 'node:crypto';

export const CODE_WORDS = 12;
const BITS_PER_WORD = 11;
/** 132 bits need 17 bytes; the last 4 bits of the 17th are not used. */
export const CODE_BYTES = 17;
const LIST_SIZE = 2048;

/** The word list as the data file holds it: 2048 distinct lower-case words, one per line, sorted. */
export function parseWordlist(text: string): readonly string[] {
  const words = text.split('\n').filter((w) => w !== '');
  const sorted = [...words].sort();
  if (words.length !== LIST_SIZE || new Set(words).size !== LIST_SIZE || !words.every((w, i) => /^[a-z]{3,8}$/.test(w) && w === sorted[i])) {
    throw new RangeError('the code word list is not 2048 sorted distinct lower-case words');
  }
  return words;
}

/** `count` words for the first `count * 11` bits of `bytes`, most significant first. */
function wordsOf(bytes: Uint8Array, count: number, wordlist: readonly string[]): string {
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  bits >>= BigInt(bytes.length * 8 - count * BITS_PER_WORD);
  const words: string[] = [];
  for (let i = count - 1; i >= 0; i -= 1) words.push(wordlist[Number((bits >> BigInt(i * BITS_PER_WORD)) & 0x7ffn)] ?? '');
  return words.join(' ');
}

/** The 12 words for the first 132 bits of `bytes`. */
export function codeFromBytes(bytes: Uint8Array, wordlist: readonly string[]): string {
  if (bytes.length !== CODE_BYTES) throw new RangeError(`a code is drawn from ${CODE_BYTES} random bytes`);
  return wordsOf(bytes, CODE_WORDS, wordlist);
}

/** A new approver's fingerprint is this many words (spec revision 4). */
export const FINGERPRINT_WORDS = 6;

/**
 * The fingerprint both phones show for an approver_add (spec revision 4): 6 words of the code list over
 * SHA-256(cose_sha256 ‖ device_sha256), the two hashes taken as their 32 bytes each.
 */
export function approverFingerprint(coseSha256: string, deviceSha256: string, wordlist: readonly string[]): string {
  const digest = createHash('sha256').update(Buffer.from(coseSha256, 'hex')).update(Buffer.from(deviceSha256, 'hex')).digest();
  return wordsOf(digest, FINGERPRINT_WORDS, wordlist);
}

/** A typed code in its one hashed form: lower case, single spaces, exactly 12 words of the list; undefined otherwise. */
export function normaliseCode(typed: string, wordlist: readonly string[]): string | undefined {
  if (typed.length > 200) return undefined;
  const words = typed.trim().toLowerCase().split(/\s+/);
  if (words.length !== CODE_WORDS || !words.every((w) => wordlist.includes(w))) return undefined;
  return words.join(' ');
}

/** Lower-case hex SHA-256 of the normalised code. */
export function codeHash(code: string): string {
  return createHash('sha256').update(code, 'utf8').digest('hex');
}

/** Constant-time comparison of a typed code against a kept hash. */
export function codeMatches(typed: string, keptHash: string, wordlist: readonly string[]): boolean {
  const normal = normaliseCode(typed, wordlist);
  if (normal === undefined || !/^[0-9a-f]{64}$/.test(keptHash)) return false;
  return timingSafeEqual(Buffer.from(codeHash(normal), 'hex'), Buffer.from(keptHash, 'hex'));
}
