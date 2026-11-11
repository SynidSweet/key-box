// A reference reader of the share file (KBOX-33), written from devbox admin-secrets-spec section 4's CI backend and the share-file
// layout alone. It imports nothing from src/: writer and reader do not share a mistake. It fails closed: a file it cannot verify,
// read in full, or that is older than one it has already seen gives a refusal and no findings.
import { createHmac, createPublicKey, verify } from 'node:crypto';

export type Refusal = 'bad_envelope' | 'bad_signature' | 'bad_body' | 'rolled_back';

export interface Finding {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly form: string;
  /** Offset of the copy in the raw bytes scanned. */
  readonly start: number;
}

export interface OpenShare {
  readonly version: number;
  scan(content: Uint8Array): Finding[];
}

export type OpenResult = { readonly ok: true; readonly share: OpenShare } | { readonly ok: false; readonly code: Refusal };

export interface OpenOptions {
  /** The highest version already seen: a file below it is a rollback and is refused. */
  readonly lastVersion?: number;
}

const WINDOW = 24;
const STRIDE = 9;
const PROBES = 40;
const FORMS = ['raw', 'b64s0', 'b64s1', 'b64s2', 'b64u0', 'b64u1', 'b64u2'];
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');

interface Entry {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly tier: 'windowed' | 'anchored';
  readonly form: string;
  readonly anchor: string;
  readonly len: number;
  readonly digest: string;
}
interface Probe {
  readonly entry: number;
  readonly j: number;
  readonly d: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function parseEntry(raw: unknown): Entry | undefined {
  if (!isRecord(raw)) return undefined;
  const { project, name, gen, retired, tier, form } = raw;
  if (typeof project !== 'string' || typeof name !== 'string' || typeof gen !== 'number' || typeof retired !== 'boolean' || typeof form !== 'string') return undefined;
  if (!FORMS.includes(form)) return undefined;
  const base = { project, name, gen, retired, form };
  if (tier === 'windowed') return Object.keys(raw).length === 6 ? { ...base, tier, anchor: '', len: 0, digest: '' } : undefined;
  const { anchor, len, digest } = raw;
  if (tier !== 'anchored' || typeof anchor !== 'string' || typeof len !== 'number' || typeof digest !== 'string' || Object.keys(raw).length !== 9) return undefined;
  return { ...base, tier, anchor, len, digest };
}

function parseProbe(raw: unknown): Probe | undefined {
  if (!isRecord(raw) || Object.keys(raw).length !== 3) return undefined;
  const { entry, j, d } = raw;
  return typeof entry === 'number' && typeof j === 'number' && typeof d === 'string' && /^[0-9a-f]{64}$/.test(d) ? { entry, j, d } : undefined;
}

/** The raw bytes with every whitespace byte and every backslash that precedes a line break removed, and the raw offset of each byte kept. */
function strippedView(raw: Buffer): { readonly bytes: Buffer; readonly offsets: number[] } {
  const kept: number[] = [];
  const offsets: number[] = [];
  for (let i = 0; i < raw.length; i += 1) {
    const b = raw[i] ?? 0;
    const blank = b === 0x20 || (b >= 0x09 && b <= 0x0d);
    const next = raw[i + 1];
    const folded = b === 0x5c && (next === 0x0a || next === 0x0d);
    if (blank || folded) continue;
    kept.push(b);
    offsets.push(i);
  }
  return { bytes: Buffer.from(kept), offsets };
}

/** Characters of a base64 form between the end of the anchor and the first character fixed by core bytes alone: 0 or 1. */
function gapAfterAnchor(form: string, anchorLength: number): number {
  const first = form === 'raw' ? 0 : [0, 2, 3][Number(form.slice(-1))] ?? 0;
  return form === 'raw' || (first + anchorLength) % 4 === 0 ? 0 : 1;
}

export function openShare(envelope: Uint8Array, publicKeyRawB64: string, options: OpenOptions = {}): OpenResult {
  const refuse = (code: Refusal): OpenResult => ({ ok: false, code });
  let outer: unknown;
  try {
    outer = JSON.parse(Buffer.from(envelope).toString('utf8'));
  } catch {
    return refuse('bad_envelope');
  }
  if (!isRecord(outer) || Object.keys(outer).length !== 4 || outer['format'] !== 'kbox-share' || outer['v'] !== 3) return refuse('bad_envelope');
  const { body_b64: bodyB64, sig_b64: sigB64 } = outer;
  if (typeof bodyB64 !== 'string' || typeof sigB64 !== 'string') return refuse('bad_envelope');
  const bodyBytes = Buffer.from(bodyB64, 'base64');
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(publicKeyRawB64, 'base64')]), format: 'der', type: 'spki' });
  if (!verify(null, bodyBytes, key, Buffer.from(sigB64, 'base64'))) return refuse('bad_signature');
  let body: unknown;
  try {
    body = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    return refuse('bad_body');
  }
  if (!isRecord(body) || Object.keys(body).length !== 4) return refuse('bad_body');
  const { header, entries: rawEntries, probes: rawProbes } = body;
  if (!isRecord(header) || header['v'] !== 3 || header['stride'] !== STRIDE || typeof header['version'] !== 'number' || typeof header['salt_b64'] !== 'string' || !Array.isArray(rawEntries) || !Array.isArray(rawProbes)) {
    return refuse('bad_body');
  }
  if (Object.hasOwn(header, 'baseline')) return refuse('bad_body');
  const entries = rawEntries.map(parseEntry);
  const probes = rawProbes.map(parseProbe);
  if (entries.some((e) => e === undefined) || probes.some((p) => p === undefined)) return refuse('bad_body');
  const known = entries.filter((e): e is Entry => e !== undefined);
  const listed = probes.filter((p): p is Probe => p !== undefined);
  for (const [index, entry] of known.entries()) {
    if (entry.tier !== 'windowed') continue;
    const mine = listed.filter((p) => p.entry === index);
    if (mine.length !== PROBES || mine.some((p, i) => p.j !== i * STRIDE)) return refuse('bad_body');
  }
  if (listed.some((p) => known[p.entry]?.tier !== 'windowed')) return refuse('bad_body');
  const { version } = header;
  if (options.lastVersion !== undefined && version < options.lastVersion) return refuse('rolled_back');
  const salt = Buffer.from(header['salt_b64'], 'base64');
  const mac = (bytes: Uint8Array): string => createHmac('sha256', salt).update(bytes).digest('hex');
  const byDigest = new Map<string, Probe[]>();
  for (const p of listed) byDigest.set(p.d, [...(byDigest.get(p.d) ?? []), p]);

  const scan = (content: Uint8Array): Finding[] => {
    const raw = Buffer.from(content);
    const views = [{ bytes: raw, offsets: undefined }, strippedView(raw)];
    const found = new Map<string, Finding>();
    const report = (index: number, startInView: number, offsets: number[] | undefined): void => {
      const entry = known[index];
      if (entry === undefined) return;
      const start = offsets === undefined ? startInView : (offsets[startInView] ?? startInView);
      found.set(`${index}:${start}`, { project: entry.project, name: entry.name, gen: entry.gen, retired: entry.retired, form: entry.form, start });
    };
    for (const view of views) {
      for (let i = 0; i + WINDOW <= view.bytes.length; i += 1) {
        for (const p of byDigest.get(mac(view.bytes.subarray(i, i + WINDOW))) ?? []) report(p.entry, i - p.j, view.offsets);
      }
      for (const [index, entry] of known.entries()) {
        if (entry.tier !== 'anchored') continue;
        const anchor = Buffer.from(entry.anchor, 'latin1');
        for (let at = view.bytes.indexOf(anchor); at >= 0; at = view.bytes.indexOf(anchor, at + 1)) {
          const runAt = at + anchor.length + gapAfterAnchor(entry.form, anchor.length);
          const run = view.bytes.subarray(runAt, runAt + entry.len);
          if (run.length === entry.len && mac(run) === entry.digest) report(index, at, view.offsets);
        }
      }
    }
    return [...found.values()].sort((a, b) => a.start - b.start || a.name.localeCompare(b.name) || a.form.localeCompare(b.form));
  };
  return { ok: true, share: { version, scan } };
}
