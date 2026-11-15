// KBOX-66: a QR code encoder and its half-block text renderer, for the Pi's own screen (tty1). Byte mode, error correction
// level M, versions 1 to 10 (up to 213 bytes). Pure and with no dependency: it imports nothing. The address it encodes is
// not a secret; an input too long for version 10 is refused with an error, never encoded truncated.

/** Raised when the input is empty or longer than version 10 holds at level M. Its message never carries the input. */
export class QrTooLongError extends Error {
  constructor() {
    super('The text does not fit one QR code (1 to 213 bytes).');
    this.name = 'QrTooLongError';
  }
}

/** The modules of a code, row by row, no quiet zone; true is dark. */
export type QrMatrix = readonly (readonly boolean[])[];

/** Level M, per version: error-correction codewords per block and the blocks as [count, data codewords] groups. */
const BLOCKS_M: readonly { readonly ec: number; readonly groups: readonly (readonly [count: number, data: number])[] }[] = [
  { ec: 10, groups: [[1, 16]] },
  { ec: 16, groups: [[1, 28]] },
  { ec: 26, groups: [[1, 44]] },
  { ec: 18, groups: [[2, 32]] },
  { ec: 24, groups: [[2, 43]] },
  { ec: 16, groups: [[4, 27]] },
  { ec: 18, groups: [[4, 31]] },
  { ec: 22, groups: [[2, 38], [2, 39]] },
  { ec: 22, groups: [[3, 36], [2, 37]] },
  { ec: 26, groups: [[4, 43], [1, 44]] },
];
const ALIGNMENT: readonly (readonly number[])[] = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
const MAX_VERSION = BLOCKS_M.length;

const at = <T>(a: ArrayLike<T>, i: number): T => {
  const v = a[i];
  if (v === undefined) throw new Error('qr: table index out of range');
  return v;
};
const dataCodewords = (version: number): number => at(BLOCKS_M, version - 1).groups.reduce((s, [count, data]) => s + count * data, 0);
/** Byte mode: 4 bits mode, 8 bits count (16 from version 10), the bytes. */
const countBits = (version: number): number => (version < 10 ? 8 : 16);
const capacity = (version: number): number => Math.floor((dataCodewords(version) * 8 - 4 - countBits(version)) / 8);

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = at(EXP, i - 255);
const mul = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : at(EXP, at(LOG, a) + at(LOG, b)));

const rsRemainder = (data: readonly number[], degree: number): number[] => {
  let gen: number[] = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array<number>(gen.length + 1).fill(0);
    gen.forEach((c, j) => {
      next[j] = at(next, j) ^ c;
      next[j + 1] = at(next, j + 1) ^ mul(c, at(EXP, i));
    });
    gen = next;
  }
  const rem = new Array<number>(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ at(rem, 0);
    rem.shift();
    rem.push(0);
    gen.slice(1).forEach((c, j) => {
      rem[j] = at(rem, j) ^ mul(c, factor);
    });
  }
  return rem;
};

// ---- the codeword stream ----
const bitsOf = (value: number, length: number): number[] => Array.from({ length }, (_, i) => (value >>> (length - 1 - i)) & 1);

const dataStream = (bytes: Uint8Array, version: number): number[] => {
  const bits = [...bitsOf(0b0100, 4), ...bitsOf(bytes.length, countBits(version)), ...Array.from(bytes).flatMap((b) => bitsOf(b, 8))];
  const total = dataCodewords(version) * 8;
  bits.push(...new Array<number>(Math.min(4, total - bits.length)).fill(0));
  while (bits.length % 8 !== 0) bits.push(0);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((v, b) => (v << 1) | b, 0));
  for (let pad = 0xec; out.length < dataCodewords(version); pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
};

/** Splits the data into blocks, adds each block's error correction, and interleaves data then correction. */
const interleaved = (data: readonly number[], version: number): number[] => {
  const { ec, groups } = at(BLOCKS_M, version - 1);
  const blocks: number[][] = [];
  let pos = 0;
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      blocks.push(data.slice(pos, pos + size));
      pos += size;
    }
  }
  const ecs = blocks.map((b) => rsRemainder(b, ec));
  const out: number[] = [];
  const longest = Math.max(...blocks.map((b) => b.length));
  for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.length) out.push(at(b, i));
  for (let i = 0; i < ec; i++) for (const e of ecs) out.push(at(e, i));
  return out;
};

// ---- the module grid ----
interface Grid {
  readonly size: number;
  readonly dark: Uint8Array;
  readonly fixed: Uint8Array; // function modules: never carry data and are never masked
}
const newGrid = (version: number): Grid => {
  const size = 17 + 4 * version;
  return { size, dark: new Uint8Array(size * size), fixed: new Uint8Array(size * size) };
};
const inside = (g: Grid, x: number, y: number): boolean => x >= 0 && y >= 0 && x < g.size && y < g.size;
const isDark = (g: Grid, x: number, y: number): boolean => g.dark[y * g.size + x] === 1;
const isFixed = (g: Grid, x: number, y: number): boolean => g.fixed[y * g.size + x] === 1;
const setFunction = (g: Grid, x: number, y: number, dark: boolean): void => {
  g.dark[y * g.size + x] = dark ? 1 : 0;
  g.fixed[y * g.size + x] = 1;
};

const drawFunctionPatterns = (g: Grid, version: number): void => {
  for (let i = 0; i < g.size; i++) {
    setFunction(g, 6, i, i % 2 === 0);
    setFunction(g, i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [g.size - 4, 3], [3, g.size - 4]] as const) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        if (inside(g, cx + dx, cy + dy)) setFunction(g, cx + dx, cy + dy, dist !== 2 && dist !== 4);
      }
    }
  }
  const centres = at(ALIGNMENT, version - 1);
  const last = centres.length - 1;
  centres.forEach((cy, i) => {
    centres.forEach((cx, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return; // under a finder
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) setFunction(g, cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    });
  });
  drawFormat(g, 0); // reserves the format areas; redrawn with the real mask later
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const a = g.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFunction(g, a, b, ((bits >>> i) & 1) === 1);
      setFunction(g, b, a, ((bits >>> i) & 1) === 1);
    }
  }
};

/** Format information for level M (bits 00) and the mask: BCH(15,5), then xor 0x5412; both copies and the dark module. */
const drawFormat = (g: Grid, mask: number): void => {
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i: number): boolean => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) setFunction(g, 8, i, bit(i));
  setFunction(g, 8, 7, bit(6));
  setFunction(g, 8, 8, bit(7));
  setFunction(g, 7, 8, bit(8));
  for (let i = 9; i < 15; i++) setFunction(g, 14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) setFunction(g, g.size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) setFunction(g, 8, g.size - 15 + i, bit(i));
  setFunction(g, 8, g.size - 8, true);
};

const placeCodewords = (g: Grid, codewords: readonly number[]): void => {
  let i = 0;
  for (let right = g.size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < g.size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const y = ((right + 1) & 2) === 0 ? g.size - 1 - vert : vert;
        if (isFixed(g, x, y) || i >= codewords.length * 8) continue;
        g.dark[y * g.size + x] = (at(codewords, i >> 3) >>> (7 - (i & 7))) & 1;
        i++;
      }
    }
  }
  if (i !== codewords.length * 8) throw new Error('qr: the codewords did not fill the grid');
};

const MASKS: readonly ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

const applyMask = (g: Grid, mask: number): void => {
  const test = at(MASKS, mask);
  for (let y = 0; y < g.size; y++) for (let x = 0; x < g.size; x++) if (!isFixed(g, x, y) && test(x, y)) g.dark[y * g.size + x] = isDark(g, x, y) ? 0 : 1;
};

/** Run lengths of one line, alternating light, dark, light ... (the first is 0 when the line starts dark). */
const runsOf = (line: readonly boolean[]): number[] => {
  const runs = [0];
  let dark = false;
  for (const m of line) {
    if (m === dark) runs[runs.length - 1] = at(runs, runs.length - 1) + 1;
    else {
      runs.push(1);
      dark = m;
    }
  }
  return runs;
};

/** Rule 1 (runs of 5 or more) and rule 3 (the 1:1:3:1:1 finder shape with a light run of 4 on a side) for one line. */
const linePenalty = (line: readonly boolean[]): number => {
  const runs = runsOf(line);
  let score = 0;
  runs.forEach((r, i) => {
    if (r >= 5) score += 3 + (r - 5);
    if (i % 2 === 1 && i >= 3 && i < runs.length - 2 && r % 3 === 0) {
      const unit = r / 3;
      if (at(runs, i - 2) === unit && at(runs, i - 1) === unit && at(runs, i + 1) === unit && at(runs, i + 2) === unit) {
        if (i === 3 || at(runs, i - 3) >= 4 * unit || i + 4 >= runs.length || at(runs, i + 3) >= 4 * unit) score += 40;
      }
    }
  });
  return score;
};

/**
 * The mask penalty. The four rules follow ISO/IEC 18004 8.8.2 as libqrencode 4.1.1 evaluates them (the recorded
 * fixtures are its output, and the mask choice is the one place where encoders differ): rule 3 counts a finder
 * shape touching the symbol edge, rule 4 uses the dark share rounded to a whole percent.
 */
const penalty = (g: Grid): number => {
  const n = g.size;
  let score = 0;
  for (let a = 0; a < n; a++) {
    score += linePenalty(Array.from({ length: n }, (_, b) => isDark(g, b, a)));
    score += linePenalty(Array.from({ length: n }, (_, b) => isDark(g, a, b)));
  }
  for (let y = 0; y + 1 < n; y++) {
    for (let x = 0; x + 1 < n; x++) {
      const c = isDark(g, x, y);
      if (c === isDark(g, x + 1, y) && c === isDark(g, x, y + 1) && c === isDark(g, x + 1, y + 1)) score += 3;
    }
  }
  const darkCount = g.dark.reduce((s, v) => s + v, 0);
  const percent = Math.floor((200 * darkCount + n * n) / (n * n) / 2); // rounded to the nearest whole percent
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return score;
};

/** Encodes the UTF-8 bytes of `text`. Refuses an empty text and one over 213 bytes with a QrTooLongError. */
export const encodeQr = (text: string): QrMatrix => {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  while (version <= MAX_VERSION && bytes.length > capacity(version)) version++;
  if (bytes.length === 0 || version > MAX_VERSION) throw new QrTooLongError();
  const codewords = interleaved(dataStream(bytes, version), version);
  const g = newGrid(version);
  drawFunctionPatterns(g, version);
  placeCodewords(g, codewords);
  let best = { mask: 0, score: Infinity };
  for (let mask = 0; mask < 8; mask++) {
    applyMask(g, mask);
    drawFormat(g, mask);
    const score = penalty(g);
    if (score < best.score) best = { mask, score };
    applyMask(g, mask); // xor again: undone
  }
  applyMask(g, best.mask);
  drawFormat(g, best.mask);
  return Array.from({ length: g.size }, (_, y) => Array.from({ length: g.size }, (_, x) => isDark(g, x, y)));
};

const QUIET = 4;
/**
 * The code as half-block text for a dark terminal: light modules (and the quiet zone of 4) are filled, dark modules are
 * the terminal's own background, two module rows to a text row; then a blank line and the text itself, so a person
 * can type it. Ends with a newline.
 */
export const renderQr = (text: string): string => {
  const m = encodeQr(text);
  const n = m.length;
  const dark = (x: number, y: number): boolean => m[y - QUIET]?.[x - QUIET] === true;
  const width = n + 2 * QUIET;
  const rows: string[] = [];
  for (let y = 0; y < width; y += 2) {
    let line = '';
    for (let x = 0; x < width; x++) {
      const upper = !dark(x, y);
      const lower = !dark(x, y + 1);
      line += upper ? (lower ? '█' : '▀') : lower ? '▄' : ' ';
    }
    rows.push(line);
  }
  return `${rows.join('\n')}\n\n${text}\n`;
};
