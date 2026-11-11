// KBOX-25: path templates and query shapes of an allow rule. A template segment is a literal, a typed parameter
// `{name:[class]{min,max}}` or, last, `{rest:**}`; every segment is matched against the decoded segments of the one parse
// (src/pure/target-parse.ts).
import type { QueryShape } from '../ports/relay-profile.ts';
import type { QueryPair } from './target-parse.ts';

type Segment =
  | { readonly kind: 'literal'; readonly text: string }
  | { readonly kind: 'param'; readonly test: RegExp }
  | { readonly kind: 'rest' };

export interface Template {
  readonly segments: readonly Segment[];
  readonly hasTail: boolean;
}

export type TemplateParse = { readonly ok: true; readonly template: Template } | { readonly ok: false };

const LITERAL = /^[A-Za-z0-9._~:@!$'()*+,=-]+$/;
const PARAM = /^\{([a-z][A-Za-z0-9_]{0,31}):\[((?:[A-Za-z0-9_.~]|[A-Za-z0-9]-[A-Za-z0-9]|-)+)\]\{(\d{1,3}),(\d{1,3})\}\}$/;
const REST = '{rest:**}';
const LONGEST_PARAM = 256;
/** A tail segment is still validated: RFC 3986 unreserved characters only, 1 to 128 of them. */
const TAIL_SEGMENT = /^[A-Za-z0-9._~-]{1,128}$/;

function paramOf(text: string): Segment | undefined {
  const m = PARAM.exec(text);
  if (m === null) return undefined;
  const [, , cls = '', minText = '', maxText = ''] = m;
  const min = Number(minText);
  const max = Number(maxText);
  if (min < 1 || min > max || max > LONGEST_PARAM) return undefined;
  for (const range of cls.matchAll(/([A-Za-z0-9])-([A-Za-z0-9])/g)) {
    const [, from = '', to = ''] = range;
    if (from > to) return undefined;
  }
  return { kind: 'param', test: new RegExp(`^[${cls}]{${min},${max}}$`) };
}

export function compileTemplate(text: string): TemplateParse {
  if (!text.startsWith('/')) return { ok: false };
  const raw = text.slice(1).split('/');
  const segments: Segment[] = [];
  for (const [i, piece] of raw.entries()) {
    if (piece === REST) {
      if (i !== raw.length - 1) return { ok: false };
      segments.push({ kind: 'rest' });
    } else if (piece.startsWith('{')) {
      const param = paramOf(piece);
      if (param === undefined) return { ok: false };
      segments.push(param);
    } else if (LITERAL.test(piece) && piece !== '.' && piece !== '..') {
      segments.push({ kind: 'literal', text: piece });
    } else {
      return { ok: false };
    }
  }
  return { ok: true, template: { segments, hasTail: segments.some((s) => s.kind === 'rest') } };
}

export function matchTemplate(template: Template, path: readonly string[]): boolean {
  const fixed = template.hasTail ? template.segments.length - 1 : template.segments.length;
  if (template.hasTail ? path.length <= fixed : path.length !== fixed) return false;
  for (const [i, segment] of template.segments.entries()) {
    if (segment.kind === 'rest') return path.slice(i).every((s) => TAIL_SEGMENT.test(s));
    const got = path[i];
    if (got === undefined) return false;
    if (segment.kind === 'literal' ? got !== segment.text : !segment.test.test(got)) return false;
  }
  return true;
}

const DECIMAL = /^(0|[1-9][0-9]{0,15})$/;

function valueFits(shape: QueryShape, value: string): boolean {
  switch (shape.kind) {
    case 'word':
      return shape.words.includes(value);
    case 'int': {
      if (!DECIMAL.test(value)) return false;
      const n = Number(value);
      return n >= shape.min && n <= shape.max;
    }
  }
}

/** Every key must be listed by the rule and its value must have the listed shape. Listed keys are optional. */
export function queryFits(shapes: Readonly<Record<string, QueryShape>>, pairs: readonly QueryPair[]): boolean {
  return pairs.every(([name, value]) => {
    const shape = Object.hasOwn(shapes, name) ? shapes[name] : undefined;
    return shape !== undefined && valueFits(shape, value);
  });
}
