// Architecture tests: KBOX-27 (toolchain), KBOX-28 (pure core, layers, cycles, catches), KBOX-35 (kit independence),
// KBOX-42 (probe reports). Each rule is shown red on a fixture that breaks it, and green on the repo's own tree.
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkCatches,
  checkCycles,
  checkErasable,
  checkKitIndependence,
  checkLayers,
  checkProbes,
  checkPure,
  checkSourceImports,
  checkStaticCli,
  checkStrippedText,
  checkToolchain,
  checkTypecheck,
  checkZeroCounts,
  walk,
} from './arch/index.ts';
import type { Violation, ViolationCode } from './arch/index.ts';
import { GOOD_PACKAGE, GOOD_TSCONFIG, REPO_ROOT, goodTree, materialise, withChanges, withPackage, withTsconfig } from './arch/fixture.ts';
import type { Tree } from './arch/fixture.ts';

const codes = (violations: readonly Violation[]): ViolationCode[] => violations.map((v) => v.code);

type Check = (root: string) => Promise<Violation[]>;

async function judge(t: TestContext, tree: Tree, check: Check, options: { withNodeModules?: boolean } = {}): Promise<Violation[]> {
  return check(await materialise(t, tree, options));
}

/** The tree must be refused with exactly this code among its findings. */
async function refuses(t: TestContext, tree: Tree, check: Check, code: ViolationCode, options: { withNodeModules?: boolean } = {}): Promise<void> {
  const found = await judge(t, tree, check, options);
  assert.ok(codes(found).includes(code), `expected ${code}, got ${JSON.stringify(found)}`);
}

async function accepts(t: TestContext, tree: Tree, check: Check, options: { withNodeModules?: boolean } = {}): Promise<void> {
  assert.deepEqual(await judge(t, tree, check, options), []);
}

const inShell = (code: string): Tree => withChanges({ 'src/shell/x.ts': code });
const inPure = (code: string): Tree => withChanges({ 'src/pure/x.ts': code });

// ---------------------------------------------------------------- KBOX-27

test('KBOX-27 a tree with the exact toolchain passes the toolchain check', (t) => accepts(t, goodTree(), checkToolchain));

test('KBOX-27 a dependencies key, even an empty one, is refused', async (t) => {
  await refuses(t, withPackage({ dependencies: {} }), checkToolchain, 'dependencies-key');
  await refuses(t, withPackage({ dependencies: { left: '1.0.0' } }), checkToolchain, 'dependencies-key');
});

test('KBOX-27 devDependencies are exactly typescript and @types/node: a third package, a missing one or a renamed one is refused', async (t) => {
  const base = GOOD_PACKAGE.devDependencies;
  await refuses(t, withPackage({ devDependencies: { ...base, eslint: '9.0.0' } }), checkToolchain, 'dev-dependency-set');
  await refuses(t, withPackage({ devDependencies: { typescript: '6.0.3' } }), checkToolchain, 'dev-dependency-set');
  await refuses(t, withPackage({ devDependencies: { '@types/node': '24.1.0' } }), checkToolchain, 'dev-dependency-set');
  await refuses(t, withPackage({ devDependencies: { '@types/node': '24.1.0', 'typescript-x': '6.0.3' } }), checkToolchain, 'dev-dependency-set');
});

for (const range of ['^6.0.3', '~6.0.3', '>=6', 'latest', '6.x', '6', '6.0.3-beta.1', '*', 'workspace:*', '']) {
  test(`KBOX-27 a dev dependency version of "${range}" is not an exact version and is refused`, async (t) => {
    await refuses(t, withPackage({ devDependencies: { ...GOOD_PACKAGE.devDependencies, typescript: range } }), checkToolchain, 'dev-dependency-range');
    await refuses(t, withPackage({ devDependencies: { ...GOOD_PACKAGE.devDependencies, '@types/node': range } }), checkToolchain, 'dev-dependency-range');
  });
}

test('KBOX-27 the major of @types/node must equal the major in .nvmrc', async (t) => {
  await accepts(t, withChanges({ '.nvmrc': 'v24.2.0\n' }), checkToolchain);
  await refuses(t, withChanges({ '.nvmrc': '25\n' }), checkToolchain, 'types-node-major');
  await refuses(t, withChanges({ '.nvmrc': '23.9.0\n' }), checkToolchain, 'types-node-major');
  await refuses(t, withChanges({ '.nvmrc': 'lts/*\n' }), checkToolchain, 'types-node-major');
  await refuses(t, withChanges({ '.nvmrc': null }), checkToolchain, 'types-node-major');
});

test('KBOX-27 tsconfig types must be exactly ["node"]', async (t) => {
  await refuses(t, withTsconfig({ types: [] }), checkToolchain, 'tsconfig-types');
  await refuses(t, withTsconfig({ types: ['node', 'other'] }), checkToolchain, 'tsconfig-types');
  await refuses(t, withTsconfig({ types: ['other'] }), checkToolchain, 'tsconfig-types');
  await refuses(t, withTsconfig({ types: undefined }), checkToolchain, 'tsconfig-types');
});

for (const flag of Object.keys(GOOD_TSCONFIG.compilerOptions).filter((k) => GOOD_TSCONFIG.compilerOptions[k as keyof typeof GOOD_TSCONFIG.compilerOptions] === true)) {
  if (flag === 'allowJs' || flag === 'skipLibCheck') continue;
  test(`KBOX-27 tsconfig option ${flag} must be true: false and absent are both refused`, async (t) => {
    await refuses(t, withTsconfig({ [flag]: false }), checkToolchain, 'tsconfig-option');
    await refuses(t, withTsconfig({ [flag]: undefined }), checkToolchain, 'tsconfig-option');
  });
}

test('KBOX-27 tsconfig must include src and test so tests are checked too', async (t) => {
  await refuses(t, withTsconfig({}, { include: ['src'] }), checkToolchain, 'tsconfig-include');
  await refuses(t, withTsconfig({}, { include: ['test'] }), checkToolchain, 'tsconfig-include');
  await refuses(t, withTsconfig({}, { include: undefined }), checkToolchain, 'tsconfig-include');
});

test('KBOX-27 a .d.ts that declares a node: module is refused, one that declares another module is not', async (t) => {
  await refuses(t, withChanges({ 'src/shims.d.ts': "declare module 'node:fs' {\n  export const x: number;\n}\n" }), checkToolchain, 'node-module-stub');
  await refuses(t, withChanges({ 'test/shims.d.ts': 'declare module "node:sqlite" {}\n' }), checkToolchain, 'node-module-stub');
  await accepts(t, withChanges({ 'src/shims.d.ts': "declare module 'some-asset' {\n  const x: string;\n  export default x;\n}\n" }), checkToolchain);
});

test('KBOX-27 a missing package-lock.json is refused', (t) => refuses(t, withChanges({ 'package-lock.json': null }), checkToolchain, 'lockfile-missing'));

test('KBOX-27 node_modules must be ignored and no tracked file may sit under it', async (t) => {
  await refuses(t, withChanges({ '.gitignore': '*.log\n' }), checkToolchain, 'node-modules-not-ignored');
  await refuses(t, withChanges({ '.gitignore': null }), checkToolchain, 'node-modules-not-ignored');
  const root = await materialise(t, goodTree());
  const found = await checkToolchain(root, { trackedFiles: ['src/a.ts', 'node_modules/typescript/lib/tsc.js'] });
  assert.ok(codes(found).includes('node-modules-tracked'));
  assert.deepEqual(await checkToolchain(root, { trackedFiles: ['src/a.ts'] }), []);
});

test('KBOX-27 a package.json that is missing or not JSON is reported as unreadable, never passed', async (t) => {
  await refuses(t, withChanges({ 'package.json': null }), checkToolchain, 'unreadable');
  await refuses(t, withChanges({ 'package.json': '{ not json' }), checkToolchain, 'unreadable');
  await refuses(t, withChanges({ 'tsconfig.json': null }), checkToolchain, 'unreadable');
});

test('KBOX-27 import specifiers in src are node: builtins or relative paths ending .ts or .js', async (t) => {
  await accepts(
    t,
    inShell(
      "import { readFile } from 'node:fs/promises';\nimport type { Clock } from '../ports/clock.ts';\nimport a from './y.js';\nexport { b } from './y.ts';\nexport * from '../pure/add.ts';\nconst m = await import('./y.ts');\nconst n = await import('node:os');\nexport type T = typeof import('./y.ts');\nexport const keep = [readFile, a, m, n];\nexport type C = Clock;\n",
    ),
    checkSourceImports,
  );
});

for (const [why, code] of [
  ['a builtin without the node: prefix', "import fs from 'fs';\n"],
  ['a builtin that does not exist', "import x from 'node:no-such-builtin';\n"],
  ['a package', "import x from 'lodash';\n"],
  ['a type-only import of a package', "import type { X } from 'some-types';\n"],
  ['a relative path without an extension', "import x from './y';\n"],
  ['a relative path to a json file', "import x from './y.json';\n"],
  ['a relative path ending .mjs', "import x from './y.mjs';\n"],
  ['a package re-export', "export * from 'pkg';\n"],
  ['a dynamic import with a computed specifier', "const name = './a'; export const m = import(name + '.ts');\n"],
  ['a require call', "const fs = require('node:fs');\nexport { fs };\n"],
  ['an import type of a package', "export type T = import('pkg').X;\n"],
  ['an absolute path', "import x from '/etc/y.ts';\n"],
] as const) {
  test(`KBOX-27 a src file with ${why} is refused`, (t) => refuses(t, inShell(code), checkSourceImports, 'import-specifier'));
}

test('KBOX-27 a src file importing typescript or @types/node is refused as a dev package import', async (t) => {
  for (const spec of ['typescript', 'typescript/lib/typescript.js', '@types/node', '@types/node/fs.d.ts']) {
    await refuses(t, inShell(`import x from '${spec}';\nexport { x };\n`), checkSourceImports, 'src-imports-dev-package');
  }
});

test('KBOX-27 only src is held to the specifier rule: a test file may import a package', (t) =>
  accepts(t, withChanges({ 'test/uses-ts.test.ts': "import ts from 'typescript';\nexport { ts };\n" }), checkSourceImports));

test('KBOX-27 src files use erasable syntax only: enum, namespace, parameter property, decorator and export = are refused', async (t) => {
  await accepts(
    t,
    inShell(
      "export interface A<T> { readonly x: T }\nexport abstract class B<T> {\n  readonly v: number;\n  constructor(v: number) { this.v = v; }\n  abstract get(): T;\n}\nexport const f = <T,>(a: T): T => a as T;\nexport const g = { k: 1 } satisfies Record<string, number>;\nexport function h(a: string): string;\nexport function h(a: number): number;\nexport function h(a: string | number): string | number { return a; }\nexport declare const d: number;\nexport type U = 'a' | 'b';\n",
    ),
    checkErasable,
  );
  for (const code of [
    'export enum E { A, B }\n',
    'export const enum E { A }\n',
    'export namespace N { export const a = 1; }\n',
    'export class C { constructor(private readonly x: number) {} }\n',
    'export class C { constructor(public x: number) {} }\n',
    'declare const dec: ClassDecorator;\n@dec\nexport class C {}\n',
    'const a = 1;\nexport = a;\n',
    "import fs = require('node:fs');\nexport { fs };\n",
  ]) {
    await refuses(t, inShell(code), checkErasable, 'ts-runtime-syntax');
  }
});

test('KBOX-27 stripping must keep the line count and leave valid JavaScript', () => {
  assert.deepEqual(checkStrippedText('src/a.ts', 'const a: number = 1;\n', 'const a         = 1;\n'), []);
  assert.deepEqual(codes(checkStrippedText('src/a.ts', 'const a: number = 1;\nconst b = 2;\n', 'const a = 1;\n')), ['strip-line-count']);
  assert.deepEqual(codes(checkStrippedText('src/a.ts', 'const a: number = 1;\n', 'const = ;\n')), ['strip-reparse']);
});

test('KBOX-27 a src file the stripper refuses is reported as runtime syntax, with the stripper injected', async (t) => {
  const root = await materialise(t, goodTree());
  const refusing = (): string => {
    throw new Error('stripper says no');
  };
  assert.ok(codes(await checkErasable(root, refusing)).includes('ts-runtime-syntax'));
});

test('KBOX-27 the counts of any, non-null !, ts-ignore, ts-expect-error, ts-nocheck, eslint-disable and noqa are zero', async (t) => {
  await accepts(
    t,
    withChanges({
      'src/shell/words.ts': "// any value is fine in prose\nexport const s = 'x as any, @ts-ignore, noqa, !';\nexport const ok = (a: number | undefined): boolean => a !== undefined && a != null;\n/** any thing goes in prose */\nexport const t = `${s} eslint-disable`;\n",
    }),
    checkZeroCounts,
  );
  const bad: [string, ViolationCode][] = [
    ['export let x: any = 1;\n', 'count-any'],
    ['export const x = [] as Array<any>;\n', 'count-any'],
    ['export const x = 1 as any;\n', 'count-any'],
    ['export const f = (a: string | undefined): number => a!.length;\n', 'count-non-null'],
    ['declare const a: { b?: number };\nexport const c = a.b!;\n', 'count-non-null'],
    ['// @ts-ignore\nexport const x: number = "a";\n', 'count-ts-ignore'],
    ['export const x: number = /* @ts-ignore */ 1;\n', 'count-ts-ignore'],
    ['// @ts-expect-error\nexport const x: number = "a";\n', 'count-ts-expect-error'],
    ['// @ts-nocheck\nexport const x = 1;\n', 'count-ts-nocheck'],
    ['// eslint-disable-next-line no-console\nexport const x = 1;\n', 'count-eslint-disable'],
    ['/* eslint-disable */\nexport const x = 1;\n', 'count-eslint-disable'],
    ['export const x = 1; // noqa\n', 'count-noqa'],
    ['export const x = 1;\n// @ts-ignore at the very end', 'count-ts-ignore'],
  ];
  for (const [code, expected] of bad) {
    await refuses(t, inShell(code), checkZeroCounts, expected);
    await refuses(t, withChanges({ 'test/helper.ts': code }), checkZeroCounts, expected);
  }
  await refuses(t, withChanges({ 'src/web/app.js': '/** @type {any} */\nexport const x = 1;\n' }), checkZeroCounts, 'count-any');
  await refuses(t, withChanges({ 'src/web/app.js': '/** @param {Array<any>} a */\nexport const f = (a) => a;\n' }), checkZeroCounts, 'count-any');
  await refuses(t, withChanges({ 'src/web/app.js': '// @ts-ignore\nexport const x = 1;\n' }), checkZeroCounts, 'count-ts-ignore');
});

test('KBOX-27 tsc --noEmit is clean on a good tree and fails on a type error, an implicit any and an unchecked index', async (t) => {
  await accepts(t, goodTree(), checkTypecheck, { withNodeModules: true });
  await refuses(t, inShell("export const n: number = 'a';\n"), checkTypecheck, 'typecheck', { withNodeModules: true });
  await refuses(t, inShell('export const f = (x) => x;\n'), checkTypecheck, 'typecheck', { withNodeModules: true });
  await refuses(t, inShell('export const f = (xs: string[]): number => xs[0].length;\n'), checkTypecheck, 'typecheck', { withNodeModules: true });
  await refuses(t, inShell("import { readFileSync } from 'node:fs';\nexport const r = readFileSync('x', 'utf8') satisfies number;\n"), checkTypecheck, 'typecheck', { withNodeModules: true });
});

// ---------------------------------------------------------------- KBOX-28

test('KBOX-28 src/pure may use hashing, HMAC, key derivation, verification, fixed-IV AES-GCM, dates built from an argument and plain maths', (t) =>
  accepts(
    t,
    inPure(
      "import { createCipheriv, createHash, createHmac, hkdfSync, verify } from 'node:crypto';\nimport { Buffer } from 'node:buffer';\nimport { posix } from 'node:path';\nexport const digest = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');\nexport const mac = (k: Uint8Array, b: Uint8Array): Buffer => createHmac('sha256', k).update(b).digest();\nexport const day = (ms: number): number => new Date(ms).getUTCDay() + Date.UTC(2020, 1, 1) + Math.floor(ms);\nexport const keep = [hkdfSync, verify, createCipheriv, posix];\nexport const obj = { process: 1, fetch: 2, setTimeout: 3 };\nexport interface P { fetch(): void; process: number }\nexport class K { fetch(): number { return 1; } }\nexport const processed = (o: { process: number }): number => o.process;\n",
    ),
    checkPure,
  ));

for (const spec of ['fs', 'net', 'http', 'http2', 'https', 'tls', 'dns', 'os', 'child_process', 'sqlite', 'worker_threads']) {
  test(`KBOX-28 src/pure may not import node:${spec} (static, type-only, dynamic, re-export, sub-path, or without the prefix)`, async (t) => {
    const forms = [
      `import * as m from 'node:${spec}';\nexport { m };\n`,
      `import type * as m from 'node:${spec}';\nexport type M = typeof m;\n`,
      `export const m = await import('node:${spec}');\n`,
      `export * from 'node:${spec}';\n`,
      `import * as m from '${spec}';\nexport { m };\n`,
      `export type M = import('node:${spec}').Foo;\n`,
    ];
    for (const code of forms) await refuses(t, inPure(code), checkPure, 'pure-import');
    if (['fs', 'dns'].includes(spec)) await refuses(t, inPure(`import * as m from 'node:${spec}/promises';\nexport { m };\n`), checkPure, 'pure-import');
  });
}

for (const [why, code] of [
  ['Date.now', 'export const t = Date.now();\n'],
  ['Date.now by element access', "export const t = Date['now']();\n"],
  ['new Date() with no argument', 'export const t = new Date();\n'],
  ['new Date without parentheses', 'export const t = new Date;\n'],
  ['Date() called as a function', 'export const t = Date();\n'],
  ['Math.random', 'export const r = Math.random();\n'],
  ['setTimeout', 'export const x = setTimeout(() => undefined, 1);\n'],
  ['setInterval', 'export const x = setInterval(() => undefined, 1);\n'],
  ['fetch', "export const x = fetch('http://x');\n"],
  ['globalThis.fetch', "export const x = globalThis.fetch('http://x');\n"],
  ['globalThis.setTimeout', 'export const x = globalThis.setTimeout(() => undefined, 1);\n'],
  ['process.env', 'export const x = process.env;\n'],
  ['process.exit', 'export const x = () => process.exit(1);\n'],
  ['process passed as a value', 'export const p = process;\n'],
  ['globalThis.process', 'export const p = globalThis.process;\n'],
  ['randomBytes from node:crypto', "import { randomBytes } from 'node:crypto';\nexport const b = randomBytes(8);\n"],
  ['randomBytes as a member', "import * as c from 'node:crypto';\nexport const b = c.randomBytes(8);\n"],
  ['randomBytes imported under another name', "import { randomBytes as rb } from 'node:crypto';\nexport { rb };\n"],
  ['randomUUID', "import { randomUUID } from 'node:crypto';\nexport const b = randomUUID();\n"],
  ['randomInt', "import { randomInt } from 'node:crypto';\nexport const b = randomInt(5);\n"],
  ['generateKeyPairSync', "import { generateKeyPairSync } from 'node:crypto';\nexport const b = generateKeyPairSync('ec', { namedCurve: 'P-256' });\n"],
  ['generateKeySync', "import * as c from 'node:crypto';\nexport const b = c.generateKeySync('hmac', { length: 256 });\n"],
  ['generateKey', "import * as c from 'node:crypto';\nexport const b = c.generateKey;\n"],
  ['crypto.randomUUID on the global crypto', 'export const b = crypto.randomUUID();\n'],
] as const) {
  test(`KBOX-28 src/pure may not use ${why}`, async (t) => {
    await refuses(t, inPure(code), checkPure, 'pure-global');
  });
}

test('KBOX-28 the pure-core rules bind src/pure only: the same code in src/shell is fine', (t) =>
  accepts(t, inShell("import * as fs from 'node:fs';\nexport const t = Date.now() + Math.random() + process.pid;\nexport const f = [fs, setTimeout, fetch];\n"), checkPure));

test('KBOX-28 src/ports and src/pure import nothing from src/shell or src/platforms (static, type-only, dynamic, re-export, path tricks)', async (t) => {
  await accepts(
    t,
    withChanges({
      'src/ports/more.ts': "import type { Clock } from './clock.ts';\nimport { add } from '../pure/add.ts';\nexport type C = Clock;\nexport const a = add;\n",
      'src/shell/uses.ts': "import { add } from '../pure/add.ts';\nimport { x } from '../platforms/google/index.ts';\nexport const y = [add, x];\n",
    }),
    checkLayers,
  );
  const targets = ['../shell/clock.ts', '../platforms/google/index.ts', '../pure/../shell/clock.ts', './../shell/clock.ts'];
  for (const dir of ['src/ports', 'src/pure']) {
    for (const target of targets) {
      await refuses(t, withChanges({ [`${dir}/bad.ts`]: `import { s } from '${target}';\nexport { s };\n` }), checkLayers, 'layer-import');
      await refuses(t, withChanges({ [`${dir}/bad.ts`]: `import type { s } from '${target}';\nexport type S = typeof s;\n` }), checkLayers, 'layer-import');
      await refuses(t, withChanges({ [`${dir}/bad.ts`]: `export const m = await import('${target}');\n` }), checkLayers, 'layer-import');
      await refuses(t, withChanges({ [`${dir}/bad.ts`]: `export * from '${target}';\n` }), checkLayers, 'layer-import');
    }
  }
  await refuses(t, withChanges({ 'src/pure/deep/bad.ts': "import { s } from '../../shell/clock.ts';\nexport { s };\n" }), checkLayers, 'layer-import');
  await refuses(t, withChanges({ 'src/pure/deep/bad.ts': "import { s } from '../../platforms/a/b.ts';\nexport { s };\n" }), checkLayers, 'layer-import');
});

test('KBOX-28 an import cycle is refused in every import form, and a diamond is not a cycle', async (t) => {
  await accepts(
    t,
    withChanges({
      'src/pure/a.ts': "import { b } from './b.ts';\nimport { c } from './c.ts';\nexport const a = [b, c];\n",
      'src/pure/b.ts': "import { d } from './d.ts';\nexport const b = d;\n",
      'src/pure/c.ts': "import { d } from './d.ts';\nexport const c = d;\n",
      'src/pure/d.ts': 'export const d = 1;\n',
    }),
    checkCycles,
  );
  const cycles: [string, Tree][] = [
    ['two files', { 'src/pure/a.ts': "import { b } from './b.ts';\nexport const a = b;\n", 'src/pure/b.ts': "import { a } from './a.ts';\nexport const b = a;\n" }],
    ['a type-only import', { 'src/pure/a.ts': "import type { B } from './b.ts';\nexport type A = B;\n", 'src/pure/b.ts': "import { a } from './a.ts';\nexport type B = typeof a;\nexport const b = 1;\n" }],
    ['a dynamic import', { 'src/pure/a.ts': "export const a = () => import('./b.ts');\n", 'src/pure/b.ts': "import { a } from './a.ts';\nexport const b = a;\n" }],
    ['a re-export', { 'src/pure/a.ts': "export * from './b.ts';\n", 'src/pure/b.ts': "export { a } from './a.ts';\n" }],
    ['an import type', { 'src/pure/a.ts': "export type A = import('./b.ts').B;\n", 'src/pure/b.ts': "import type { A } from './a.ts';\nexport type B = A;\n" }],
    ['itself', { 'src/pure/a.ts': "import { a as me } from './a.ts';\nexport const a = me;\n" }],
    ['three files across folders', {
      'src/pure/a.ts': "import { b } from '../shell/b.ts';\nexport const a = b;\n",
      'src/shell/b.ts': "import { c } from '../ports/c.ts';\nexport const b = c;\n",
      'src/ports/c.ts': "import { a } from '../pure/a.ts';\nexport const c = a;\n",
    }],
  ];
  for (const [, extra] of cycles) await refuses(t, withChanges(extra), checkCycles, 'import-cycle');
});

test('KBOX-28 every catch rethrows, reports through Audit or Notifier, or returns an error result', async (t) => {
  await accepts(
    t,
    withChanges({
      'src/shell/ok.ts': [
        'declare const audit: { append(e: object): void };',
        'declare const notifier: { notify(e: object): void };',
        'declare function f(): void;',
        'declare function isX(e: unknown): boolean;',
        'export const a = () => { try { f(); } catch (e) { throw e; } };',
        "export const b = () => { try { f(); } catch (e) { throw new Error('wrapped', { cause: e }); } };",
        'export const c = () => { try { f(); return { ok: true }; } catch (e) { return { ok: false, error: e }; } };',
        "export const d = () => { try { f(); } catch (e) { audit.append({ action: 'failed', e }); } };",
        "export const g = () => { try { f(); } catch (e) { notifier.notify({ kind: 'k', e }); } };",
        'export const h = () => { try { f(); } catch (e) { if (isX(e)) { return false; } throw e; } };',
        'declare const p: Promise<number>;',
        'declare const handle: (e: unknown) => void;',
        'export const i = p.catch(handle);',
        'export const j = p.catch((e) => { throw e; });',
        'export const k = p.catch(() => ({ ok: false }));',
        'export const l = p.catch((e) => { audit.append({ e }); });',
        '',
      ].join('\n'),
    }),
    checkCatches,
  );
  const silent = [
    'try { f(); } catch {}',
    'try { f(); } catch (e) {}',
    'try { f(); } catch (e) { /* ignored */ }',
    'try { f(); } catch (e) { console.log(e); }',
    'try { f(); } catch (e) { console.error(e); }',
    'try { f(); } catch (e) { return; }',
    'try { f(); } catch (e) { return undefined; }',
    'try { f(); } catch (e) { return null; }',
    'try { f(); } catch (e) { return void 0; }',
    'try { f(); } catch (e) { setTimeout(() => { throw e; }); }',
    'try { f(); } catch (e) { if (isX(e)) { throw e; } }',
    'try { f(); } catch (e) { other.append(e); }',
    'p.catch(() => {});',
    'p.catch((e) => { console.log(e); });',
    'p.catch(() => undefined);',
    'p.catch(function () {});',
  ];
  for (const body of silent) {
    const code = `declare function f(): void;\ndeclare function isX(e: unknown): boolean;\ndeclare const p: Promise<number>;\ndeclare const other: { append(e: unknown): void };\nexport const x = () => { ${body} };\n`;
    await refuses(t, inShell(code), checkCatches, 'silent-catch');
    await refuses(t, withChanges({ 'test/helper.ts': code }), checkCatches, 'silent-catch');
  }
});

// ---------------------------------------------------------------- KBOX-35

test('KBOX-35 nothing in test/kit reaches src/pure/webauthn, cose or challenge, directly or through another file', async (t) => {
  await accepts(
    t,
    withChanges({
      'test/kit/soft-authenticator.ts': "import { helper } from './helper.ts';\nimport type { Clock } from '../../src/ports/clock.ts';\nimport { add } from '../../src/pure/add.ts';\nexport const s = [helper, add];\nexport type C = Clock;\n",
      'test/kit/helper.ts': 'export const helper = 1;\n',
      'test/kit/kit.test.ts': "import { x } from '../../src/pure/cose.ts';\nexport { x };\n",
    }),
    checkKitIndependence,
  );
  for (const target of ['webauthn', 'cose', 'challenge']) {
    await refuses(t, withChanges({ 'test/kit/soft-authenticator.ts': `import { v } from '../../src/pure/${target}.ts';\nexport { v };\n` }), checkKitIndependence, 'kit-shares-verifier');
    await refuses(t, withChanges({ 'test/kit/soft-authenticator.ts': `export const v = await import('../../src/pure/${target}.ts');\n` }), checkKitIndependence, 'kit-shares-verifier');
    await refuses(
      t,
      withChanges({
        'test/kit/soft-authenticator.ts': "import { h } from './helper.ts';\nexport { h };\n",
        'test/kit/helper.ts': "import { v } from '../support/more.ts';\nexport const h = v;\n",
        'test/support/more.ts': `export { v } from '../../src/pure/${target}.ts';\n`,
      }),
      checkKitIndependence,
      'kit-shares-verifier',
    );
  }
});

// ---------------------------------------------------------------- KBOX-42

const PLATFORM_FILE = 'src/platforms/google/index.ts';
const probeTree = (probe: string | null, list: string | null = '["U1","U2"]'): Tree =>
  withChanges({
    [PLATFORM_FILE]: 'export const google = 1;\n',
    'src/platforms/google/unverified.json': list,
    'docs/probes/google.md': probe,
  });
const GOOD_PROBE = '# google probe\n\n- U1: GET /v1/x on a throwaway project: 200, keys: name. VERIFIED\n- U2: POST /v1/y: 403, keys: error. STILL UNVERIFIED\n';

test('KBOX-42 a platform folder with a complete probe report passes, and a repo with no platforms passes', async (t) => {
  await accepts(t, probeTree(GOOD_PROBE), checkProbes);
  await accepts(t, goodTree(), checkProbes);
  await accepts(t, withChanges({ 'src/platforms/registry.ts': 'export const registry = [];\n' }), checkProbes);
  await accepts(t, probeTree('- U1: x. REFUTED\n- U2: y. VERIFIED\n'), checkProbes);
});

test('KBOX-42 a platform folder with no probe file is refused', async (t) => {
  await refuses(t, probeTree(null), checkProbes, 'probe-missing');
});

test('KBOX-42 a probe file missing one of the platform UNVERIFIED ids, or giving it no status, is refused', async (t) => {
  await refuses(t, probeTree('- U1: x. VERIFIED\n'), checkProbes, 'probe-item-missing');
  await refuses(t, probeTree('- U1: x. VERIFIED\n- U2: no status on this line\n'), checkProbes, 'probe-item-missing');
  await refuses(t, probeTree('- U1: x. VERIFIED\n- U2: still open. UNVERIFIED\n'), checkProbes, 'probe-item-missing');
  await refuses(t, probeTree('- U1: x. VERIFIED\n- U10: wrong id. VERIFIED\n'), checkProbes, 'probe-item-missing');
  await refuses(t, probeTree('- U1: x. VERIFIED\n- XU2: wrong id. VERIFIED\n'), checkProbes, 'probe-item-missing');
  const found = await judge(t, probeTree('- U1: x. VERIFIED\n'), checkProbes);
  assert.ok(found.some((v) => v.detail.includes('U2')));
});

test('KBOX-42 a platform without a readable unverified.json list of ids is refused', async (t) => {
  await refuses(t, probeTree(GOOD_PROBE, null), checkProbes, 'unverified-list');
  await refuses(t, probeTree(GOOD_PROBE, '{ nope'), checkProbes, 'unverified-list');
  await refuses(t, probeTree(GOOD_PROBE, '{"U1":1}'), checkProbes, 'unverified-list');
  await refuses(t, probeTree(GOOD_PROBE, '["U1", 2]'), checkProbes, 'unverified-list');
  await refuses(t, probeTree(GOOD_PROBE, '["U1", ""]'), checkProbes, 'unverified-list');
});

test('KBOX-42 only the failing platform is named when one of two is complete', async (t) => {
  const tree = withChanges({
    ...probeTree(GOOD_PROBE),
    'src/platforms/vercel/index.ts': 'export const vercel = 1;\n',
    'src/platforms/vercel/unverified.json': '["V1"]',
  });
  const found = await judge(t, tree, checkProbes);
  assert.deepEqual(codes(found), ['probe-missing']);
  assert.match(found[0]?.file ?? '', /vercel/);
});

// ---------------------------------------------------------------- the repo's own tree

test('KBOX-27 the walker sees the repo (a check that sees no files proves nothing)', async () => {
  const files = await walk(REPO_ROOT);
  for (const expected of ['package.json', 'tsconfig.json', 'src/ports/clock.ts', 'test/kit/index.ts', 'test/arch.test.ts']) {
    assert.ok(files.includes(expected), `${expected} not seen`);
  }
  assert.equal(files.some((f) => f.startsWith('node_modules/')), false);
});

const REPO_CHECKS: [string, string, Check][] = [
  ['KBOX-27', 'toolchain', checkToolchain],
  ['KBOX-27', 'import specifiers', checkSourceImports],
  ['KBOX-27', 'erasable syntax', checkErasable],
  ['KBOX-27', 'zero counts', checkZeroCounts],
  ['KBOX-28', 'pure core', checkPure],
  ['KBOX-28', 'layers', checkLayers],
  ['KBOX-28', 'import cycles', checkCycles],
  ['KBOX-28', 'catches', checkCatches],
  ['KBOX-35', 'kit independence', checkKitIndependence],
  ['KBOX-42', 'probe reports', checkProbes],
  ['KBOX-27', 'tsc --noEmit', checkTypecheck],
];

for (const [rule, name, check] of REPO_CHECKS) {
  test(`${rule} the repo's own tree passes the ${name} check`, async () => {
    assert.deepEqual(await check(REPO_ROOT), []);
  });
}

// ---------------------------------------------------------------- KBOX-6 (kb-install loads every module before its first step)

test('KBOX-6 a dynamic import() or require() in src/cli is refused', async (t) => {
  await refuses(t, withChanges({ 'src/cli/x.ts': "export const later = (): Promise<unknown> => import('./y.ts');\n", 'src/cli/y.ts': 'export const y = 1;\n' }), checkStaticCli, 'cli-dynamic-import');
  await refuses(t, withChanges({ 'src/cli/x.ts': "declare const require: (s: string) => unknown;\nexport const y = require('./y.ts');\n" }), checkStaticCli, 'cli-dynamic-import');
});

test('KBOX-6 a dynamic import() in a module a src/cli file reaches, two imports away, is refused; one in a module it does not reach is not', async (t) => {
  await refuses(
    t,
    withChanges({ 'src/cli/x.ts': "import { a } from '../shell/a.ts';\nexport const x = a;\n", 'src/shell/a.ts': "import { b } from './b.ts';\nexport const a = b;\n", 'src/shell/b.ts': "export const b = 1;\nexport const later = (): Promise<unknown> => import('./a.ts');\n" }),
    checkStaticCli,
    'cli-dynamic-import',
  );
  await accepts(t, withChanges({ 'src/cli/x.ts': 'export const x = 1;\n', 'src/shell/b.ts': "export const later = (): Promise<unknown> => import('./c.ts');\n", 'src/shell/c.ts': 'export const c = 1;\n' }), checkStaticCli);
});

test('KBOX-6 the repo\'s own src/cli loads only static imports', async () => {
  assert.deepEqual(await checkStaticCli(REPO_ROOT), []);
});
