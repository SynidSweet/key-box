// A small tree that passes every check, for a test to break in exactly one way.
import { mkdir, symlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { TestContext } from 'node:test';
import { tempDir } from '../kit/index.ts';

export type Tree = Record<string, string>;

export const REPO_ROOT = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');

export const GOOD_TSCONFIG = {
  compilerOptions: {
    target: 'es2023',
    module: 'nodenext',
    moduleResolution: 'nodenext',
    lib: ['es2023'],
    types: ['node'],
    strict: true,
    noUncheckedIndexedAccess: true,
    exactOptionalPropertyTypes: true,
    noImplicitOverride: true,
    noPropertyAccessFromIndexSignature: true,
    noFallthroughCasesInSwitch: true,
    verbatimModuleSyntax: true,
    erasableSyntaxOnly: true,
    allowImportingTsExtensions: true,
    noEmit: true,
    checkJs: true,
    allowJs: true,
    skipLibCheck: true,
  },
  include: ['src', 'test'],
};

export const GOOD_PACKAGE = {
  name: 'fixture',
  private: true,
  type: 'module',
  devDependencies: { '@types/node': '24.1.0', typescript: '6.0.3' },
};

export function goodTree(): Tree {
  return {
    'package.json': JSON.stringify(GOOD_PACKAGE),
    '.nvmrc': '24\n',
    '.gitignore': 'node_modules/\n',
    'package-lock.json': '{}',
    'tsconfig.json': JSON.stringify(GOOD_TSCONFIG),
    'src/ports/clock.ts': 'export interface Clock {\n  now(): number;\n}\n',
    'src/pure/add.ts': "import type { Clock } from '../ports/clock.ts';\n\nexport const add = (a: number, b: number): number => a + b;\nexport const stamp = (clock: Clock): number => clock.now();\n",
    'src/shell/clock.ts': "import type { Clock } from '../ports/clock.ts';\n\nexport const systemClock: Clock = { now: () => Date.now() };\n",
  };
}

/** The good tree with changes: a string sets a file, null removes it. */
export function withChanges(changes: Record<string, string | null>): Tree {
  const tree = goodTree();
  for (const [path, content] of Object.entries(changes)) {
    if (content === null) delete tree[path];
    else tree[path] = content;
  }
  return tree;
}

export function withPackage(patch: Record<string, unknown>): Tree {
  return withChanges({ 'package.json': JSON.stringify({ ...GOOD_PACKAGE, ...patch }) });
}

export function withTsconfig(options: Record<string, unknown>, rest: Record<string, unknown> = {}): Tree {
  return withChanges({ 'tsconfig.json': JSON.stringify({ ...GOOD_TSCONFIG, compilerOptions: { ...GOOD_TSCONFIG.compilerOptions, ...options }, ...rest }) });
}

/** Writes the tree under a temp directory and returns the directory. */
export async function materialise(t: TestContext, tree: Tree, options: { withNodeModules?: boolean } = {}): Promise<string> {
  const root = await tempDir(t);
  for (const [path, content] of Object.entries(tree)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
  if (options.withNodeModules === true) await symlink(join(REPO_ROOT, 'node_modules'), join(root, 'node_modules'));
  return root;
}
