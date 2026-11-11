// KBOX-27: the toolchain table holds.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { readTextIfPresent, walk } from './tree.ts';

const REQUIRED_DEV_DEPENDENCIES = ['@types/node', 'typescript'];
const EXACT_VERSION = /^\d+\.\d+\.\d+$/;
const REQUIRED_TRUE_OPTIONS = [
  'strict',
  'noUncheckedIndexedAccess',
  'exactOptionalPropertyTypes',
  'noImplicitOverride',
  'noPropertyAccessFromIndexSignature',
  'noFallthroughCasesInSwitch',
  'verbatimModuleSyntax',
  'erasableSyntaxOnly',
  'allowImportingTsExtensions',
  'noEmit',
  'checkJs',
];

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : undefined;

type Read<T> = { readonly value: T } | { readonly problem: string };

async function readPackage(root: string): Promise<Read<Record<string, unknown>>> {
  const text = await readTextIfPresent(root, 'package.json');
  if (text === undefined) return { problem: 'package.json is missing' };
  try {
    const record = asRecord(JSON.parse(text));
    return record === undefined ? { problem: 'package.json is not an object' } : { value: record };
  } catch (error) {
    return { problem: `package.json is not JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
}

async function readTsconfig(root: string): Promise<Read<Record<string, unknown>>> {
  const text = await readTextIfPresent(root, 'tsconfig.json');
  if (text === undefined) return { problem: 'tsconfig.json is missing' };
  const parsed = ts.parseConfigFileTextToJson('tsconfig.json', text);
  const record = asRecord(parsed.config);
  if (parsed.error !== undefined || record === undefined) return { problem: 'tsconfig.json does not parse' };
  return { value: record };
}

const majorOf = (version: string, pattern: RegExp): number | undefined => {
  const match = pattern.exec(version.trim());
  return match?.[1] === undefined ? undefined : Number(match[1]);
};

const isIncluded = (include: unknown, folder: string): boolean =>
  Array.isArray(include) &&
  include.some((entry) => typeof entry === 'string' && entry.replace(/^\.\//, '').replace(/(\/\*\*)?(\/\*)?$/, '').replace(/\/$/, '') === folder);

function packageViolations(pkg: Record<string, unknown>, nvmrc: string | undefined): Violation[] {
  const found: Violation[] = [];
  const at = (code: Violation['code'], detail: string): void => void found.push({ code, file: 'package.json', detail });
  if ('dependencies' in pkg) at('dependencies-key', 'package.json has a dependencies key');
  const dev = asRecord(pkg['devDependencies']) ?? {};
  if (Object.keys(dev).sort().join(',') !== REQUIRED_DEV_DEPENDENCIES.join(',')) {
    at('dev-dependency-set', `devDependencies are ${JSON.stringify(Object.keys(dev).sort())}, must be exactly ${JSON.stringify(REQUIRED_DEV_DEPENDENCIES)}`);
  }
  for (const [name, version] of Object.entries(dev)) {
    if (typeof version !== 'string' || !EXACT_VERSION.test(version)) at('dev-dependency-range', `${name} is "${String(version)}", not an exact version`);
  }
  const typesVersion = dev['@types/node'];
  const typesMajor = typeof typesVersion === 'string' ? majorOf(typesVersion, /^(\d+)\./) : undefined;
  const nvmrcMajor = nvmrc === undefined ? undefined : majorOf(nvmrc, /^v?(\d+)(?:\.|$)/);
  if (typesMajor === undefined || nvmrcMajor === undefined || typesMajor !== nvmrcMajor) {
    at('types-node-major', `@types/node major is ${typesMajor ?? 'unreadable'} and .nvmrc major is ${nvmrcMajor ?? 'unreadable'}`);
  }
  return found;
}

function tsconfigViolations(config: Record<string, unknown>): Violation[] {
  const found: Violation[] = [];
  const at = (code: Violation['code'], detail: string): void => void found.push({ code, file: 'tsconfig.json', detail });
  const options = asRecord(config['compilerOptions']) ?? {};
  if (JSON.stringify(options['types']) !== JSON.stringify(['node'])) at('tsconfig-types', `types is ${JSON.stringify(options['types'])}, must be ["node"]`);
  for (const name of REQUIRED_TRUE_OPTIONS) if (options[name] !== true) at('tsconfig-option', `${name} must be true`);
  for (const folder of ['src', 'test']) if (!isIncluded(config['include'], folder)) at('tsconfig-include', `include must cover ${folder}`);
  return found;
}

export interface ToolchainOptions {
  /** The files git tracks, when the root is a repository. */
  readonly trackedFiles?: readonly string[];
}

export async function checkToolchain(root: string, options: ToolchainOptions = {}): Promise<Violation[]> {
  const found: Violation[] = [];
  const pkg = await readPackage(root);
  if ('problem' in pkg) found.push({ code: 'unreadable', file: 'package.json', detail: pkg.problem });
  else found.push(...packageViolations(pkg.value, await readTextIfPresent(root, '.nvmrc')));

  const config = await readTsconfig(root);
  if ('problem' in config) found.push({ code: 'unreadable', file: 'tsconfig.json', detail: config.problem });
  else found.push(...tsconfigViolations(config.value));

  for (const file of (await walk(root)).filter((f) => f.endsWith('.d.ts'))) {
    if (/declare\s+module\s+['"]node:/.test((await readTextIfPresent(root, file)) ?? '')) {
      found.push({ code: 'node-module-stub', file, detail: 'declares a node: module; @types/node provides them' });
    }
  }
  if ((await readTextIfPresent(root, 'package-lock.json')) === undefined) found.push({ code: 'lockfile-missing', file: 'package-lock.json', detail: 'not committed' });
  const ignore = (await readTextIfPresent(root, '.gitignore')) ?? '';
  if (!ignore.split('\n').some((line) => /^\/?node_modules\/?$/.test(line.trim()))) {
    found.push({ code: 'node-modules-not-ignored', file: '.gitignore', detail: 'node_modules is not ignored' });
  }
  for (const file of options.trackedFiles ?? []) {
    if (file.split('/').includes('node_modules')) found.push({ code: 'node-modules-tracked', file, detail: 'tracked file under node_modules' });
  }
  return found;
}
