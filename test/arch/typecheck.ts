// KBOX-27: tsc --noEmit is clean under the strict options of the toolchain table.
import { fileURLToPath } from 'node:url';
import { runNode } from '../kit/index.ts';
import type { Violation } from './violation.ts';

const TSC = fileURLToPath(new URL('../../node_modules/typescript/bin/tsc', import.meta.url));

export async function checkTypecheck(root: string): Promise<Violation[]> {
  const run = runNode([TSC, '--noEmit', '-p', 'tsconfig.json'], root);
  if (run.status === 0) return [];
  const detail = `tsc exited ${run.status}: ${run.stdout.split('\n').slice(0, 12).join(' | ')}`;
  return [{ code: 'typecheck', file: 'tsconfig.json', detail }];
}
