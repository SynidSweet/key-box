// H of an extracted release tree by src/pure/release-hash.ts: prints the hash and the file count.  node release-hash-tree.ts <dir>
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileSha256, releaseHash } from '../src/pure/release-hash.ts';
import type { HashedFile } from '../src/pure/release-hash.ts';

const root = process.argv[2];
if (root === undefined) {
  console.error('usage: release-hash-tree.ts <dir>');
  process.exit(2);
}
const files: HashedFile[] = [];
function walk(rel: string): void {
  for (const name of readdirSync(join(root as string, rel))) {
    const path = rel === '' ? name : `${rel}/${name}`;
    const st = lstatSync(join(root as string, path));
    if (st.isDirectory()) walk(path);
    else if (st.isFile()) files.push({ path, executable: (st.mode & 0o100) !== 0, sha256: fileSha256(readFileSync(join(root as string, path))) });
    else throw new Error('a release tree holds only files and directories');
  }
}
walk('');
console.log(`${releaseHash(files)} ${files.length}`);
