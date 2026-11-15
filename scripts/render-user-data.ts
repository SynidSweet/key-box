// Renders the setup file a release publishes: deploy/cloud-init.yaml AT a commit, with the five value lines filled in.
//   node scripts/render-user-data.ts <commit> [--out user-data] KB_REPO=<owner/name> KB_DOMAIN=<name> KB_COMMIT=<40 hex> KB_RELEASE=<64 hex> KB_TIME_FLOOR=<seconds>
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { renderUserData } from '../src/pure/release-userdata.ts';

const args = process.argv.slice(2);
const outAt = args.indexOf('--out');
const out = outAt >= 0 ? args.splice(outAt, 2)[1] : 'user-data';
const [commit, ...pairs] = args;
if (commit === undefined || out === undefined || !/^[0-9a-f]{40}$/.test(commit)) {
  console.error('usage: render-user-data.ts <40-hex commit> [--out <file>] KB_REPO=.. KB_DOMAIN=.. KB_COMMIT=.. KB_RELEASE=.. KB_TIME_FLOOR=..');
  process.exit(2);
}
const values: Record<string, string> = {};
for (const pair of pairs) {
  const eq = pair.indexOf('=');
  if (eq < 1) {
    console.error('render-user-data: every value is KEY=value');
    process.exit(2);
  }
  values[pair.slice(0, eq)] = pair.slice(eq + 1);
}
const template = execFileSync('git', ['show', `${commit}:deploy/cloud-init.yaml`], { encoding: 'utf8' });
const rendered = renderUserData(template, values);
if (!rendered.ok) {
  console.error(`render-user-data: refused (${rendered.error})`);
  process.exit(1);
}
writeFileSync(out, rendered.text);
console.log(`wrote ${out}`);
