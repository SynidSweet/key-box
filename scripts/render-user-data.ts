// Renders the setup file a release publishes: deploy/cloud-init.yaml AT a commit, with the five value lines filled in.
//   node scripts/render-user-data.ts <commit> [--out user-data] KB_REPO=<owner/name> KB_DOMAIN=<name> KB_COMMIT=<40 hex> KB_RELEASE=<64 hex> KB_TIME_FLOOR=<seconds>
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { renderUserData } from '../src/pure/release-userdata.ts';

const args = process.argv.slice(2);
const outAt = args.indexOf('--out');
const out = outAt >= 0 ? args.splice(outAt, 2)[1] : 'user-data';
// `--template <file>` reads the template from a file instead of a commit (a checkout with no history, as a queued job has).
const templateAt = args.indexOf('--template');
const templateFile = templateAt >= 0 ? args.splice(templateAt, 2)[1] : undefined;
const [commit, ...pairs] = templateFile === undefined ? args : ['', ...args];
if (commit === undefined || out === undefined || (templateFile === undefined && !/^[0-9a-f]{40}$/.test(commit))) {
  console.error('usage: render-user-data.ts <40-hex commit | --template <file>> [--out <file>] KB_REPO=.. KB_DOMAIN=.. KB_COMMIT=.. KB_RELEASE=.. KB_TIME_FLOOR=..');
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
function readTemplate(): string {
  if (templateFile !== undefined) return readFileSync(templateFile, 'utf8');
  try {
    return execFileSync('git', ['show', `${commit}:deploy/cloud-init.yaml`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  } catch {
    console.error(`render-user-data: git could not show deploy/cloud-init.yaml at ${commit}`);
    process.exit(1);
  }
}
const template = readTemplate();
const rendered = renderUserData(template, values);
if (!rendered.ok) {
  console.error(`render-user-data: refused (${rendered.error})`);
  process.exit(1);
}
writeFileSync(out, rendered.text);
console.log(`wrote ${out}`);
