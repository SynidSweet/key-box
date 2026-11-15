/**
 * KBOX-44 (revision 5): Caddy serves two sites on the box's one Tailscale name, with certificates from the local tailscaled.
 * The deploy files are the product's configuration, so these tests read their text.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = (path: string): string => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const stripComments = (text: string): string => text.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
const caddy = stripComments(read('deploy/Caddyfile'));

/** The top-level blocks: header line (the part before ` {`) and the body up to the line holding only `}`. */
const blocks = (text: string): { head: string; body: string }[] =>
  [...text.matchAll(/^(\S[^\n]*?)\s*\{\n([\s\S]*?)^\}$/gm)].map((m) => ({ head: m[1] ?? '', body: m[2] ?? '' }));
const all = blocks(caddy);
const sites = all.filter((b) => b.head !== '');
const globalBlock = (): string => /^\{\n([\s\S]*?)^\}$/m.exec(caddy)?.[1] ?? '';
const site = (head: string): string => sites.find((s) => s.head === head)?.body ?? assert.fail(`no site ${head}`);

test('KBOX-44 the Caddyfile serves exactly two sites, {$KB_DOMAIN}:8443 and {$KB_DOMAIN}:443', () => {
  assert.deepEqual(sites.map((s) => s.head).sort(), ['{$KB_DOMAIN}:443', '{$KB_DOMAIN}:8443']);
});

test('KBOX-44 each site takes its certificate from the local tailscaled, with no ACME and no port 80', () => {
  for (const s of sites) assert.match(s.body, /tls\s*\{\s*get_certificate tailscale\s*\}/, s.head);
  assert.doesNotMatch(caddy, /acme|disable_http_challenge/);
  assert.doesNotMatch(caddy, /:80\b|http:\/\//);
  assert.match(globalBlock(), /auto_https disable_redirects/);
});

test('KBOX-44 the global block turns the admin endpoint off and offers h1 and h2 only', () => {
  const g = globalBlock();
  assert.match(g, /^\s*admin off\s*$/m);
  assert.match(g, /servers\s*\{\s*protocols h1 h2\s*\}/);
});

test('KBOX-44 the 8443 site proxies to core only', () => {
  const body = site('{$KB_DOMAIN}:8443');
  assert.deepEqual([...body.matchAll(/reverse_proxy (\S+)/g)].map((m) => m[1]), ['unix//run/keybox/http.sock']);
  assert.doesNotMatch(body, /keyrelay/);
});

test('KBOX-44 the 443 site sends /api/* to core, /r/* to the relay, 404 otherwise, and strips Set-Cookie', () => {
  const body = site('{$KB_DOMAIN}:443');
  const handle = (matcher: string): string => new RegExp(`handle ${matcher} \\{([\\s\\S]*?)\\n\\t\\}`).exec(body)?.[1] ?? assert.fail(matcher);
  assert.match(handle('/api/\\*'), /reverse_proxy unix\/\/run\/keybox\/http\.sock/);
  assert.match(handle('/r/\\*'), /reverse_proxy unix\/\/run\/keyrelay\/http\.sock/);
  assert.match(body, /handle \{\s*respond 404\s*\}/);
  assert.match(body, /^\s*header -Set-Cookie\s*$/m);
});

test('KBOX-44 caddy.service starts after and wants tailscaled, and tailscaled lets the caddy user fetch certificates', () => {
  const unit = read('deploy/caddy.service');
  assert.match(unit, /^After=.*\btailscaled\.service\b/m);
  assert.match(unit, /^Wants=.*\btailscaled\.service\b/m);
  assert.match(read('deploy/tailscaled.defaults'), /^TS_PERMIT_CERT_UID=caddy$/m);
});
