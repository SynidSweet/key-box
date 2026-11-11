// The demo of the phone pages (test/support/demo-pages.ts) as a developer starts it: a real process that prints one address per page, answers each
// with HTML over its TLS certificate, and on SIGTERM exits cleanly and removes its temp directory. A demo that cannot start, serves a page that is
// not HTML, or leaves its directory behind is what this test catches. The child runs outside the test runner's context so the demo starts.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { request } from 'node:https';
import { test } from 'node:test';
import { startNode, tempDir } from './kit/index.ts';

const DEMO = new URL('./support/demo-pages.ts', import.meta.url).pathname;

const get = (port: number, url: string, ca: string): Promise<{ readonly status: number; readonly type: string; readonly body: string }> =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const call = request({ host: '127.0.0.1', port, servername: target.hostname, path: target.pathname + target.search, headers: { host: target.hostname }, ca }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode ?? 0, type: String(res.headers['content-type']), body: Buffer.concat(chunks).toString('utf8') }));
    });
    call.on('error', reject);
    call.end();
  });

test('KBOX-8 KBOX-12 KBOX-49 the demo prints an address for the setup, recovery, app and paste pages, each answers 200 with HTML, and SIGTERM ends it with its temp directory gone', async (t) => {
  const parent = await tempDir(t);
  const demo = startNode(t, [DEMO, '--port', '0', '--dir', parent], parent, { NODE_TEST_CONTEXT: '' });
  await demo.ready('\nready\n');
  const lines = demo.stdout().split('\n');
  const served = /^demo serving on 127\.0\.0\.1:(\d+) \(TLS, certificate (.+)\)$/.exec(lines[0] ?? '');
  assert.ok(served, `the first line names the port and certificate: ${lines[0]}`);
  const port = Number(served[1]);
  const ca = readFileSync(served[2] ?? '', 'utf8');
  const pages = lines.filter((l) => l.startsWith('page\t')).map((l) => l.split('\t'));
  assert.deepEqual(
    pages.map((p) => new URL(p[2] ?? '').pathname),
    ['/setup', '/recover', '/', '/paste.html'],
  );
  assert.match(lines.find((l) => l.startsWith('setup code: ')) ?? '', /^setup code: ([a-z]+ ){11}[a-z]+$/);
  for (const [, name, url] of pages) {
    const answer = await get(port, url ?? '', ca);
    assert.equal(answer.status, 200, `${name}: ${answer.body}`);
    assert.match(answer.type, /^text\/html/, name);
    assert.match(answer.body, /<!doctype html>/i, name);
  }
  assert.equal(readdirSync(parent).length, 1, 'the demo keeps its state in one directory under the one it was given');
  const exit = await demo.stop();
  assert.equal(exit.status, 0, exit.stderr);
  assert.deepEqual(readdirSync(parent), [], 'the demo removed its temp directory');
});
