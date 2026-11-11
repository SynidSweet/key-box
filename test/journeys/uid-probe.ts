// Run as another user in the process-split journey: tries one thing and prints what the operating system said, as JSON.
// Run with no arguments (as `node --test` does to every file under test/) it does nothing.
import { closeSync, openSync, readdirSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';

const [action, target] = process.argv.slice(2);

const code = (error: unknown): string => (typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string' ? error.code : 'UNKNOWN');

/** Runs one attempt and returns what the operating system said; a failure is the result, not an exception. */
function attempt(work: () => Record<string, unknown>): Record<string, unknown> {
  try {
    return work();
  } catch (error) {
    return { ok: false, code: code(error) };
  }
}
const say = (result: Record<string, unknown>): void => void process.stdout.write(`${JSON.stringify(result)}\n`);

if (action === 'connect' && target !== undefined) {
  const socket = connect(target);
  socket.once('data', (data: Buffer) => {
    say({ ok: true, said: data.toString('utf8') });
    socket.destroy();
  });
  socket.once('error', (error) => say({ ok: false, code: code(error) }));
} else if (action === 'list' && target !== undefined) {
  say(attempt(() => ({ ok: true, entries: readdirSync(target) })));
} else if (action === 'open' && target !== undefined) {
  say(attempt(() => (closeSync(openSync(target, 'r')), { ok: true })));
} else if (action === 'write' && target !== undefined) {
  say(attempt(() => (closeSync(openSync(join(target, 'probe-file'), 'wx')), { ok: true })));
}
