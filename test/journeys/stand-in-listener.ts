// A stand-in for core or relay in the process-split journey: listens on a unix socket and answers every connection with `hello`.
// With `core` it also makes the lend socket, which exists only once core is running. Run with no arguments (as `node --test`
// does to every file under test/) it does nothing.
import { rmSync } from 'node:fs';
import { createServer } from 'node:net';

const [role, socketPath, lendPath] = process.argv.slice(2);

if ((role === 'core' || role === 'relay') && socketPath !== undefined) {
  // The units set UMask=0007, so a socket gives its group everything and others nothing.
  process.umask(0o007);
  const listen = (path: string): Promise<void> =>
    new Promise((resolve, reject) => {
      const server = createServer((connection) => connection.end('hello'));
      rmSync(path, { force: true });
      server.once('error', reject);
      server.listen(path, resolve);
    });
  await listen(socketPath);
  if (role === 'core' && lendPath !== undefined) await listen(lendPath);
  process.stdout.write('listening\n');
  setInterval(() => undefined, 1 << 30);
}
