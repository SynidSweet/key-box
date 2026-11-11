// The egress gate's test connector, shared by the in-process relay world and the relay journey's entry script.
import { connect } from 'node:net';
import type { Connector } from '../../src/shell/egress.ts';

/**
 * The egress gate's test connector: every connect the gate allows goes to the loopback upstream on `port` instead of the
 * resolved public address, in plain TCP; a host in `hung` never connects.
 */
export function loopbackConnector(port: number, hung: ReadonlySet<string> = new Set()): Connector {
  return {
    connect: (target, signal) =>
      new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('connect aborted')), { once: true });
        if (hung.has(target.servername)) return;
        const socket = connect(port, '127.0.0.1');
        socket.once('connect', () => resolve(socket));
        socket.once('error', reject);
      }),
  };
}
