// KBOX-3, KBOX-45: the lend socket's transport, both ends. Core listens on /run/keybox-lend/lend.sock (mode 0660, group
// keyrelay: the operating system is the access check); kb-relay connects once per operation. A frame is a 4-byte big-endian
// length, a kind byte and the body. Core answers one request per connection and closes it, so an answer is one-shot.
import { chmodSync, rmSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import type { Socket } from 'node:net';
import type { Lent } from '../ports/types.ts';
import { makeLent } from '../pure/lent.ts';
import { FRAME_BYTES, FRAME_END, FRAME_JSON, FRAME_MAX, parseAccepted, parseGrantsAnswer, parseLendRequest, parseResolveAnswer, parseScanStep, refusalMessage } from '../pure/lend-protocol.ts';
import type { GrantsAnswer, LendRefusal, LendRequest, RelayAuditRow, ResolveAnswer } from '../pure/lend-protocol.ts';
import type { Parsed } from '../pure/schemas.ts';
import type { ScanStep } from '../pure/scanner.ts';

export interface Frame {
  readonly kind: number;
  readonly body: Uint8Array;
}

export function encodeFrame(kind: number, body: Uint8Array): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(body.length + 1, 0);
  header[4] = kind;
  return Buffer.concat([header, body]);
}

const jsonFrame = (message: unknown): Buffer => encodeFrame(FRAME_JSON, Buffer.from(JSON.stringify(message), 'utf8'));

/** Splits a byte stream into frames. A frame over FRAME_MAX sets `refused`, and nothing after it is ever decoded. */
export class FrameDecoder {
  #buffer: Buffer = Buffer.alloc(0);
  refused = false;

  push(chunk: Uint8Array): Frame[] {
    if (this.refused) return [];
    this.#buffer = this.#buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.#buffer, chunk]);
    const frames: Frame[] = [];
    while (this.#buffer.length >= 4) {
      const length = this.#buffer.readUInt32BE(0);
      if (length < 1 || length > FRAME_MAX + 1) {
        this.refused = true;
        this.#buffer = Buffer.alloc(0);
        return frames;
      }
      if (this.#buffer.length < 4 + length) break;
      frames.push({ kind: this.#buffer[4] ?? 0, body: Uint8Array.from(this.#buffer.subarray(5, 4 + length)) });
      this.#buffer = this.#buffer.subarray(4 + length);
    }
    return frames;
  }
}

function decodeJson(frame: Frame | undefined): Parsed<unknown> {
  if (frame?.kind !== FRAME_JSON) return { ok: false };
  try {
    return { ok: true, value: JSON.parse(Buffer.from(frame.body).toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

// ---------------------------------------------------------------- core's end

export interface LendSession {
  readonly request: LendRequest;
  reply(message: Record<string, unknown>): void;
  replyBytes(bytes: Uint8Array): void;
  /** The frames the relay sends after its request (a scan session's data); ends when the relay closes. */
  next(): Promise<Frame | undefined>;
}

export interface LendHandler {
  handle(session: LendSession): Promise<void>;
}

export interface LendServer {
  listen(socketPath: string): Promise<void>;
  /** Stops taking connections and drops the open ones. */
  stop(): Promise<void>;
}

export function createLendServer(handler: LendHandler, journal: (code: string) => void = () => undefined): LendServer {
  const open = new Set<Socket>();

  const serve = (socket: Socket): void => {
    open.add(socket);
    const decoder = new FrameDecoder();
    const queue: Frame[] = [];
    const waiting: ((f: Frame | undefined) => void)[] = [];
    let ended = false;
    let started = false;
    const finish = (): void => {
      ended = true;
      for (const wake of waiting.splice(0)) wake(undefined);
    };
    const close = (): void => {
      finish();
      socket.end();
    };
    const start = (first: Frame): void => {
      started = true;
      const raw = decodeJson(first);
      const parsed = raw.ok ? parseLendRequest(raw.value) : { ok: false as const };
      if (!parsed.ok) {
        socket.write(jsonFrame(refusalMessage('bad_request')));
        close();
        return;
      }
      const session: LendSession = {
        request: parsed.value,
        reply: (message) => void socket.write(jsonFrame(message)),
        replyBytes: (bytes) => void socket.write(encodeFrame(FRAME_BYTES, bytes)),
        next: () => (queue.length > 0 ? Promise.resolve(queue.shift()) : ended ? Promise.resolve(undefined) : new Promise((resolve) => waiting.push(resolve))),
      };
      void handler
        .handle(session)
        .then(
          () => 'done',
          () => 'failed',
        )
        .then((outcome) => {
          if (outcome === 'failed') journal('lend_handler_failed');
          close();
        });
    };
    socket.on('data', (chunk: Buffer) => {
      const frames = decoder.push(chunk);
      if (decoder.refused) {
        journal('lend_frame_refused');
        finish();
        socket.destroy();
        return;
      }
      for (const frame of frames) {
        if (!started) start(frame);
        else if (!ended) {
          const wake = waiting.shift();
          if (wake === undefined) queue.push(frame);
          else wake(frame);
        }
      }
    });
    socket.on('error', () => {
      journal('lend_connection_error');
      socket.destroy();
    });
    socket.on('close', () => {
      open.delete(socket);
      finish();
    });
  };

  const server = createServer(serve);
  return {
    async listen(socketPath) {
      rmSync(socketPath, { force: true });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, () => {
          server.off('error', reject);
          resolve();
        });
      });
      // Group read and write, nothing for others, whatever the umask: the directory's group is the access check (KBOX-45).
      chmodSync(socketPath, 0o660);
    },
    async stop() {
      for (const socket of open) socket.destroy();
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => server.close((error) => (error === undefined ? resolve() : reject(error))));
    },
  };
}

// ---------------------------------------------------------------- the relay's end

/** Core could not be reached or answered something unreadable: the relay answers 503 `unavailable`. */
export class LendUnavailable extends Error {
  constructor(options?: ErrorOptions) {
    super('the lend socket is not available', options);
    this.name = 'LendUnavailable';
  }
}

/** One connection: frames in arrival order; a failure or close rejects the waiting read with LendUnavailable. */
function openConnection(socketPath: string): Promise<{ readonly send: (frame: Buffer) => void; readonly read: () => Promise<Frame>; readonly close: () => void }> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const decoder = new FrameDecoder();
    const frames: Frame[] = [];
    const waiting: { resolve: (f: Frame) => void; reject: (e: Error) => void }[] = [];
    let failure: Error | undefined;
    const fail = (error: Error): void => {
      failure ??= error;
      for (const w of waiting.splice(0)) w.reject(failure);
    };
    socket.once('connect', () =>
      resolve({
        send: (frame) => void socket.write(frame),
        read: () => {
          const frame = frames.shift();
          if (frame !== undefined) return Promise.resolve(frame);
          if (failure !== undefined) return Promise.reject(failure);
          return new Promise((res, rej) => waiting.push({ resolve: res, reject: rej }));
        },
        close: () => socket.destroy(),
      }),
    );
    socket.on('data', (chunk: Buffer) => {
      const got = decoder.push(chunk);
      if (decoder.refused) {
        fail(new LendUnavailable());
        socket.destroy();
        return;
      }
      for (const frame of got) {
        const w = waiting.shift();
        if (w === undefined) frames.push(frame);
        else w.resolve(frame);
      }
    });
    socket.on('error', (cause) => {
      const error = new LendUnavailable({ cause });
      fail(error);
      reject(error);
    });
    socket.on('close', () => fail(new LendUnavailable()));
  });
}

export type LendAnswer = { readonly ok: true; readonly value: Lent } | { readonly ok: false; readonly code: LendRefusal };

export interface ScanSession {
  feed(chunk: Uint8Array): Promise<ScanStep>;
  end(): Promise<ScanStep>;
  close(): void;
}

export type ScanOpen = { readonly ok: true; readonly session: ScanSession } | { readonly ok: false; readonly code: LendRefusal };

export interface LendClient {
  resolve(request: Extract<LendRequest, { op: 'resolve' }>): Promise<ResolveAnswer>;
  grants(request: Extract<LendRequest, { op: 'grants' }>): Promise<GrantsAnswer>;
  /** The value for this one call: the Lent can be used once, and its bytes are wiped when that use ends. */
  lend(request: Extract<LendRequest, { op: 'lend' }>): Promise<LendAnswer>;
  scan(request: Extract<LendRequest, { op: 'scan' }>): Promise<ScanOpen>;
  audit(row: RelayAuditRow): Promise<void>;
}

const answerOf = <T>(parse: (raw: unknown) => Parsed<T>, frame: Frame): T => {
  const raw = decodeJson(frame);
  const parsed = raw.ok ? parse(raw.value) : { ok: false as const };
  if (!parsed.ok) throw new LendUnavailable();
  return parsed.value;
};

const refusalOf = (frame: Frame): { readonly ok: false; readonly code: LendRefusal } => {
  const answer = answerOf(parseResolveAnswer, frame);
  if (answer.ok) throw new LendUnavailable();
  return answer;
};

export function createLendClient(socketPath: string): LendClient {
  /** One request, one answer frame, then the connection is closed. */
  const exchange = async (request: LendRequest): Promise<Frame> => {
    const conn = await openConnection(socketPath);
    try {
      conn.send(jsonFrame(request));
      return await conn.read();
    } finally {
      conn.close();
    }
  };

  return {
    resolve: async (request) => answerOf(parseResolveAnswer, await exchange(request)),
    grants: async (request) => answerOf(parseGrantsAnswer, await exchange(request)),
    async lend(request) {
      const frame = await exchange(request);
      if (frame.kind !== FRAME_BYTES) return refusalOf(frame);
      const bytes = frame.body;
      let used = false;
      const value = makeLent(request.keyref, () => {
        if (used) throw new RangeError('a lent value is used once');
        used = true;
        return bytes;
      });
      return { ok: true, value };
    },
    async scan(request) {
      const conn = await openConnection(socketPath);
      conn.send(jsonFrame(request));
      const first = await conn.read().catch((error: unknown) => {
        conn.close();
        throw error;
      });
      const raw = decodeJson(first);
      if (!raw.ok || !parseAccepted(raw.value)) {
        conn.close();
        return refusalOf(first);
      }
      const step = async (frame: Buffer): Promise<ScanStep> => {
        conn.send(frame);
        return answerOf(parseScanStep, await conn.read());
      };
      const session: ScanSession = {
        async feed(chunk) {
          const count = Math.max(1, Math.ceil(chunk.length / FRAME_MAX));
          let last: ScanStep = { kind: 'progress', releasable: 0 };
          for (let i = 0; i < count; i += 1) {
            last = await step(encodeFrame(FRAME_BYTES, chunk.subarray(i * FRAME_MAX, (i + 1) * FRAME_MAX)));
            if (last.kind === 'hit') break;
          }
          return last;
        },
        end: () => step(encodeFrame(FRAME_END, new Uint8Array(0))),
        close: () => conn.close(),
      };
      return { ok: true, session };
    },
    async audit(row) {
      const frame = await exchange({ op: 'audit', row });
      const raw = decodeJson(frame);
      if (!raw.ok || !parseAccepted(raw.value)) throw new LendUnavailable();
    },
  };
}
