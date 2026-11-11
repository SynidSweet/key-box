// Talks to a started core or relay over its unix socket.
import { request } from 'node:http';

export interface DriveRequest {
  readonly method?: string;
  readonly path: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string | Uint8Array;
}

export interface DriveReply {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  json(): unknown;
}

export interface Driver {
  request(req: DriveRequest): Promise<DriveReply>;
}

export function drive(socketPath: string): Driver {
  return {
    request: (req) =>
      new Promise((resolve, reject) => {
        const target = new URL(req.path, 'http://box.invalid');
        const call = request(
          { socketPath, method: req.method ?? 'GET', path: target.pathname + target.search, headers: { ...req.headers } },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('error', reject);
            res.on('end', () => {
              const headers: Record<string, string> = {};
              for (const [name, value] of Object.entries(res.headers)) {
                if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(', ') : value;
              }
              const body = Buffer.concat(chunks).toString('utf8');
              resolve({ status: res.statusCode ?? 0, headers, body, json: () => JSON.parse(body) as unknown });
            });
          },
        );
        call.on('error', reject);
        call.end(req.body);
      }),
  };
}
