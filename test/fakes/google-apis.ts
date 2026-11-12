// The API Keys, Cloud Resource Manager v3 and Secret Manager halves of the fake Google (test/fakes/google.ts serves the identity half). It plays
// the answers docs/probes/google.md could only read from discovery documents, so each is a stated assumption of the test, not a fact: names come
// back with the project NUMBER (as the documentation shows), a create answers an Operation, a key's value is only at `.../keyString`, a delete
// is hard unless `softDelete`, and the default list omits a soft-deleted key. Every call must carry the admin token of the project its path names.
import { createHash } from 'node:crypto';

export type ApisRoute = 'create-key' | 'operation' | 'key-string' | 'get-key' | 'delete-key' | 'list-keys' | 'lookup-key' | 'project' | 'add-version';

export interface ApisAnswer {
  readonly status: number;
  readonly body: unknown;
}

export interface FakeKey {
  readonly id: string;
  readonly displayName: string;
  readonly keyString: string;
  readonly restrictions: unknown;
  deleteTime: string | undefined;
}

/** What a test turns to make the fake answer another way. */
export interface ApisKnobs {
  /** How many reads of an Operation answer "not done" before it is done. */
  operationPolls: number;
  /** An Operation that is never done. */
  neverDone: boolean;
  /** A done Operation that carries an error. */
  operationError: boolean;
  /** How a done Operation names the key: with the project number (the default), the project id, or any text. */
  nameAs: 'number' | 'id' | ((project: string, id: string, number: string) => string);
  /** Keys per page of the list; undefined: one page. */
  pageSize: number | undefined;
  /** A delete marks `deleteTime` and keeps the key; false: it is gone. */
  softDelete: boolean;
  /** The list shows soft-deleted keys (the documentation's `showDeleted` default is false). */
  listIncludesDeleted: boolean;
  /** The `keyString` the next create makes (a canary), once. */
  nextKeyString: string | undefined;
  /** Every key's id (instead of a counter), once. */
  nextKeyId: string | undefined;
  /** The next page's token: its own (`normal`), the page it was asked for again (`repeat`), or one that is no token (`malformed`). */
  tokens: 'normal' | 'repeat' | 'malformed';
  /** The list answers 500 for every page after this many; undefined: never. */
  failAfterPages: number | undefined;
}

export interface PlantedKey {
  readonly id: string;
  readonly displayName: string;
  readonly keyString?: string;
  readonly deleteTime?: string;
}

export interface FakeApis {
  readonly knobs: ApisKnobs;
  /** Every route's answer of this fake, or undefined when the path and method are none of its routes. */
  routeOf(method: string, pathname: string): ApisRoute | undefined;
  answer(route: ApisRoute, request: { readonly method: string; readonly pathname: string; readonly query: URLSearchParams; readonly body: string }, account: string | undefined): ApisAnswer;
  /** Makes the project known with this project number. */
  project(project: string, number?: string): string;
  /** Plants a key as if it had been made; answers its `keyString`. */
  plant(project: string, key: PlantedKey): string;
  /** The keys of a project, soft-deleted ones included. */
  keysOf(project: string): readonly FakeKey[];
  /** A secret Secret Manager holds, so `addVersion` finds it. */
  makeSecret(project: string, secret: string): void;
  /** The values written to a secret, oldest first. */
  versionsOf(project: string, secret: string): readonly string[];
  reset(): void;
}

const ROUTES: readonly (readonly [ApisRoute, string, RegExp])[] = [
  ['create-key', 'POST', /^\/v2\/projects\/([^/]+)\/locations\/global\/keys$/],
  ['list-keys', 'GET', /^\/v2\/projects\/([^/]+)\/locations\/global\/keys$/],
  ['operation', 'GET', /^\/v2\/operations\/([^/]+)$/],
  ['key-string', 'GET', /^\/v2\/projects\/([^/]+)\/locations\/global\/keys\/([^/]+)\/keyString$/],
  ['get-key', 'GET', /^\/v2\/projects\/([^/]+)\/locations\/global\/keys\/([^/]+)$/],
  ['delete-key', 'DELETE', /^\/v2\/projects\/([^/]+)\/locations\/global\/keys\/([^/]+)$/],
  ['lookup-key', 'GET', /^\/v2\/keys:lookupKey$/],
  ['project', 'GET', /^\/v3\/projects\/([^/]+)$/],
  ['add-version', 'POST', /^\/v1\/projects\/([^/]+)\/secrets\/([^/:]+):addVersion$/],
];

const NOT_FOUND: ApisAnswer = { status: 404, body: { error: { code: 404, status: 'NOT_FOUND' } } };
const denied = (status: 401 | 403): ApisAnswer => ({ status, body: { error: { code: status, status: status === 401 ? 'UNAUTHENTICATED' : 'PERMISSION_DENIED' } } });
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A request body as JSON, or no JSON. */
function parsed(text: string): { readonly ok: true; readonly value: unknown } | { readonly ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

/** A value of Google's API-key shape (`AIza` and 35 base64url characters), unique per `n`. */
const keyStringOf = (n: number): string => `AIza${createHash('sha256').update(`kbox-test-key-${n}`).digest('base64url').slice(0, 35)}`;

export function fakeApis(): FakeApis {
  const defaults = (): ApisKnobs => ({ operationPolls: 0, neverDone: false, operationError: false, nameAs: 'number', pageSize: undefined, softDelete: false, listIncludesDeleted: false, nextKeyString: undefined, nextKeyId: undefined, tokens: 'normal', failAfterPages: undefined });
  const knobs = defaults();
  const numbers = new Map<string, string>();
  const keys = new Map<string, Map<string, FakeKey>>();
  const secrets = new Map<string, string[]>();
  const operations = new Map<string, { polls: number; project: string; id: string }>();
  let counter = 0;
  let pagesServed = 0;

  const numberOf = (project: string): string => {
    const known = numbers.get(project);
    if (known !== undefined) return known;
    const made = String(400_000_000_000 + numbers.size + 1);
    numbers.set(project, made);
    return made;
  };
  const keysIn = (project: string): Map<string, FakeKey> => {
    let held = keys.get(project);
    if (held === undefined) {
      held = new Map();
      keys.set(project, held);
    }
    return held;
  };
  const nameOf = (project: string, id: string): string => `projects/${numberOf(project)}/locations/global/keys/${id}`;
  const answeredName = (project: string, id: string): string => (knobs.nameAs === 'number' ? nameOf(project, id) : knobs.nameAs === 'id' ? `projects/${project}/locations/global/keys/${id}` : knobs.nameAs(project, id, numberOf(project)));
  const keyBody = (project: string, key: FakeKey): Record<string, unknown> => ({ name: nameOf(project, key.id), uid: key.id, displayName: key.displayName, ...(key.deleteTime === undefined ? {} : { deleteTime: key.deleteTime }) });

  /** The project's own `kbox-keys` token and no other: the one rule Google's IAM gives each call here. */
  const authorised = (account: string | undefined, project: string): ApisAnswer | undefined => (account === undefined ? denied(401) : account === `kbox-keys@${project}.iam.gserviceaccount.com` ? undefined : denied(403));

  const create = (project: string, body: string): ApisAnswer => {
    const request = parsed(body);
    const sent = request.ok ? request.value : undefined;
    if (!request.ok) return { status: 400, body: { error: { code: 400, status: 'INVALID_ARGUMENT' } } };
    const targets = isRecord(sent) && isRecord(sent['restrictions']) ? sent['restrictions']['apiTargets'] : undefined;
    const displayName = isRecord(sent) ? sent['displayName'] : undefined;
    if (typeof displayName !== 'string' || displayName.length > 63 || !Array.isArray(targets) || targets.length === 0) return { status: 400, body: { error: { code: 400, status: 'INVALID_ARGUMENT' } } };
    counter += 1;
    const id = knobs.nextKeyId ?? `key-${counter}`;
    const keyString = knobs.nextKeyString ?? keyStringOf(counter);
    knobs.nextKeyId = undefined;
    knobs.nextKeyString = undefined;
    keysIn(project).set(id, { id, displayName, keyString, restrictions: isRecord(sent) ? sent['restrictions'] : undefined, deleteTime: undefined });
    const operation = `op-${counter}`;
    operations.set(operation, { polls: 0, project, id });
    return { status: 200, body: { name: `operations/${operation}` } };
  };

  const operation = (name: string): ApisAnswer => {
    const op = operations.get(name);
    if (op === undefined) return NOT_FOUND;
    op.polls += 1;
    if (knobs.neverDone || op.polls <= knobs.operationPolls) return { status: 200, body: { name: `operations/${name}`, done: false } };
    if (knobs.operationError) return { status: 200, body: { name: `operations/${name}`, done: true, error: { code: 7, message: 'denied' } } };
    return { status: 200, body: { name: `operations/${name}`, done: true, response: { '@type': 'type.googleapis.com/google.api.apikeys.v2.Key', name: answeredName(op.project, op.id), uid: op.id } } };
  };

  const list = (project: string, query: URLSearchParams): ApisAnswer => {
    pagesServed = query.has('pageToken') ? pagesServed + 1 : 1;
    if (knobs.failAfterPages !== undefined && pagesServed > knobs.failAfterPages) return { status: 500, body: { error: { code: 500, status: 'INTERNAL' } } };
    const shown = [...keysIn(project).values()].filter((k) => knobs.listIncludesDeleted || k.deleteTime === undefined);
    const size = knobs.pageSize ?? Math.max(shown.length, 1);
    const asked = query.get('pageToken');
    const from = Number(asked?.replace(/^page-/, '') ?? '0') || 0;
    const page = shown.slice(from, from + size);
    const more = from + size < shown.length || knobs.tokens !== 'normal';
    const next = knobs.tokens === 'repeat' ? 'page-again' : knobs.tokens === 'malformed' ? 'not a token!' : `page-${from + size}`;
    return { status: 200, body: { ...(page.length === 0 ? {} : { keys: page.map((k) => keyBody(project, k)) }), ...(more ? { nextPageToken: next } : {}) } };
  };

  const remove = (project: string, id: string): ApisAnswer => {
    const key = keysIn(project).get(id);
    if (key === undefined || key.deleteTime !== undefined) return NOT_FOUND;
    if (knobs.softDelete) key.deleteTime = '2026-11-13T10:00:00Z';
    else keysIn(project).delete(id);
    counter += 1;
    return { status: 200, body: { name: `operations/del-${counter}`, done: false } };
  };

  const lookup = (query: URLSearchParams): ApisAnswer => {
    const wanted = query.get('keyString');
    for (const [project, held] of keys) for (const key of held.values()) if (key.keyString === wanted) return { status: 200, body: { name: nameOf(project, key.id), parent: `projects/${numberOf(project)}/locations/global` } };
    return NOT_FOUND;
  };

  const addVersion = (project: string, secret: string, body: string): ApisAnswer => {
    const held = secrets.get(`${project}/${secret}`);
    if (held === undefined) return NOT_FOUND;
    const request = parsed(body);
    const sent = request.ok ? request.value : undefined;
    const data = isRecord(sent) && isRecord(sent['payload']) ? sent['payload']['data'] : undefined;
    if (typeof data !== 'string') return { status: 400, body: { error: { code: 400, status: 'INVALID_ARGUMENT' } } };
    held.push(Buffer.from(data, 'base64').toString('utf8'));
    return { status: 200, body: { name: `projects/${numberOf(project)}/secrets/${secret}/versions/${held.length}`, state: 'ENABLED' } };
  };

  return {
    knobs,
    routeOf(method, pathname) {
      return ROUTES.find(([, m, pattern]) => m === method && pattern.test(pathname))?.[0];
    },
    answer(route, request, account) {
      const pattern = ROUTES.find(([r]) => r === route)?.[2];
      const [, project = '', second = ''] = pattern?.exec(request.pathname) ?? [];
      if (route === 'operation') return authorisedAnywhere(account) ?? operation(project);
      if (route === 'lookup-key') return authorisedAnywhere(account) ?? lookup(request.query);
      const refused = authorised(account, project);
      if (refused !== undefined) return refused;
      switch (route) {
        case 'create-key':
          return create(project, request.body);
        case 'list-keys':
          return list(project, request.query);
        case 'key-string': {
          const key = keysIn(project).get(second);
          return key === undefined ? NOT_FOUND : { status: 200, body: { keyString: key.keyString } };
        }
        case 'get-key': {
          const key = keysIn(project).get(second);
          return key === undefined ? NOT_FOUND : { status: 200, body: keyBody(project, key) };
        }
        case 'delete-key':
          return remove(project, second);
        case 'project':
          return numbers.has(project) ? { status: 200, body: { name: `projects/${numberOf(project)}`, projectId: project } } : NOT_FOUND;
        case 'add-version':
          return addVersion(project, second, request.body);
      }
    },
    project: (project, number) => {
      if (number !== undefined) numbers.set(project, number);
      return numberOf(project);
    },
    plant(project, key) {
      numberOf(project);
      counter += 1;
      const keyString = key.keyString ?? keyStringOf(counter);
      keysIn(project).set(key.id, { id: key.id, displayName: key.displayName, keyString, restrictions: undefined, deleteTime: key.deleteTime });
      return keyString;
    },
    keysOf: (project) => [...keysIn(project).values()],
    makeSecret: (project, secret) => void secrets.set(`${project}/${secret}`, []),
    versionsOf: (project, secret) => secrets.get(`${project}/${secret}`) ?? [],
    reset() {
      Object.assign(knobs, defaults());
      numbers.clear();
      keys.clear();
      secrets.clear();
      operations.clear();
      counter = 0;
    },
  };
}

/** A call that names no project (an Operation, a lookup) needs some admin token. */
const authorisedAnywhere = (account: string | undefined): ApisAnswer | undefined => (account === undefined ? denied(401) : undefined);
