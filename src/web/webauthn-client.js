// The phone side of an approver (KBOX-9, KBOX-49): the challenges the box checks, built the same way; the passkey (WebAuthn)
// and the device key (a WebCrypto ECDSA P-256 key that cannot be exported, kept in IndexedDB) that together make one proof;
// and the box's JSON routes. Plain JS checked by tsc (spec decision 21): the served bytes are the reviewed bytes.

/**
 * The few browser objects the pages use, typed here because the project's type check carries no DOM library.
 * @typedef {{ textContent: string | null, hidden: boolean, disabled: boolean, value: string, className: string,
 *   append(...nodes: (BrowserElement | string)[]): void, replaceChildren(...nodes: (BrowserElement | string)[]): void,
 *   setAttribute(name: string, value: string): void, addEventListener(type: string, listener: () => void): void }} BrowserElement
 * @typedef {{ getElementById(id: string): BrowserElement | null, createElement(tag: string): BrowserElement }} BrowserDocument
 * @typedef {{ result: unknown, error: unknown, onsuccess: (() => void) | null, onerror: (() => void) | null, onupgradeneeded: (() => void) | null }} IdbRequest
 * @typedef {{ objectStore(name: string): { put(value: unknown, key: string): IdbRequest, get(key: string): IdbRequest } }} IdbTransaction
 * @typedef {{ createObjectStore(name: string): void, transaction(name: string, mode: 'readonly' | 'readwrite'): IdbTransaction }} IdbDatabase
 * @typedef {{ open(name: string, version: number): IdbRequest }} IdbFactory
 * @typedef {{ subscribe(o: { userVisibleOnly: true, applicationServerKey: Uint8Array<ArrayBuffer> }): Promise<{ toJSON(): unknown }> }} PushManager
 * @typedef {{ credentials: { create(o: { publicKey: object }): Promise<unknown>, get(o: { publicKey: object }): Promise<unknown> },
 *   serviceWorker?: { register(url: string): Promise<unknown>, ready: Promise<{ pushManager?: PushManager }> } }} BrowserNavigator
 * @typedef {{ document: BrowserDocument, navigator: BrowserNavigator, indexedDB: IdbFactory, location: { hostname: string, hash: string } }} Browser
 */

/** The browser's globals under the types above. The one place the page's code meets the untyped runtime. */
export function browser() {
  return /** @type {Browser} */ (/** @type {unknown} */ (globalThis));
}

// --- bytes -------------------------------------------------------------------------------------------------------

const encoder = new TextEncoder();

/** @param {Uint8Array} bytes */
export function toB64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** @param {string} text @returns {Uint8Array<ArrayBuffer>} */
export function fromB64u(text) {
  const raw = atob(text.replaceAll('-', '+').replaceAll('_', '/'));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** @param {(string | Uint8Array)[]} parts @returns {Uint8Array<ArrayBuffer>} */
function concat(parts) {
  const bytes = parts.map((p) => (typeof p === 'string' ? encoder.encode(p) : p));
  const out = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of bytes) {
    out.set(b, at);
    at += b.length;
  }
  return out;
}

/** @param {(string | Uint8Array)[]} parts @returns {Promise<Uint8Array<ArrayBuffer>>} */
async function sha256(...parts) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', concat(parts)));
}

// --- the challenges (src/pure/challenge.ts builds the box's side) ------------------------------------------------

/** `SHA-256("kbox-v1" || approvalId || actionDigest || nonce)`. @param {string} approvalId @param {Uint8Array} digest @param {Uint8Array} nonce */
export const approvalChallenge = (approvalId, digest, nonce) => sha256('kbox-v1', approvalId, digest, nonce);

/** `SHA-256("kbox-v1-deny" || approvalId || actionDigest || nonce)`. @param {string} approvalId @param {Uint8Array} digest @param {Uint8Array} nonce */
export const denialChallenge = (approvalId, digest, nonce) => sha256('kbox-v1-deny', approvalId, digest, nonce);

/** `SHA-256("kbox-v1-paste" || pasteId || actionDigest || nonce)` (KBOX-12). @param {string} pasteId @param {Uint8Array} digest @param {Uint8Array} nonce */
export const pasteChallenge = (pasteId, digest, nonce) => sha256('kbox-v1-paste', pasteId, digest, nonce);

/** `SHA-256("kbox-v1-view" || nonce)`. @param {Uint8Array} nonce */
export const viewChallenge = (nonce) => sha256('kbox-v1-view', nonce);

/** `SHA-256("kbox-v1-register" || nonce)`. @param {Uint8Array} nonce */
export const registrationChallenge = (nonce) => sha256('kbox-v1-register', nonce);

/**
 * `SHA-256("kbox-v1-op" || SHA-256(canonical operation JSON) || nonce)`. The operation has two string members, kind before
 * label, so JSON.stringify of `{kind, label}` is its RFC 8785 form.
 * @param {{ kind: 'enrol_window_open' | 'token_revoke', label: string }} op @param {Uint8Array} nonce
 */
export const operationChallenge = async (op, nonce) => sha256('kbox-v1-op', await sha256(JSON.stringify({ kind: op.kind, label: op.label })), nonce);

// --- registration: the passkey's public key out of the authenticator data -------------------------------------------

/**
 * The credential id and COSE key of a new passkey: authenticator data is rpIdHash(32) flags(1) counter(4), then, with the
 * AT flag (0x40) set, aaguid(16) length(2) credentialId COSE key. The box parses the COSE key itself; an ES256 key is 77 bytes.
 * @param {Uint8Array} authData @returns {{ credentialId: Uint8Array, coseKey: Uint8Array } | undefined}
 */
export function attestedKey(authData) {
  const flags = authData[32];
  if (flags === undefined || (flags & 0x40) === 0 || authData.length < 55) return undefined;
  const length = ((authData[53] ?? 0) << 8) | (authData[54] ?? 0);
  const keyAt = 55 + length;
  if (authData.length < keyAt + 77) return undefined;
  return { credentialId: authData.slice(55, keyAt), coseKey: authData.slice(keyAt, keyAt + 77) };
}

// --- the device key ---------------------------------------------------------------------------------------------

/** @typedef {{ credentialId: string, deviceKey: InstanceType<typeof CryptoKey> }} StoredApprover */

/** @param {(db: IdbDatabase) => IdbRequest} use @returns {Promise<unknown>} */
function withDb(use) {
  return new Promise((resolve, reject) => {
    const open = browser().indexedDB.open('keybox', 1);
    open.onupgradeneeded = () => /** @type {IdbDatabase} */ (open.result).createObjectStore('approver');
    open.onerror = () => reject(new Error('the phone storage did not open'));
    open.onsuccess = () => {
      const request = use(/** @type {IdbDatabase} */ (open.result));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('the phone storage refused the request'));
    };
  });
}

/** The approver this phone holds, or undefined when it holds none (a new install, cleared data). @returns {Promise<StoredApprover | undefined>} */
export async function storedApprover() {
  const value = await withDb((db) => db.transaction('approver', 'readonly').objectStore('approver').get('me'));
  if (typeof value !== 'object' || value === null) return undefined;
  const { credentialId, deviceKey } = /** @type {{ credentialId?: unknown, deviceKey?: unknown }} */ (value);
  if (typeof credentialId !== 'string' || !(deviceKey instanceof CryptoKey)) return undefined;
  return { credentialId, deviceKey };
}

/** @param {unknown} v @returns {ArrayBuffer} */
function buffer(v) {
  if (!(v instanceof ArrayBuffer)) throw new Error('the authenticator answered in an unexpected shape');
  return v;
}

/**
 * Makes the passkey and the device key of a new approver, keeps the device key on this phone, and proves both over the
 * registration challenge. Returns the body members the box's /setup, /recover and /recover/register take.
 * @param {Uint8Array} nonce
 */
export async function registerApprover(nonce) {
  const nav = browser().navigator;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const created = /** @type {{ response?: { getAuthenticatorData?: () => unknown } } | null} */ (
    await nav.credentials.create({
      publicKey: {
        rp: { id: browser().location.hostname, name: 'Key box' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'owner', displayName: 'Key box owner' },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
      },
    })
  );
  const authData = created?.response?.getAuthenticatorData?.();
  const key = attestedKey(new Uint8Array(buffer(authData)));
  if (key === undefined) throw new Error('the passkey is not an ES256 key this box can use');
  const credentialId = toB64u(key.credentialId);
  await withDb((db) => db.transaction('approver', 'readwrite').objectStore('approver').put({ credentialId, deviceKey: pair.privateKey }, 'me'));
  const approver = { credential_id: credentialId, cose_key: toB64u(key.coseKey), device_public_key: toB64u(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))) };
  return { approver, proof: await prove(nonce, await registrationChallenge(nonce)) };
}

/**
 * One approver proof: a passkey assertion (user verification required) and the device key's signature, both over the same
 * challenge. The device signature is WebCrypto's raw r||s, which is what the box verifies.
 * @param {Uint8Array} nonce @param {Uint8Array<ArrayBuffer>} challenge
 */
export async function prove(nonce, challenge) {
  const me = await storedApprover();
  if (me === undefined) throw new Error('this phone holds no approver key: use recovery');
  const assertion = /** @type {{ response?: { authenticatorData?: unknown, clientDataJSON?: unknown, signature?: unknown } } | null} */ (
    await browser().navigator.credentials.get({
      publicKey: { challenge, rpId: browser().location.hostname, allowCredentials: [{ type: 'public-key', id: fromB64u(me.credentialId) }], userVerification: 'required' },
    })
  );
  const response = assertion?.response;
  const deviceSignature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, me.deviceKey, challenge));
  return {
    nonce: toB64u(nonce),
    credential_id: me.credentialId,
    authenticator_data: toB64u(new Uint8Array(buffer(response?.authenticatorData))),
    client_data_json: toB64u(new Uint8Array(buffer(response?.clientDataJSON))),
    signature: toB64u(new Uint8Array(buffer(response?.signature))),
    device_signature: toB64u(deviceSignature),
  };
}

// --- the box ------------------------------------------------------------------------------------------------------

/**
 * One JSON call to the box. Resolves to the answer's JSON body, or rejects with the box's error code.
 * @param {string} path @param {unknown} [body] @returns {Promise<unknown>}
 */
export async function call(path, body) {
  return answerOf(await fetch(path, body === undefined ? { credentials: 'same-origin' } : { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }));
}

/** A POST with no body (a route that takes none, such as asking for a registration code). @param {string} path @returns {Promise<unknown>} */
export async function post(path) {
  return answerOf(await fetch(path, { method: 'POST', credentials: 'same-origin' }));
}

/** The answer's JSON body, or the box's error as a rejection. @param {Response} reply @returns {Promise<unknown>} */
async function answerOf(reply) {
  const json = /** @type {unknown} */ (await reply.json());
  if (reply.ok) return json;
  const error = /** @type {{ error?: { message?: unknown } }} */ (typeof json === 'object' && json !== null ? json : {}).error;
  throw new Error(typeof error?.message === 'string' ? error.message : `The box answered ${reply.status}.`);
}

/** A fresh single-use nonce for a view, a signed operation or a registration. @param {'view' | 'op' | 'register'} purpose */
export async function nonce(purpose) {
  const json = await call(`/app/nonce?purpose=${purpose}`);
  if (typeof json !== 'object' || json === null || !('nonce_b64' in json) || typeof json.nonce_b64 !== 'string') throw new Error('the box sent no nonce');
  return fromB64u(json.nonce_b64);
}

/**
 * Subscribes this phone to the box's notifications when the browser offers Web Push; answers the subscription the box
 * stores, or undefined when push is not available here (the queue still shows what waits when the app is opened).
 * @returns {Promise<{ endpoint: string, p256dh: string, auth: string } | undefined>}
 */
export async function pushSubscription() {
  const sw = browser().navigator.serviceWorker;
  if (sw === undefined) return undefined;
  await sw.register('/sw.js');
  const manager = (await sw.ready).pushManager;
  if (manager === undefined) return undefined;
  const json = await call('/app/push-key');
  if (typeof json !== 'object' || json === null || !('application_server_key_b64' in json) || typeof json.application_server_key_b64 !== 'string') return undefined;
  const sub = /** @type {{ endpoint?: unknown, keys?: { p256dh?: unknown, auth?: unknown } }} */ ((await manager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64u(json.application_server_key_b64) })).toJSON());
  const { endpoint } = sub;
  const p256dh = sub.keys?.p256dh;
  const auth = sub.keys?.auth;
  if (typeof endpoint !== 'string' || typeof p256dh !== 'string' || typeof auth !== 'string') return undefined;
  return { endpoint, p256dh, auth };
}

/** The element with this id; the pages are static, so a missing one is a page fault. @param {string} id */
export function byId(id) {
  const el = browser().document.getElementById(id);
  if (el === null) throw new Error(`the page has no #${id}`);
  return el;
}

/** The page's notifier: the status line under the buttons, where every outcome and every failure is shown. */
export const notifier = {
  /** @param {string} text */
  say(text) {
    byId('status').textContent = text;
  },
  /** @param {unknown} error */
  failed(error) {
    notifier.say(error instanceof Error ? error.message : 'That did not work.');
  },
};
