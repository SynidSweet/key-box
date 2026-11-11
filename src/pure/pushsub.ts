// KBOX-22: a push subscription is accepted only when its endpoint is https on a closed list of push service hosts and
// its keys are well formed. Parse at the edge: the interior gets bytes and a URL, or a fixed code.
import { AUTH_SECRET_BYTES, isP256Point } from './pushcrypto.ts';

export interface SubscriptionInput {
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

export type SubscriptionCode = 'bad_endpoint' | 'bad_key';
export type ParsedSubscription =
  | { readonly ok: true; readonly endpoint: URL; readonly receiverPublicKey: Uint8Array; readonly authSecret: Uint8Array }
  | { readonly ok: false; readonly code: SubscriptionCode };

/** Canonical unpadded base64url only: what the browser's `toJSON` writes. Anything else decodes to nothing. */
export function decodeBase64Url(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? Uint8Array.from(bytes) : undefined;
}

/** `*.domain` matches one or more labels below `domain`, never `domain` itself. */
function hostAllowed(host: string, allowed: readonly string[]): boolean {
  return allowed.some((entry) => (entry.startsWith('*.') ? host.length > entry.length - 1 && host.endsWith(entry.slice(1)) : host === entry));
}

const refused = (code: SubscriptionCode): { readonly ok: false; readonly code: SubscriptionCode } => ({ ok: false, code });

function parseEndpoint(raw: string, allowedHosts: readonly string[]): URL | undefined {
  if (!URL.canParse(raw)) return undefined;
  const url = new URL(raw);
  // A port of 443 is the https default and parses to the empty string; a literal IP address can never equal a list entry.
  const plain = url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '';
  return plain && hostAllowed(url.hostname, allowedHosts) ? url : undefined;
}

export function parseSubscription(input: SubscriptionInput, allowedHosts: readonly string[]): ParsedSubscription {
  const endpoint = parseEndpoint(input.endpoint, allowedHosts);
  if (endpoint === undefined) return refused('bad_endpoint');
  const receiverPublicKey = decodeBase64Url(input.p256dh);
  const authSecret = decodeBase64Url(input.auth);
  if (receiverPublicKey === undefined || authSecret === undefined || !isP256Point(receiverPublicKey) || authSecret.length !== AUTH_SECRET_BYTES) return refused('bad_key');
  return { ok: true, endpoint, receiverPublicKey, authSecret };
}
