// KBOX-22: the shell of Web Push. Subscriptions and the VAPID key pair live only in the private store; every outside call
// goes through the one PushTransport; time, timers and randomness come in through ports.
import { createECDH } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Audit, AuditEvent } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { PrivateStore, PushSubscriptionRow } from '../ports/private.ts';
import type { Push, PushMessage, PushSubscriptionInput, PushSubscriptions, PushTransport, SubscribeResult } from '../ports/push.ts';
import type { Random } from '../ports/random.ts';
import { encryptPayload, vapidAuthorization } from '../pure/pushcrypto.ts';
import type { P256KeyPair } from '../pure/pushcrypto.ts';
import { decodeBase64Url, parseSubscription } from '../pure/pushsub.ts';

/** The closed list of push service hosts, read once at start. A file that is not a list of strings stops the start: a bad list must never mean "allow". */
function loadPushHosts(): readonly string[] {
  const parsed: unknown = JSON.parse(readFileSync(new URL('../data/push-hosts.json', import.meta.url), 'utf8'));
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed.every((h): h is string => typeof h === 'string')) throw new Error('src/data/push-hosts.json must be a non-empty list of host names');
  return parsed;
}

export interface PushDeps {
  readonly store: PrivateStore;
  readonly transport: PushTransport;
  readonly scheduler: Scheduler;
  readonly clock: Clock;
  readonly random: Random;
  readonly audit: Audit;
  /** The VAPID `sub` claim: a `mailto:` or `https:` contact for the push service operator. */
  readonly subject: string;
}

/** A hung push service is aborted after this long (decided in KBOX-22's build). */
export const SEND_TIMEOUT_MS = 10_000;
/** How long a push service may hold a message for an offline phone: an hour, after which "approve this" is stale. */
const TTL_SECONDS = 3600;
/** The VAPID JWT lives 12 hours; RFC 8292 section 2 allows 24. */
const VAPID_LIFETIME_SECONDS = 12 * 3600;
/** The audit row's ref for every push outcome: names only, never an endpoint. */
const REF = 'push';

const text = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'utf8'));
const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

/** The payload is exactly `{title, kind}` and `{count}` when there is one: nothing else a caller put on the message gets through. */
function payloadOf(message: PushMessage): Uint8Array {
  return text(JSON.stringify(message.count === undefined ? { title: message.title, kind: message.kind } : { title: message.title, kind: message.kind, count: message.count }));
}

/** A fresh P-256 key pair. Drawn here, in the shell: pure code may not generate keys (KBOX-28). */
function newKeyPair(random: Random): P256KeyPair {
  const ecdh = createECDH('prime256v1');
  // A uniformly random 32 bytes is a valid scalar except with probability about 2^-128; setPrivateKey refuses the rest.
  ecdh.setPrivateKey(Buffer.from(random.bytes(32)));
  return { privateKey: Uint8Array.from(ecdh.getPrivateKey()), publicKey: Uint8Array.from(ecdh.getPublicKey()) };
}

export function createPush(deps: PushDeps): Push & PushSubscriptions {
  const hosts = loadPushHosts();
  const failed = (code: string, status?: number): AuditEvent => ({ action: 'push.failed', subject: REF, at: deps.clock.now(), detail: status === undefined ? { code } : { code, status } });

  /** The box's one VAPID key pair: made at the first send, then read back from the store. */
  function vapidKeys(): P256KeyPair {
    const stored = deps.store.getVapidKeyPair();
    const privateKey = stored === undefined ? undefined : decodeBase64Url(stored.privateKey);
    const publicKey = stored === undefined ? undefined : decodeBase64Url(stored.publicKey);
    if (privateKey !== undefined && publicKey !== undefined) return { privateKey, publicKey };
    const made = newKeyPair(deps.random);
    deps.store.putVapidKeyPair({ privateKey: b64u(made.privateKey), publicKey: b64u(made.publicKey) });
    return made;
  }

  /** The POST for one subscription, or the code that kept it from being made. */
  function request(sub: PushSubscriptionRow, vapid: P256KeyPair, plaintext: Uint8Array): { ok: true; endpoint: URL; headers: Record<string, string>; body: Uint8Array } | { ok: false; code: string } {
    const receiverPublicKey = decodeBase64Url(sub.p256dh);
    const authSecret = decodeBase64Url(sub.auth);
    if (receiverPublicKey === undefined || authSecret === undefined || !URL.canParse(sub.endpoint)) return { ok: false, code: 'bad_key' };
    const endpoint = new URL(sub.endpoint);
    const body = encryptPayload({ plaintext, receiverPublicKey, authSecret, sender: newKeyPair(deps.random), salt: deps.random.bytes(16) });
    if (!body.ok) return { ok: false, code: body.code };
    const expiresAt = Math.floor(deps.clock.now() / 1000) + VAPID_LIFETIME_SECONDS;
    const authorization = vapidAuthorization({ sender: vapid, endpoint, expiresAt, subject: deps.subject });
    if (!authorization.ok) return { ok: false, code: authorization.code };
    const headers = { TTL: String(TTL_SECONDS), 'Content-Encoding': 'aes128gcm', Urgency: 'high', Authorization: authorization.value };
    return { ok: true, endpoint, headers, body: body.value };
  }

  /** One POST under its own timeout. Settles after the outcome is audited; it never rejects. */
  async function deliver(sub: PushSubscriptionRow, req: { endpoint: URL; headers: Record<string, string>; body: Uint8Array }): Promise<void> {
    const controller = new AbortController();
    const cancelTimeout = deps.scheduler.after(SEND_TIMEOUT_MS, () => controller.abort());
    try {
      const status = await deps.transport.post(req.endpoint, req.headers, req.body, controller.signal);
      if (status >= 200 && status < 300) {
        deps.audit.append({ action: 'push.delivered', subject: REF, at: deps.clock.now(), detail: { status } });
      } else if (status === 404 || status === 410) {
        deps.store.removePushSubscription(sub.endpoint);
        deps.audit.append({ action: 'push.subscription_removed', subject: REF, at: deps.clock.now(), detail: { status } });
      } else {
        deps.audit.append(failed('bad_status', status));
      }
    } catch {
      deps.audit.append(failed(controller.signal.aborted ? 'timeout' : 'transport_failed'));
    } finally {
      cancelTimeout();
    }
  }

  return {
    subscribe(input: PushSubscriptionInput): SubscribeResult {
      const parsed = parseSubscription(input, hosts);
      if (!parsed.ok) return { ok: false, code: parsed.code };
      deps.store.addPushSubscription({ endpoint: parsed.endpoint.href, p256dh: input.p256dh, auth: input.auth });
      return { ok: true };
    },

    send(message: PushMessage): void {
      try {
        const subs = deps.store.listPushSubscriptions();
        if (subs.length === 0) return;
        const vapid = vapidKeys();
        const plaintext = payloadOf(message);
        for (const sub of subs) {
          const req = request(sub, vapid, plaintext);
          if (req.ok) void deliver(sub, req);
          else deps.audit.append(failed(req.code));
        }
      } catch {
        deps.audit.append(failed('store_failed'));
      }
    },
  };
}
