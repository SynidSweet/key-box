// KBOX-13, KBOX-25, KBOX-32: what a platform adapter declares for the relay. A profile is data plus two functions: the
// relay engine (src/pure/profile.ts, src/pure/rule-match.ts) decides every match from the data; `inject` and
// `envForClients` are the only code a platform supplies.
import type { Lent, PlatformId } from './types.ts';

/** The headers a pass may be carried in (KBOX-32). */
export type PassHeader = 'authorization' | 'apikey';

/** A query value is a fixed word or a bounded integer; nothing else is accepted (KBOX-13 step 4). */
export type QueryShape =
  | { readonly kind: 'word'; readonly words: readonly string[] }
  | { readonly kind: 'int'; readonly min: number; readonly max: number };

/**
 * One named operation. `pathTemplate` segments are literals, typed parameters `{name:[class]{min,max}}` and, last and only
 * where the profile lists the rule in `tailRules`, `{rest:**}`. `query` lists every query key the rule accepts.
 */
export interface AllowRule {
  readonly id: string;
  readonly method: string;
  readonly host: string;
  readonly pathTemplate: string;
  readonly query: Readonly<Record<string, QueryShape>>;
}

/** A concrete request as the caller would ask it upstream: `url` is `https://<host><raw path and query>`, never normalised. */
export interface SampleRequest {
  readonly method: string;
  readonly url: string;
}

export interface DenyRule {
  readonly id: string;
  readonly samples: readonly SampleRequest[];
}

/**
 * Where the upstream origin comes from: one fixed host, or (Google) the first path segment, which must equal one of `hosts`
 * byte for byte, or (Supabase) the key's stored project: the host is `<ref>.<domain>`, the ref (`refLength` lower-case letters) being the
 * key's stored project from core's resolve answer and nothing else (KBOX-57). An allow rule of such a profile names the host `*.<domain>`
 * (`projectRuleHost`); the stored location supplies the ref, never the request.
 */
export type Origin =
  | { readonly kind: 'fixed'; readonly host: string }
  | { readonly kind: 'host-in-path'; readonly hosts: readonly string[] }
  | { readonly kind: 'project-host'; readonly domain: string; readonly refLength: number };

export interface RelayProfile {
  readonly platform: PlatformId;
  readonly origin: Origin;
  /** The headers this platform's clients carry the pass in; lower case. */
  readonly callerTokenHeaders: readonly PassHeader[];
  /** Sets the platform's auth headers from the lent value; never the query or the body. */
  inject(h: Headers, v: Lent): Promise<void>;
  /** Nothing else passes. */
  readonly allow: readonly AllowRule[];
  /** Ids of allow rules whose template may end in `{rest:**}`. */
  readonly tailRules: readonly string[];
  /** Non-empty; each carries concrete sample requests. */
  readonly mustDeny: readonly DenyRule[];
  /** Request headers forwarded besides the defaults (`content-type`, `accept`); lower case. */
  readonly requestHeaders: readonly string[];
  /** Headers of `requestHeaders` that pass only with one of these words (Supabase `accept-profile`: `public`); others give 403. */
  readonly headerWords: Readonly<Record<string, readonly string[]>>;
  /** Response headers passed back besides the defaults (rate limits, the platform's request id); lower case. */
  readonly responseHeaders: readonly string[];
  /** PostgREST states the rows of a 200 read as `Content-Range: 0-24/*`: such a header (items, no unit word) is not partial content (KBOX-14). */
  readonly itemsRange?: true;
  envForClients(relayUrl: string): Record<string, string>;
}
