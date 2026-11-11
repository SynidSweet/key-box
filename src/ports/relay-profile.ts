import type { Lent, PlatformId } from './types.ts';

export interface RelayTarget {
  readonly host: string;
  readonly path: string;
}

/** `query` maps a parameter name to the name of the value shape it must have. */
export interface AllowRule {
  readonly id: string;
  readonly method: string;
  readonly host: string;
  readonly pathTemplate: string;
  readonly query: Readonly<Record<string, string>>;
}

export interface SampleRequest {
  readonly method: string;
  readonly url: string;
}

export interface DenyRule {
  readonly id: string;
  readonly samples: readonly SampleRequest[];
}

export interface RelayProfile {
  readonly platform: PlatformId;
  upstream(target: RelayTarget): URL;
  readonly callerTokenHeaders: readonly string[];
  inject(h: Headers, v: Lent): Promise<void>;
  /** Nothing else passes. */
  readonly allow: readonly AllowRule[];
  /** Non-empty; each carries concrete sample requests. */
  readonly mustDeny: readonly DenyRule[];
  readonly requestHeaders: readonly string[];
  envForClients(relayUrl: string): Record<string, string>;
}
