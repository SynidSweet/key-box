// KBOX-25 and KBOX-23: the relay profile engine and the registry checks. A profile is compiled once; the engine decides each
// request default-deny: the request must match one allow rule and equal none of the profile's mustDeny samples. The registry
// check uses the same parse and the same engine, so what the box refuses at startup is exactly what the relay would let through.
import type { PlatformEntry } from '../ports/platform.ts';
import type { AllowRule, DenyRule, RelayProfile, SampleRequest } from '../ports/relay-profile.ts';
import { checkDestinationKinds, checkHosts, checkLocationFields, checkShapeSource } from './registry-entry.ts';
import type { EntryFailure } from './registry-entry.ts';
import { compileTemplate, matchTemplate, queryFits } from './rule-match.ts';
import type { Template } from './rule-match.ts';
import { HTTP_METHODS } from './schemas.ts';
import { canonicalPath, canonicalQuery, parseRelayTarget } from './target-parse.ts';
import type { QueryPair, RelayTarget } from './target-parse.ts';

/** Platforms whose keys are never relayed in v1; they export only their mustDeny list (KBOX-23). */
export const RELAY_DENY_ONLY: readonly string[] = ['vercel', 'elevenlabs'];

/** Request headers the relay always forwards when present (`content-length` is recomputed, never copied). */
export const DEFAULT_REQUEST_HEADERS: readonly string[] = ['content-type', 'accept'];
/** Response headers the relay always passes (`location` only on a 3xx). */
export const DEFAULT_RESPONSE_HEADERS: readonly string[] = ['content-type', 'content-length', 'retry-after'];

/** Partial-content request headers: on no profile's list, ever (KBOX-13). */
const PARTIAL_CONTENT = new Set(['range', 'if-range']);
/** Headers the relay itself owns or refuses; a profile may not forward them. */
const RELAY_OWNED_REQUEST = new Set([
  'authorization', 'apikey', 'proxy-authorization', 'cookie', 'host', 'content-length', 'transfer-encoding', 'te', 'trailer', 'connection',
  'upgrade', 'keep-alive', 'accept-encoding', 'x-http-method-override', 'x-http-method', 'x-method-override', 'x-forwarded-for',
  'x-forwarded-host', 'x-forwarded-proto', 'forwarded', 'x-real-ip', 'x-kb-client-ip', 'x-agent', 'x-project', 'origin',
]);
const RELAY_OWNED_RESPONSE = new Set([
  'set-cookie', 'content-range', 'content-encoding', 'transfer-encoding', 'trailer', 'connection', 'upgrade', 'keep-alive', 'location',
  'x-content-type-options', 'content-security-policy', 'content-disposition', 'accept-ranges',
]);

const HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

export type ProfileFailure = 'bad_template' | 'tail_not_named' | 'bad_host';

/** A request as rules see it: the method from the request line, the upstream host and the decoded segments of its path. */
export interface RelayRequest {
  readonly method: string;
  readonly host: string;
  readonly segments: readonly string[];
  readonly query: readonly QueryPair[];
}

export type Decision = { readonly ok: true; readonly rule: AllowRule; readonly request: RelayRequest } | { readonly ok: false; readonly code: 'forbidden' };

export interface ProfileEngine {
  readonly profile: RelayProfile;
  /** Default-deny: the one allow rule this request matches, or `forbidden`. */
  decide(method: string, target: RelayTarget): Decision;
  /** The request equals a mustDeny sample of the profile. */
  isDenied(method: string, target: RelayTarget): boolean;
  /** The sample as the relay would see it, or undefined when the one parse refuses it (so no rule can ever match it). */
  sampleTarget(sample: SampleRequest, keyref: string): string | undefined;
}

interface CompiledRule {
  readonly rule: AllowRule;
  readonly template: Template;
}

const hostsOf = (profile: RelayProfile): readonly string[] => (profile.origin.kind === 'fixed' ? [profile.origin.host] : profile.origin.hosts);

const requestKey = (r: RelayRequest): string => `${r.method} ${r.host}${canonicalPath(r.segments)}?${canonicalQuery(r.query)}`;

function requestOf(profile: RelayProfile, method: string, target: RelayTarget): RelayRequest | undefined {
  if (profile.origin.kind === 'fixed') return { method, host: profile.origin.host, segments: target.segments, query: target.query };
  const [host, ...rest] = target.segments;
  const raw = target.rawSegments[0];
  if (host === undefined || raw !== host || !profile.origin.hosts.includes(host)) return undefined;
  return { method, host, segments: rest, query: target.query };
}

const ruleMatches = (compiled: CompiledRule, request: RelayRequest): boolean =>
  compiled.rule.method === request.method && compiled.rule.host === request.host && matchTemplate(compiled.template, request.segments) && queryFits(compiled.rule.query, request.query);

/** `https://<host><tail>` split into its host and the rest, or undefined for another scheme or an empty host. */
function splitSample(url: string): { readonly host: string; readonly tail: string } | undefined {
  if (!url.startsWith('https://')) return undefined;
  const rest = url.slice('https://'.length);
  const cut = rest.search(/[/?]/);
  const host = cut < 0 ? rest : rest.slice(0, cut);
  return host === '' ? undefined : { host, tail: cut < 0 ? '' : rest.slice(cut) };
}

function relayTargetOf(profile: RelayProfile, sample: SampleRequest, keyref: string): string | undefined {
  const parts = splitSample(sample.url);
  if (parts === undefined || !hostsOf(profile).includes(parts.host)) return undefined;
  return profile.origin.kind === 'fixed' ? `/r/${keyref}${parts.tail}` : `/r/${keyref}/${parts.host}${parts.tail}`;
}

/** Any keyref the parse accepts: samples are about the path, never the key. */
const SAMPLE_KEYREF = 'sample';

/** The methods a sample may name, compared case-exactly: `OTHER` is the audit's placeholder, not a method. */
const SAMPLE_METHODS: readonly string[] = HTTP_METHODS.filter((m) => m !== 'OTHER');

/**
 * What one mustDeny sample is. A `request` parses to one the rules can match. A `variant` is a canonicalisation variant of
 * KBOX-13 that the one parse refuses on purpose. `unparsed` is anything else that never reaches the rules: a typo host, another
 * scheme, a method that is not spelled exactly.
 */
type SampleKind = { readonly kind: 'request'; readonly request: RelayRequest } | { readonly kind: 'variant' } | { readonly kind: 'unparsed' };

const UNPARSED: SampleKind = { kind: 'unparsed' };
const VARIANT: SampleKind = { kind: 'variant' };

function classifySample(sample: SampleRequest, targetOf: (sample: SampleRequest) => string | undefined, toRequest: (target: RelayTarget) => RelayRequest | undefined): SampleKind {
  if (!SAMPLE_METHODS.includes(sample.method)) return UNPARSED;
  const text = targetOf(sample);
  if (text === undefined) return UNPARSED;
  const target = parseRelayTarget(text);
  if (!target.ok) return target.code === 'bad_path' || target.code === 'bad_query' ? VARIANT : UNPARSED;
  const request = toRequest(target.value);
  return request === undefined ? UNPARSED : { kind: 'request', request };
}

const classifyForProfile = (profile: RelayProfile, sample: SampleRequest): SampleKind =>
  classifySample(sample, (s) => relayTargetOf(profile, s, `${SAMPLE_KEYREF}01`), (target) => requestOf(profile, sample.method, target));

/** A denyOnly list has no profile: the host is the sample's own, and it must be a plain host name. */
const classifyDenyOnly = (sample: SampleRequest): SampleKind =>
  classifySample(
    sample,
    (s) => {
      const parts = splitSample(s.url);
      return parts === undefined || !HOST.test(parts.host) ? undefined : `/r/${SAMPLE_KEYREF}01${parts.tail}`;
    },
    (target) => ({ method: sample.method, host: '', segments: target.segments, query: target.query }),
  );

function sampleRequests(profile: RelayProfile, rules: readonly DenyRule[]): RelayRequest[] {
  const out: RelayRequest[] = [];
  for (const sample of rules.flatMap((r) => r.samples)) {
    const kind = classifyForProfile(profile, sample);
    if (kind.kind === 'request') out.push(kind.request);
  }
  return out;
}

export type ProfileCompile = { readonly ok: true; readonly engine: ProfileEngine } | { readonly ok: false; readonly code: ProfileFailure };

/** Checks the shape of a profile (templates, tails, hosts) and builds its engine. */
export function compileProfile(profile: RelayProfile): ProfileCompile {
  const hosts = hostsOf(profile);
  if (hosts.length === 0 || !hosts.every((h) => HOST.test(h))) return { ok: false, code: 'bad_host' };
  const compiled: CompiledRule[] = [];
  for (const rule of profile.allow) {
    if (!hosts.includes(rule.host)) return { ok: false, code: 'bad_host' };
    const parsed = compileTemplate(rule.pathTemplate);
    if (!parsed.ok) return { ok: false, code: 'bad_template' };
    if (parsed.template.hasTail && !profile.tailRules.includes(rule.id)) return { ok: false, code: 'tail_not_named' };
    compiled.push({ rule, template: parsed.template });
  }
  const denied = new Set(sampleRequests(profile, profile.mustDeny).map(requestKey));
  const isDeniedRequest = (request: RelayRequest): boolean => denied.has(requestKey(request));
  const engine: ProfileEngine = {
    profile,
    decide(method, target) {
      const request = requestOf(profile, method, target);
      if (request === undefined || isDeniedRequest(request)) return { ok: false, code: 'forbidden' };
      const found = compiled.find((c) => ruleMatches(c, request));
      return found === undefined ? { ok: false, code: 'forbidden' } : { ok: true, rule: found.rule, request };
    },
    isDenied(method, target) {
      const request = requestOf(profile, method, target);
      return request !== undefined && isDeniedRequest(request);
    },
    sampleTarget: (sample, keyref) => relayTargetOf(profile, sample, keyref),
  };
  return { ok: true, engine };
}

/** The first allow rule that matches a mustDeny sample, or undefined. */
function leakingRule(engine: ProfileEngine, rules: readonly AllowRule[], tailRules: readonly string[]): string | undefined {
  const profile = { ...engine.profile, allow: rules, tailRules };
  const compiled = compileProfile(profile);
  if (!compiled.ok) return rules[0]?.id ?? 'none';
  const samples = sampleRequests(engine.profile, engine.profile.mustDeny);
  for (const rule of rules) {
    const template = compileTemplate(rule.pathTemplate);
    if (!template.ok) return rule.id;
    if (samples.some((s) => ruleMatches({ rule, template: template.template }, s))) return rule.id;
  }
  return undefined;
}

export type Widening = { readonly ok: true } | { readonly ok: false; readonly code: 'allow_matches_must_deny'; readonly rule: string };

/** KBOX-25: a proposed rule that matches a mustDeny sample is refused, whatever approval it would get. */
export function refuseWidening(engine: ProfileEngine, rules: readonly AllowRule[], tailRules: readonly string[]): Widening {
  const rule = leakingRule(engine, rules, [...engine.profile.tailRules, ...tailRules]);
  return rule === undefined ? { ok: true } : { ok: false, code: 'allow_matches_must_deny', rule };
}

export type RegistryFailure =
  | ProfileFailure
  | 'no_must_deny'
  | 'must_deny_sample_unparsed'
  | 'must_deny_untested'
  | 'allow_matches_must_deny'
  | 'partial_content_header'
  | 'relay_owned_header'
  | 'deny_only_with_relay'
  | 'deny_only_not_listed'
  | 'deny_only_without_must_deny'
  | EntryFailure
  | 'reveal_once_without_lister'
  | 'duplicate_platform'
  | 'platform_mismatch';

export type RegistryCheck = { readonly ok: true } | { readonly ok: false; readonly code: RegistryFailure; readonly platform: string };

const hasSamples = (rules: readonly DenyRule[] | undefined): boolean => rules !== undefined && rules.length > 0 && rules.every((r) => r.samples.length > 0);

/** KBOX-23: every sample is a request or a deliberate variant, and each rule has at least one request, or its list tests nothing. */
function checkSamples(rules: readonly DenyRule[], classify: (sample: SampleRequest) => SampleKind): RegistryFailure | undefined {
  for (const rule of rules) {
    const kinds = rule.samples.map(classify);
    if (kinds.some((k) => k.kind === 'unparsed')) return 'must_deny_sample_unparsed';
    if (!kinds.some((k) => k.kind === 'request')) return 'must_deny_untested';
  }
  return undefined;
}

function checkRelay(profile: RelayProfile): RegistryFailure | undefined {
  const requestHeaders = profile.requestHeaders.map((h) => h.toLowerCase());
  if (requestHeaders.some((h) => PARTIAL_CONTENT.has(h))) return 'partial_content_header';
  if (requestHeaders.some((h) => RELAY_OWNED_REQUEST.has(h)) || profile.responseHeaders.some((h) => RELAY_OWNED_RESPONSE.has(h.toLowerCase()))) return 'relay_owned_header';
  const compiled = compileProfile(profile);
  if (!compiled.ok) return compiled.code;
  if (!hasSamples(profile.mustDeny)) return 'no_must_deny';
  const unparsed = checkSamples(profile.mustDeny, (sample) => classifyForProfile(profile, sample));
  if (unparsed !== undefined) return unparsed;
  if (leakingRule(compiled.engine, profile.allow, profile.tailRules) !== undefined) return 'allow_matches_must_deny';
  return undefined;
}

function checkRelaySide(entry: PlatformEntry): RegistryFailure | undefined {
  if (entry.issuer?.capabilities().revealOnce === true && entry.lister === undefined) return 'reveal_once_without_lister';
  if (entry.relay !== undefined && entry.denyOnly !== undefined) return 'deny_only_with_relay';
  if (entry.denyOnly !== undefined && !RELAY_DENY_ONLY.includes(entry.id)) return 'deny_only_not_listed';
  if (RELAY_DENY_ONLY.includes(entry.id)) {
    if (entry.relay !== undefined) return 'deny_only_with_relay';
    if (!hasSamples(entry.denyOnly)) return 'deny_only_without_must_deny';
    const unparsed = checkSamples(entry.denyOnly ?? [], classifyDenyOnly);
    if (unparsed !== undefined) return unparsed;
  }
  if (entry.relay === undefined) return undefined;
  if (entry.relay.platform !== entry.id) return 'platform_mismatch';
  return checkRelay(entry.relay);
}

const checkEntry = (entry: PlatformEntry): RegistryFailure | undefined => checkRelaySide(entry) ?? checkShapeSource(entry) ?? checkHosts(entry) ?? checkLocationFields(entry);

/** KBOX-23: every check the box runs before it starts; the first failure names its platform. */
export function checkRegistry(entries: readonly PlatformEntry[]): RegistryCheck {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.id)) return { ok: false, code: 'duplicate_platform', platform: entry.id };
    seen.add(entry.id);
    const code = checkEntry(entry);
    if (code !== undefined) return { ok: false, code, platform: entry.id };
  }
  const repeated = checkDestinationKinds(entries);
  if (repeated !== undefined) return { ok: false, ...repeated };
  return { ok: true };
}

export class RegistryRefused extends Error {
  readonly code: RegistryFailure;
  readonly platform: string;

  constructor(code: RegistryFailure, platform: string) {
    super(`registry check failed: ${code} (${platform})`);
    this.name = 'RegistryRefused';
    this.code = code;
    this.platform = platform;
  }
}

/** Throws RegistryRefused for the first failing check: both processes call this before they listen. */
export function assertRegistry(entries: readonly PlatformEntry[]): void {
  const result = checkRegistry(entries);
  if (!result.ok) throw new RegistryRefused(result.code, result.platform);
}
