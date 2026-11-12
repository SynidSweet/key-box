// KBOX-13, KBOX-47, KBOX-57: a relay origin of the kind `project-host` is one host per key, `<ref>.<domain>`, where the ref is the
// key's stored project (Supabase: 20 lower-case letters under `supabase.co`). This is the one home of what a ref and such a host are:
// the profile engine, the relay and the egress gate all ask here, so no one of them can grant a wider host than the others.
import type { Origin } from '../ports/relay-profile.ts';
import type { PlatformEntry } from '../ports/platform.ts';

export type ProjectOrigin = Extract<Origin, { readonly kind: 'project-host' }>;

export const isProjectOrigin = (origin: Origin): origin is ProjectOrigin => origin.kind === 'project-host';

/** The host an allow rule of a project-host profile names: the rule says "this domain", the request supplies the ref. */
export const projectRuleHost = (origin: ProjectOrigin): string => `*.${origin.domain}`;

const refOf = (origin: ProjectOrigin): RegExp => new RegExp(`^[a-z]{${origin.refLength}}$`);

/** `<ref>.<domain>`, or undefined when `project` is not a ref of this origin. */
export const projectHostOf = (origin: ProjectOrigin, project: string): string | undefined => (refOf(origin).test(project) ? `${project}.${origin.domain}` : undefined);

/** The ref of a host that is exactly one ref label directly under the domain, else undefined. */
export function projectOfHost(origin: ProjectOrigin, host: string): string | undefined {
  const suffix = `.${origin.domain}`;
  if (!host.endsWith(suffix)) return undefined;
  const ref = host.slice(0, host.length - suffix.length);
  return refOf(origin).test(ref) ? ref : undefined;
}

/** The project-host origins of the registered relay profiles (the egress gate's grant for caller `relay`). */
export function projectOriginsOf(registry: readonly PlatformEntry[]): ProjectOrigin[] {
  return registry.flatMap((e) => (e.relay !== undefined && isProjectOrigin(e.relay.origin) ? [e.relay.origin] : []));
}
