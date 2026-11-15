/** The only place that composes an origin of the box (design 3.3): one host name, the phone's pages on one port, the machine API on 443. */

export const PAGES_PORT = 8443;

/** The phone pages' origin: `https://<host>:<port>`. */
export function pagesOrigin(host: string, port: number = PAGES_PORT): string {
  return `https://${host}:${port}`;
}

/** The machine API and relay origin: `https://<host>`. */
export function machineOrigin(host: string): string {
  return `https://${host}`;
}

/** The relay URL of a key: `https://<host>/r/<address>`. */
export function relayUrl(host: string, address: string): string {
  return `${machineOrigin(host)}/r/${address}`;
}

/** The box's OIDC issuer: an identifier only, nobody fetches it. */
export function oidcIssuer(host: string): string {
  return machineOrigin(host);
}

/** The web-push subject. */
export function pushSubject(host: string): string {
  return machineOrigin(host);
}
