// KBOX-14, KBOX-41: every failure of the Google identity is one fixed code (and the HTTP status Google gave, when it gave one). No error
// here carries a platform's text, a token, a key, a target or a cause.

export type GoogleErrorCode =
  /** A request asked for an audience or subject other than the fixed ones. */
  | 'claims_fixed'
  /** The configured audience is not a workload identity provider. */
  | 'identity_malformed'
  /** The vault's value is not a 43-character base64url P-256 private scalar. */
  | 'signing_key_unreadable'
  /** The minter was built without the box's identity, the scanner's sink or the stored-record reader (the relay's registry, KBOX-3). */
  | 'identity_unconfigured'
  /** The keyref has no stored record to read the target from. */
  | 'no_key_info'
  /** The key's stored scope holds no `sa:` item, or several: the box never guesses the target. */
  | 'target_count'
  /** The `sa:` item is not `sa:<project>/<account>` with both parts in Google's id form. */
  | 'target_malformed'
  /** The `sa:` item names `kbox-keys`, the box's own admin account in every project. */
  | 'target_reserved'
  /** An admin token was asked for a location that names no project id (KBOX-57). */
  | 'bad_location'
  /** A relay token was asked with `cloud-platform`. */
  | 'cloud_platform_for_relay'
  /** A relay token was asked with a scope its profile does not name. */
  | 'scope_not_in_profile'
  /** A scope is not a full `https://www.googleapis.com/auth/<name>` URL, is repeated, or none was asked. */
  | 'scope_malformed'
  /** STS answered 4xx: the assertion, audience or provider was not accepted. */
  | 'sts_refused'
  /** STS answered anything else that is not a token. */
  | 'sts_failed'
  /** IAM Credentials answered 4xx: no Token Creator on the target, or the federated token refused. */
  | 'impersonation_refused'
  /** IAM Credentials answered anything else that is not a token. */
  | 'impersonation_failed'
  /** Cloud Resource Manager did not answer testIamPermissions with 200. */
  | 'permissions_failed'
  /** A 200 whose body is not the documented shape. */
  | 'bad_answer'
  /** No answer came (any transport failure of the adapter's HTTP client). */
  | 'unreachable';

export class GoogleError extends Error {
  readonly code: GoogleErrorCode;
  readonly status: number | undefined;

  constructor(code: GoogleErrorCode, status?: number) {
    super(status === undefined ? `google: ${code}` : `google: ${code} (${status})`);
    this.name = 'GoogleError';
    this.code = code;
    this.status = status;
  }
}
