# Probe report: Stripe (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `stripe.restricted-keys-dashboard-only` | KBOX-40 | `GET` and `POST https://api.stripe.com/v1/api_keys`, `GET /v1/restricted_keys`, `GET /v1/apikeys` with basic auth user `kbox-probe-invalid` | 404 each, JSON `{error:{message,type}}`, type `invalid_request_error`, message "Unrecognized request URL". The 404 comes even though the key is fake, so these routes do not exist. Doc: the public OpenAPI spec (stripe/openapi spec3.json) has no path with "key" except `/v1/ephemeral_keys` and `/v1/ephemeral_keys/{key}` (for client-side access, not account keys); docs.stripe.com/keys.md and keys/restricted-api-keys.md describe creation only through the Dashboard. A negative cannot be proven from outside, and a private or OAuth path is not excluded | STILL UNVERIFIED |
| `stripe.rk-live-format` | KBOX-40 | none: a format cannot be seen without a key | (doc: https://docs.stripe.com/keys/restricted-api-keys.md says a restricted key starts with `rk_live_` or `rk_test_`; no length is documented) | STILL UNVERIFIED |
| `stripe.verify-calls` | KBOX-40 | `GET https://api.stripe.com/v1/balance`, `/v1/customers?limit=1`, `/v1/charges?limit=1`, `/v1/products?limit=1`, `/v1/account` with fake basic-auth user `kbox-probe-invalid` | 401 each, `{error:{message,type}}`, type `invalid_request_error`, message "Invalid API Key provided: <masked>"; so all five routes exist (a 404 would have shown otherwise). Which permission each needs is doc only, and a permitted-versus-forbidden answer needs a real restricted key | STILL UNVERIFIED |
| `stripe.invalid-key-answer` | KBOX-40 | `GET https://api.stripe.com/v1/balance` with no key; again with fake basic-auth user `kbox-probe-invalid` | no key: 401 `invalid_request_error`, message "You did not provide an API key". Fake key: 401 `invalid_request_error`, "Invalid API Key provided". A revoked real key's answer not observed | STILL UNVERIFIED |
| `stripe.key-page` | KBOX-40 | `GET https://dashboard.stripe.com/apikeys` and `/apikeys/create` (no cookies, status only) | 303 to `https://dashboard.stripe.com/login?redirect=%2Fapikeys` (and `...%2Fapikeys%2Fcreate`). The URL exists; the "Create restricted key" button is described by doc only | STILL UNVERIFIED |

## Facts for the adapter

- Auth: HTTP basic with the key as user and empty password (curl `-u key:`), or `Authorization: Bearer <key>`. Observed answer text names Bearer. Source: https://api.stripe.com/v1/balance no-key answer.
- Both bad-key and no-key are 401 with `error.type` `invalid_request_error` (not `authentication_error`); the adapter must key on status 401 plus the message start "Invalid API Key provided", not on the type. Source: observed.
- Unknown path is 404 "Unrecognized request URL" before auth, so unlike Anthropic a 404 here does separate a missing route from a bad key. Source: observed.
- Candidate cheap read calls, all single-GET with `limit=1` where listing: `/v1/balance` (permission "Balance: read"), `/v1/customers` ("Customers: read"), `/v1/charges` ("Charges and Refunds: read"), `/v1/products` ("Products: read"), `/v1/prices` ("Prices: read"), `/v1/account` (no dedicated permission documented; may work for any key). Route existence observed or in the OpenAPI spec (`/v1/balance`, `/v1/customers`, `/v1/products`, `/v1/prices`, `/v1/account` present); permission names are from my reading of the Dashboard wording, not fetched, so treat as unconfirmed. A key lacking permission is expected to get 403 `invalid_request_error` naming the missing permission (doc, unobserved).
- Restricted key permissions are None, Read or Write per resource, set in the Dashboard. Source: https://docs.stripe.com/keys/restricted-api-keys.md.
- Stripe lists a restricted key's value only once in live mode and the box cannot re-reveal it (doc: https://docs.stripe.com/keys.md).

## Documentation read

- https://docs.stripe.com/keys.md: `rk_live_` prefix, Dashboard API keys page, live key shown once; settles nothing live for `stripe.restricted-keys-dashboard-only`, `stripe.rk-live-format`.
- https://docs.stripe.com/keys/restricted-api-keys.md: creation by "Create restricted key" on https://dashboard.stripe.com/apikeys; `stripe.key-page`, `stripe.restricted-keys-dashboard-only`.
- https://docs.stripe.com/keys-best-practices.md: rotation guidance, no key-management API mentioned.
- https://github.com/stripe/openapi (openapi/spec3.json): path list for `stripe.restricted-keys-dashboard-only` and `stripe.verify-calls`.

## Left for the box

- `stripe.restricted-keys-dashboard-only`: the owner confirms in the Dashboard that no API or OAuth route rolls a restricted key; nothing a box request can add.
- `stripe.rk-live-format`: shape-check (prefix and length only) a real restricted key pasted on the box.
- `stripe.verify-calls`: with a restricted key limited to one permission, call each candidate and record which return 200 and which 403 (and the 403 message field names).
- `stripe.invalid-key-answer`: repeat `GET /v1/balance` with a key the owner has deleted in the Dashboard; record status and `error.type`.
- `stripe.key-page`: the owner, logged in, confirms `https://dashboard.stripe.com/apikeys` has the "Create restricted key" button.
