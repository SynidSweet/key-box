# Probe report: Anthropic (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `anthropic.models-verify` | KBOX-40 | `GET https://api.anthropic.com/v1/models` with no key; again with header `x-api-key: kbox-probe-invalid` and `anthropic-version: 2023-06-01` | 401 both times, JSON `{type, error:{type, message}, request_id}`; `error.type` is `authentication_error`; message says the header is required (no key) or the key is invalid (fake key). A 200 for a valid key not observed | STILL UNVERIFIED |
| `anthropic.revoked-key-answer` | KBOX-40 | none possible: a revoked key is a once-valid key; fake key above got the same shape | (observed for a fake key only: 401 `authentication_error`; whether a revoked key differs is not observable) | STILL UNVERIFIED |
| `anthropic.key-list-status-filter` | KBOX-40 | `GET https://api.anthropic.com/v1/organizations/api_keys?status=active&limit=1` with `x-api-key: kbox-probe-invalid` | 401 `authentication_error`, "invalid x-api-key". A made-up sibling `/v1/organizations/api_keyz` gave the identical 401, so auth is checked before routing and the path and the filter are NOT distinguished by a live answer (doc: SDK lists `status` as active, archived, expired, inactive) | STILL UNVERIFIED |
| `anthropic.key-retire-statuses` | KBOX-40 | `POST https://api.anthropic.com/v1/organizations/api_keys/apikey_probe` body `{"status":"inactive"}` with `x-api-key: kbox-probe-invalid` | 401 `authentication_error`, "invalid x-api-key" (same as for a made-up path; no route evidence). Doc: SDK update accepts `status` of active, archived, inactive | STILL UNVERIFIED |
| `anthropic.key-formats` | KBOX-40 | none: a format cannot be seen without a key | (no doc states core lengths; the SDK only has the `partial_key_hint` field on a listed key) | STILL UNVERIFIED |
| `anthropic.key-page` | KBOX-40 | `GET https://console.anthropic.com/settings/keys` and `https://platform.claude.com/settings/keys`, `.../settings/admin-keys` (no cookies, status only) | console.anthropic.com: 301 to `https://platform.claude.com/settings/keys`; platform.claude.com settings/keys and settings/admin-keys: 200 (a page is served; login happens client-side, so the page content for the owner is not seen) | STILL UNVERIFIED |

## Facts for the adapter

- Verify and list calls send `x-api-key: <key>` and `anthropic-version: 2023-06-01` (observed: missing header gives 401 "x-api-key header is required"). Error body shape `{type:"error", error:{type, message}, request_id}` observed on `/v1/models` and `/v1/organizations/api_keys`.
- A bad or missing key is 401 `authentication_error` on every path tried, including made-up ones (auth precedes routing), so a 401 never tells path-wrong from key-bad. Source: observed.
- `GET /v1/models` takes `limit` (SDK `model_list_params.py`); `limit=1` keeps the verify call small. Source: https://github.com/anthropics/anthropic-sdk-python/blob/main/src/anthropic/types/model_list_params.py
- `GET /v1/organizations/api_keys` params: `after_id`, `before_id`, `created_by_user_id`, `limit` (default 20, 1 to 1000), `status` (active, archived, expired, inactive), `workspace_id`. Listed key fields: `id`, `created_at`, `created_by`, `expires_at`, `name`, `partial_key_hint`, `principal`, `scope`, `status`, `type` ("api_key"). Source: SDK `resources/organization/api_keys.py` and `types/organization/api_key.py` (anthropics/anthropic-sdk-python, main).
- `POST /v1/organizations/api_keys/{api_key_id}` body `name` and `status` (active, archived, inactive), both optional. Source: same SDK file. `expired` is list-only, not settable.
- The listed key never carries the full secret, only `partial_key_hint`: the adapter matches a pasted key to a listed id by hint, not by value (doc).
- `sk-ant-o...` login tokens are out of scope (spec).

## Documentation read

- https://github.com/anthropics/anthropic-sdk-python (`resources/organization/api_keys.py`, `types/organization/api_key.py`, `api_key_list_params.py`, `resources/models.py`): settle paths and param names for `anthropic.key-list-status-filter`, `anthropic.key-retire-statuses`; suggest `anthropic.models-verify`. Doc evidence only.
- https://platform.claude.com/docs/en/api/beta/organization/api_keys/update.md: the update page exists (redirect target), no further reading.

## Left for the box

- `anthropic.models-verify`: `GET /v1/models?limit=1` with the real ordinary key must give 200; the same call with the key after revocation must give 401 (record the `error.type`). Compare against `GET /v1/models/{id}` for cost.
- `anthropic.revoked-key-answer`: retire a throwaway key through the admin key, then repeat the verify call and record status and `error.type`.
- `anthropic.key-list-status-filter`: with the admin key, `GET /v1/organizations/api_keys?status=active&limit=1`, then `status=inactive`; record 200 and the field names, and that the filter changes the result.
- `anthropic.key-retire-statuses`: with the admin key and a throwaway key id, `POST /v1/organizations/api_keys/{id}` with `{"status":"inactive"}`, then `{"status":"archived"}`; record both statuses and whether the archived one can be listed.
- `anthropic.key-formats`: shape-check (prefix and length only, never the value) a throwaway ordinary key and a throwaway admin key on the box.
- `anthropic.key-page`: the owner opens `https://platform.claude.com/settings/keys` (ordinary) and `https://platform.claude.com/settings/admin-keys` (admin) logged in and confirms each is where a key is made.
