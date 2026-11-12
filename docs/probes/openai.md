# Probe report: OpenAI (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `openai.admin-key-length` | KBOX-38 | none: needs a credential | (doc: openai-openapi `main` openapi.yaml shows only the masked examples `sk-admin-1234abcd`, `sk-admin...def`; no full-length key) | STILL UNVERIFIED |
| `openai.svcacct-key-length` | KBOX-38 | none: needs a credential | (doc: the same file has no `sk-svcacct-` example at all; the create example shows `value: sk-abcdefghijklmnop123`, an obvious placeholder) | STILL UNVERIFIED |
| `openai.create-key-path` | KBOX-38 | `POST https://api.openai.com/v1/organization/projects/proj_x/service_accounts/svc_acct_x/api_keys` with header `Authorization: Bearer kbox-probe-invalid` and body field `name` (fake); sibling paths `.../api_keyz` and `.../zzz_keys` as controls | real path: 401, JSON `{error: {message, type, param, code}}`, code `invalid_api_key` (auth is checked, so the route exists); both made-up siblings: 404, empty body. Path and method VERIFIED; body fields `name`, `expires_in_seconds`, `scopes` and response field `value` are doc-only (see `openai.create-key-body`) | VERIFIED |
| `openai.create-key-body` | KBOX-38 | none: needs an admin credential | (doc: openai-openapi `main` openapi.yaml, schemas `CreateProjectServiceAccountApiKeyBody` and `ServiceAccountApiKeyBody`, matches the spec's names) | STILL UNVERIFIED |
| `openai.verifier-call` | KBOX-38 | `GET https://api.openai.com/v1/models` with `Authorization: Bearer kbox-probe-invalid`; also with no header; also `GET .../v1/organization/projects/proj_x/api_keys` with the fake bearer | all three: 401, JSON `{error: {message, type, param, code}}`; fake bearer gives code `invalid_api_key` (message quotes the key masked as `kbox-pro******alid`), no header gives code null and message "Missing bearer authentication in header". A fake key is not a revoked key, so what a revoked real key gets was not observed | STILL UNVERIFIED |

## Facts for the adapter

- Create service-account key: `POST /v1/organization/projects/{project_id}/service_accounts/{service_account_id}/api_keys`; body `name` (string), `scopes` (array of strings), `expires_in_seconds` (integer 1..31536000, or null); no field is marked required. Response (200): `object` (`organization.project.service_account.api_key`), `value` (the unredacted key), `name`, `created_at`, `expires_at` (integer or null), `id`. Error statuses: 400 (invalid or archived project), 403, 404 (project or service account), 429. Security `AdminApiKeyAuth`. Source: https://raw.githubusercontent.com/openai/openai-openapi/main/openapi.yaml (doc-only except the path's existence, observed).
- The older published branch `manual_spec` (https://raw.githubusercontent.com/openai/openai-openapi/manual_spec/openapi.yaml) does NOT contain this path (nor `scopes`); only `main` does. The live service nevertheless routes it (401 vs 404 above). Use `main` as the reference.
- Revoke: `DELETE /v1/organization/projects/{project_id}/api_keys/{api_key_id}`; list: `GET /v1/organization/projects/{project_id}/api_keys`; both paths exist in `main` (the list route answered 401 to the fake bearer). Source: same file.
- Create service account: `POST /v1/organization/projects/{project_id}/service_accounts` uses schema `ProjectServiceAccountCreateRequest`; response is `ProjectServiceAccountCreateResponse` (carries `api_key`). Source: same file (doc-only).
- Auth failure shape: 401 with `{error: {message, type: "invalid_request_error", param: null, code}}`; code `invalid_api_key` for a bad bearer, null for a missing one. Observed. The error message quotes the sent key masked (first 8 and last 4 characters kept), the KBOX-14 case.
- Unknown route under `/v1/organization/...`: 404 with empty body. Observed.
- Verifier candidate: `GET /v1/models` (cheap, no body). Caveat: a restricted project key lacking model read scope may get 403 instead of 200, which still means "key accepted"; the box must test this with a restricted throwaway key.

## Documentation read

- https://raw.githubusercontent.com/openai/openai-openapi/main/openapi.yaml: create-key path, request and response schemas (`openai.create-key-path`, `openai.create-key-body`); masked admin-key examples only (`openai.admin-key-length`, `openai.svcacct-key-length`).
- https://raw.githubusercontent.com/openai/openai-openapi/manual_spec/openapi.yaml: lacks the create-key path; the stale branch (`openai.create-key-path`).

## Left for the box

- `openai.admin-key-length`: create or list an admin key through the owner's admin key and record the exact length of the `sk-admin-` value (length only, never the value).
- `openai.svcacct-key-length`: create a service account in a throwaway project and record the length of the returned `api_key` and of a key from `.../api_keys` `value` (lengths only).
- `openai.create-key-body`: `POST .../service_accounts/{id}/api_keys` with `name`, `expires_in_seconds`, `scopes`, in a throwaway project; confirm status 200 and response field names `value`, `id`, `expires_at`.
- `openai.verifier-call`: with a throwaway project key, `GET /v1/models` expects 200; then `DELETE .../api_keys/{id}` and repeat; record the revoked status and `error.code` (expected 401, unconfirmed). Repeat once with a restricted-scope key.
