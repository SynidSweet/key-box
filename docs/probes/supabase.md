# Probe report: Supabase (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

Only `https://api.supabase.com` (the Management API) was contacted, with no `Authorization` header or `Bearer kbox-probe-invalid`, and the made-up project ref
`abcdefghijklmnopqrst`. No `<ref>.supabase.co` host was contacted. Result: nothing could be VERIFIED (see the first Fact).

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `supabase.pat-create-by-api` | KBOX-37 | `POST https://api.supabase.com/v1/access-tokens` body `{}`, once with no header and once with fake bearer (this path is a guess: it is not in the OpenAPI file) | 401 `{message}`: "No access token provided" / "JWT could not be decoded"; the same answer comes for a made-up `/v1/zzz-madeup`, so it says nothing about the path | STILL UNVERIFIED |
| `supabase.reveal-on-create` | KBOX-37 | `POST https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/api-keys?reveal=true` body `{}`, fake bearer | 401 `{message}` "JWT could not be decoded"; auth runs before validation | STILL UNVERIFIED |
| `supabase.reveal-on-get` | KBOX-37 | `GET https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/api-keys/22222222-2222-4222-8222-222222222222?reveal=true` and `.../api-keys?reveal=true`, fake bearer | 401 `{message}` "JWT could not be decoded" | STILL UNVERIFIED |
| `supabase.edge-secrets-get-value` | KBOX-37 | `GET https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/secrets`, no header and fake bearer | 401 `{message}`; (doc: OpenAPI `SecretResponse_Output` has `name`, `value` (required), `updated_at`) | STILL UNVERIFIED |
| `supabase.relay-allow-postgrest-tables` | KBOX-37 | none: project host, off limits | (doc: self-hosted kong.yml routes `/rest/v1/` to PostgREST with `strip_path`; PostgREST docs) | STILL UNVERIFIED |
| `supabase.relay-allow-rpc` | KBOX-37 | none: project host, off limits | (doc: same `/rest/v1/` route covers `/rest/v1/rpc/<fn>`) | STILL UNVERIFIED |
| `supabase.relay-allow-storage-objects` | KBOX-37 | none: project host, off limits | (doc: kong.yml route `/storage/v1/` to storage:5000; Storage API docs) | STILL UNVERIFIED |
| `supabase.relay-allow-storage-list` | KBOX-37 | none: project host, off limits | (doc: same route; `POST /storage/v1/object/list/<bucket>` is in the Storage API docs) | STILL UNVERIFIED |
| `supabase.relay-deny-auth` | KBOX-37 | none: project host, off limits | (doc: kong.yml route `/auth/v1/` to auth:9999) | STILL UNVERIFIED |
| `supabase.relay-deny-pg` | KBOX-37 | none: project host, off limits | (doc: kong.yml route `/pg/` to pg-meta:8080; self-hosted only, hosted exposure unknown) | STILL UNVERIFIED |
| `supabase.relay-deny-graphql` | KBOX-37 | none: project host, off limits | (doc: kong.yml route `/graphql/v1` to `rest:3000/rpc/graphql`) | STILL UNVERIFIED |
| `supabase.relay-deny-functions` | KBOX-37 | none: project host, off limits | (doc: kong.yml route `/functions/v1/` to functions:9000) | STILL UNVERIFIED |
| `supabase.relay-deny-storage-sign` | KBOX-37 | none: project host, off limits | (doc: Storage API docs list `/object/sign/`; kong.yml only has the `/storage/v1/` prefix) | STILL UNVERIFIED |
| `supabase.relay-deny-storage-upload-sign` | KBOX-37 | none: project host, off limits | (doc: Storage API docs list `/object/upload/sign/`; kong.yml only has the prefix) | STILL UNVERIFIED |
| `supabase.relay-deny-storage-bucket` | KBOX-37 | none: project host, off limits | (doc: Storage API `/bucket` routes; kong.yml only has the prefix) | STILL UNVERIFIED |
| `supabase.relay-deny-realtime` | KBOX-37 | none: project host, off limits | (doc: kong.yml routes `/realtime/v1/` and `/realtime/v1/api`) | STILL UNVERIFIED |
| `supabase.relay-deny-rest-root` | KBOX-37 | none: project host, off limits | (doc: kong.yml has a separate `rest-v1-openapi` service for the exact `/rest/v1/` root, served by PostgREST) | STILL UNVERIFIED |
| `supabase.relay-deny-profile-headers` | KBOX-37 | none: project host, off limits | (doc: PostgREST schemas docs: `Accept-Profile` for GET/HEAD, `Content-Profile` for other methods; absent header means the first schema in `db_schema`) | STILL UNVERIFIED |
| `supabase.sb-secret-length` | KBOX-37 | none: a key can only be seen by creating one | (doc: OpenAPI example `sb_secret_live_example_9f4d3a206b2e4a7e8c91` is an illustration, not a length) | STILL UNVERIFIED |
| `supabase.project-get-shape` | KBOX-57 | none sent: it needs a personal access token, and none exists off the box (S-705); added 2026-11-13 for the location prover | (not observed; the prover reads 200 naming the asked `ref` (or `id`) as seen, 403 and 404 as unseen, anything else as a failure) | STILL UNVERIFIED |
| `supabase.pat-verify` | KBOX-37, KBOX-58 | none sent: it needs a personal access token, and none exists off the box (S-705); added 2026-11-13 for the master verifier | (not observed; the verifier reads `GET /v1/projects` 200 with a JSON array as ok, 401 with the `{message}` error object as rejected, anything else as unreachable) | STILL UNVERIFIED |
| `supabase.pat-shape` | KBOX-37, KBOX-58 | none: a token can only be seen in the dashboard | (assumed from the Supabase CLI: `sbp_` and 40 hex characters; never observed) | STILL UNVERIFIED |

## Facts for the adapter

- The Management API checks authentication before routing and validation: an unknown path (`/v1/zzz-madeup`) and a real one give the same 401, so 404-versus-401 probing cannot show that a path exists (observed, `https://api.supabase.com`). 401 bodies are `{message}` only: "No access token provided" (no header), "JWT could not be decoded" (fake bearer).
- `GET /v1/projects/{ref}/api-keys/{id}` also takes the `reveal` query (OpenAPI parameters), as do `POST` and `GET` list. `reveal` is a "boolean string": true values `true 1 yes on y enabled`, false values `false 0 no off n disabled` (https://api.supabase.com/api/v1-json).
- `ApiKeyResponse_Output`: `api_key` (nullable string), `id` (nullable), `type` (`legacy|publishable|secret|null`), `prefix`, `name` (the only non-nullable), `description`, `hash`, `secret_jwt_template`, `inserted_at`, `updated_at`. `ref` is 20 characters `^[a-z]+$`; `id` is a UUID (same file).
- `CreateApiKeyBody`: `type` (`publishable|secret`) and `name` required; `name` 4-64 characters `^[a-z_][a-z0-9_]+$`; `description`, `secret_jwt_template` nullable (same file).
- Edge secrets: `CreateSecretBody` is an ARRAY (max 100) of `{name, value}`; `name` max 256, `^(?!SUPABASE_).*`; `value` max 24576. `DeleteSecretsBody` is an array of names. `GET` responses listed: 200, 401, 403, 429, 500 (same file). So 429 is a rate-limit status to handle.
- No endpoint for creating a personal access token exists in the OpenAPI file: the only token-related paths are `/v1/oauth/token`, `/v1/projects/{ref}/claim-token` and `/v1/organizations/{slug}/project-claim/{token}`; `/v1/profile` is the nearest account path. This is doc evidence for "dashboard-only" but not VERIFIED.
- The OAuth route `/v1/oauth/token` takes `grant_type` of `authorization_code`, `refresh_token` or the jwt-bearer grant (Team and Enterprise only, no refresh token), a possible alternative master if PAT paste is unwanted (OpenAPI `OAuthTokenBody`).
- Self-hosted kong.yml (https://raw.githubusercontent.com/supabase/supabase/master/docker/volumes/api/kong.yml) routes by prefix: `/auth/v1/`, `/rest/v1/`, `/graphql/v1`, `/realtime/v1/`, `/storage/v1/`, `/functions/v1/`, `/pg/`, plus `/mcp` and a blocked `/api/mcp`. It is the self-hosted gateway, so hosted behaviour (including whether `/pg/` is reachable) is unconfirmed. Storage sub-paths (`sign`, `upload/sign`, `bucket`) are not distinguished by the gateway; they are the Storage service's own routes.
- Consequence for the relay: because the gateway forwards by prefix, the relay must match path segments itself after normalising (case, `//`, `%2e`, trailing slash) and treat anything not on the allow list as deny; the mustDeny list is a belt on top of default-deny.

## Documentation read

- https://api.supabase.com/api/v1-json: api-keys schemas and `reveal` parameter (`reveal-on-create`, `reveal-on-get`), secrets schema (`edge-secrets-get-value`), absence of a PAT endpoint (`pat-create-by-api`).
- https://raw.githubusercontent.com/supabase/supabase/master/docker/volumes/api/kong.yml: gateway prefixes for every `relay-allow-*` and `relay-deny-*` path item (self-hosted only).
- PostgREST schemas docs and Storage API docs were not fetched in this run; the `Accept-Profile` / `Content-Profile` row rests on general knowledge of PostgREST and must be re-read by the adapter coder.

## Left for the box

- `supabase.pat-create-by-api`: with a PAT, `POST https://api.supabase.com/v1/access-tokens` (guessed path) body `{name:"kbox-probe"}`; a 404/405 against 401-with-valid-PAT would settle it. Also compare the dashboard's network call.
- `supabase.reveal-on-create`: against a throwaway project, `POST /v1/projects/{ref}/api-keys?reveal=true` and again with `reveal=false`, `type:"secret"`, name `kbox_probe`; record whether `api_key` is a full key, masked, or null, by names and by length only.
- `supabase.reveal-on-get`: `GET /v1/projects/{ref}/api-keys/{id}` with and without `reveal=true` on that key; record whether `api_key` is full, masked or null.
- `supabase.edge-secrets-get-value`: `POST /v1/projects/{ref}/secrets` with a canary name `KBOX_PROBE` and a throwaway value, then `GET`; record whether `value` equals the canary or looks like a digest (length only), then `DELETE`.
- `supabase.relay-*` and `supabase.relay-deny-profile-headers`: on a throwaway project, send each sample path with the fake and the real publishable key through the key box relay's upstream, and with `Accept-Profile` / `Content-Profile` set to `public` and to another schema; record status only.
- `supabase.sb-secret-length`: create several secret keys on the throwaway project and record the lengths of `api_key` (length only, never the value).
- `supabase.project-get-shape`: with a PAT, `GET /v1/projects/{ref}` for the throwaway project (record status and whether the body names it as `ref` or `id`), for a made-up 20-letter ref, and for a project of another account (record each status: 404 or 403); names only.
- `supabase.pat-verify`: at the first real paste of the master, record the status and body kind (array or not) of `GET /v1/projects`; after the first master rotation, the same for the old token once the owner has ended it (status and whether the body is `{message}`), names only.
- `supabase.pat-shape`: at the first paste, the box records whether the token matched `sbp_` and 40 hex (a `bad_shape` refusal says it did not); the owner answers by format only, never the token.
