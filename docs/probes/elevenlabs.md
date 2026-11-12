# Probe report: ElevenLabs (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `elevenlabs.key-format` | KBOX-39 | none: needs a credential (an unauthenticated request cannot show a key's length) | (doc: https://api.elevenlabs.io/openapi.json names the header `xi-api-key` and the create response field `xi-api-key`, with no format or length stated) | STILL UNVERIFIED |
| `elevenlabs.permission-enum` | KBOX-39 | none: names live in the official OpenAPI file, not in a live answer (unauthenticated `GET https://api.elevenlabs.io/openapi.json` and the `api.us` copy returned byte-identical files) | (doc: schema `PermissionType` in that file, 54 names, listed under "Facts for the adapter"; a doc alone does not verify) | STILL UNVERIFIED |
| `elevenlabs.verifier-call` | KBOX-39 | `GET https://api.elevenlabs.io/v1/models`, `GET .../v1/user`, `GET .../v1/zzz-nothing` with header `xi-api-key: kbox-probe-invalid`; `GET .../v1/models` with no key; the same four on `https://api.us.elevenlabs.io` | both hosts identical: fake key on `/v1/models` and `/v1/user`: 401, JSON `{detail: {type, code, message, status, request_id}}` with `status` `invalid_api_key`, `code` `unauthorized`; no key on `/v1/models`: 404 with `status` `workspace_not_found` (not a 401); made-up path: 404 `{detail: "Not Found"}`. A fake key is not a revoked key, so the live-versus-revoked difference was not observed | STILL UNVERIFIED |
| `elevenlabs.service-account-list` | KBOX-39 | none: needs a credential (an unauthenticated request cannot read a workspace) | (doc: openapi.json names `GET /v1/service-accounts` and the key operations; the adapter reads `{"service-accounts":[{service_account_user_id, name, "api-keys":[{key_id, name, is_disabled}]}]}` from it, and `locateKey`, `list`, `listAt` and `revoke` lean on that shape; the list is read as one document with no pages; no live answer seen) | STILL UNVERIFIED |
| `elevenlabs.empty-permissions` | KBOX-39 | none: needs a credential (creating a key) | (doc: `permissions` is an array of `PermissionType` or the string `all`; what an EMPTY array means, no permission or all, is not stated; the adapter sends `[]` for a scope that names none and classes that key ordinary) | STILL UNVERIFIED |

## Facts for the adapter

- Both regional hosts, `https://api.elevenlabs.io` and `https://api.us.elevenlabs.io`, answer unauthenticated requests the same way (401 `invalid_api_key` for a bad key). Observed. The OpenAPI file is identical on both hosts. Region is therefore per-key config, not a different API.
- Auth header is `xi-api-key` (not `Authorization`). Source: openapi.json parameters on every operation.
- A request with NO key header is not a 401: it returns 404 `workspace_not_found` (message names an anonymous workspace). The verifier must treat only 401 `status: invalid_api_key` as "key rejected"; 404 means the header was not sent. Observed.
- Error shape: `{detail: {type, code, message, status, request_id}}`, `detail` is the string `Not Found` for an unknown route. Observed.
- Create key: `POST /v1/service-accounts/{service_account_user_id}/api-keys`; body required `name` (string), `permissions` (array of `PermissionType` or the string `all`); optional `character_limit` (integer or null), `allowed_ips` (1..100 strings, CIDR or bare IP), `third_party_disable_allowed` (boolean or null), `tts_concurrency_limit`, `dubbing_concurrency_limit`, `music_concurrency_limit` (integer or null; enterprise only), `expires_at_unix` (integer or null; 15 minutes to 90 days ahead). Response `WorkspaceCreateApiKeyResponseModel`: required `xi-api-key`, `key_id`. Source: openapi.json (doc-only).
- Other service-account operations: `GET .../api-keys` (`get_service_account_api_keys_route`), `PATCH` and `DELETE .../api-keys/{api_key_id}`, `POST .../api-keys/{api_key_id}/disable`, plus `GET|POST /v1/service-accounts`. Source: openapi.json.
- `PermissionType` enum, all 54 names, with a classification by NAME ONLY (the file gives no categories, so the classes are the adapter author's reading; ratify before relying on them):
  - workspace (master by KBOX-39): `workspace_read`, `workspace_write`, `workspace_analytics_full_read`, `workspace_members_read`, `workspace_members_invite`, `workspace_members_remove`, `group_members_manage`, `audit_log_read`, `copy_resources_cross_workspace`.
  - service-account (master): `service_account_write`.
  - key-management (master): `create_user_api_key`.
  - doubtful, workspace-wide effect by name but not clearly "workspace" permissions (decide at ratification): `webhooks_write`, `conversation_privacy_manage`, `terms_of_service_accept`, `share_voice_externally`, `publish_voice_to_voice_library`.
  - other (ordinary): `text_to_speech`, `speech_to_speech`, `speech_to_text`, `models_read`, `models_write`, `voices_read`, `voices_write`, `voice_collections_read`, `voice_collections_write`, `speech_history_read`, `speech_history_write`, `sound_generation`, `audio_isolation`, `voice_generation`, `dubbing_read`, `dubbing_write`, `pronunciation_dictionaries_read`, `pronunciation_dictionaries_write`, `user_read`, `user_write`, `projects_read`, `projects_write`, `audio_native_read`, `audio_native_write`, `forced_alignment`, `convai_read`, `convai_write`, `agents_architect`, `agents_environment_variables_write`, `music_generation`, `image_video_generation`, `flows`, `templates`, `add_voice_from_voice_library`, `create_instant_voice_clone`, `create_professional_voice_clone`, `synthid_detector`, `watermark`.
  - Source: schema `PermissionType` (a plain string enum) in https://api.elevenlabs.io/openapi.json. The list can grow; the unit should read the enum and fail closed (unknown name counts as master).
- Verifier candidates: `GET /v1/user` (needs permission `user_read` by name) or `GET /v1/models` (`models_read` by name); both returned the same 401 to a fake key. A restricted key may be refused by permission rather than by validity, so the permission required for a verifier call is unobserved; the box must test with a restricted key.

## Documentation read

- https://api.elevenlabs.io/openapi.json (and the `api.us` copy, identical): create-key body and response, permission enum (`elevenlabs.permission-enum`), operations of the service-account family; no key format (`elevenlabs.key-format`).

## Left for the box

- `elevenlabs.key-format`: create a key in a throwaway service account and record the prefix and length of `xi-api-key` (length only, never the value), on both regions if both are used.
- `elevenlabs.permission-enum`: confirm against a live create call that an unknown permission name is refused (400/422, names the field `permissions`) and that every enum name above is accepted by a key with `workspace_write`; compare with the OpenAPI list at that time.
- `elevenlabs.verifier-call`: with a throwaway key, `GET /v1/user` expects 200; then `DELETE .../api-keys/{api_key_id}` and repeat; record the revoked status and `detail.status` (expected 401 `invalid_api_key`, unconfirmed). Repeat with a key lacking `user_read` to see its refusal status.
- `elevenlabs.service-account-list`: with the master, `GET /v1/service-accounts` on each region; record the field names and whether the list is paged (names only, never a key value).
- `elevenlabs.empty-permissions`: create a key with `permissions: []` in a throwaway service account and read the key back; record whether it can call anything (an empty list that means all would make the key wider than its class).
