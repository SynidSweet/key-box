# Probe report: Google Cloud (KBOX-42)

Probed 2026-11-12 from an agent workstation with no credential (S-705: no admin or master key exists off the key box). No throwaway
project was used; items that need an authenticated request are listed under "Left for the box".

Authorization used where one was sent: the fake header `Bearer kbox-probe-invalid`. Made-up project `kbox-probe-none`, made-up pool and
provider `kbox-probe-nopool` / `kbox-probe-noprov` under project number `123456789012`. Discovery documents were fetched with plain GET
from `https://<api>.googleapis.com/$discovery/rest?version=<v>` (24 APIs, all 200) and matched offline.

## Items

| id | rule | request sent | answer (status and names only) | result |
|---|---|---|---|---|
| `google.sts-exchange` | KBOX-41 | `POST https://sts.googleapis.com/v1/token` form-encoded, no Authorization, fake values, one field varied per request: `grant_type`, `audience` (made-up provider), `subject_token`, `subject_token_type`, `requested_token_type`, `scope`; control `POST /v1/tokenx` | `/v1/token`: 400 JSON `{error: invalid_request, error_description}`; descriptions name `subject_token` (empty), `subject_token_type` (empty), `audience` (malformed), `grant_type` ("Unsupported grant_type" for a bogus value), `requested_token_type` (invalid value when omitted or bogus). With all five valid-shaped: 400 `{error: invalid_target}` ("pool or provider ... doesn't exist"), and `scope=https://www.googleapis.com/auth/cloud-platform` accepted without complaint. Control `/v1/tokenx`: 404. A JSON body with camelCase names (`grantType`, `subjectToken`, ...) also reached the `audience` check | VERIFIED |
| `google.generateaccesstoken-scope` | KBOX-41 | `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/x@p.iam.gserviceaccount.com:generateAccessToken` with fake `Bearer kbox-probe-invalid`, body `{"scope":["https://www.googleapis.com/auth/datastore"]}` | 401 `UNAUTHENTICATED`, ErrorInfo reason `CREDENTIALS_MISSING`, method `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken`; auth fails before the body is read, so the field is not exercised. (doc: discovery `GenerateAccessTokenRequest` has `scope` as an array, "Required", plus `lifetime`, `delegates`) | STILL UNVERIFIED |
| `google.apikeys-patch-restrictions` | KBOX-41 | `PATCH https://apikeys.googleapis.com/v2/projects/kbox-probe-none/locations/global/keys/k?updateMask=restrictions` with fake bearer, body `{}`; control `.../keysx/k` | 401 `UNAUTHENTICATED`; control 404. Path and verb exist, body fields not exercised. (doc: discovery `V2Restrictions` has `apiTargets`, `browserKeyRestrictions`, `serverKeyRestrictions`, `androidKeyRestrictions`, `iosKeyRestrictions`; `updateMask` query param, mutable `display_name`, `restrictions`, `annotations`) | STILL UNVERIFIED |
| `google.secretmanager-addversion` | KBOX-41 | `POST https://secretmanager.googleapis.com/v1/projects/kbox-probe-none/secrets/s:addVersion` with fake bearer, body `{}`; control `...:addVersionx` | 401 `UNAUTHENTICATED` (CREDENTIALS_MISSING); control 404. The verb and path exist (VERIFIED for path and method only). Body shape `{payload:{data (base64), dataCrc32c}}` is doc only (discovery `AddSecretVersionRequest`, `SecretPayload`) | VERIFIED |
| `google.jwks-cache-duration` | KBOX-41 | none: not observable without a provider and a credential | (doc: https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers says to rotate JWKS regularly and that `exp - iat` may be at most 24 hours; it gives no JWKS cache duration) | STILL UNVERIFIED |
| `google.testiampermissions-path` | KBOX-24 | `POST` with fake bearer, body `{}`, to `https://cloudresourcemanager.googleapis.com/v1/projects/kbox-probe-none:testIamPermissions`, the same under `/v3/`, and `https://iam.googleapis.com/v1/projects/kbox-probe-none/serviceAccounts/x@kbox-probe-none.iam.gserviceaccount.com:testIamPermissions`; control `...:testIamPermissionsx` | all three 401 `UNAUTHENTICATED`; control 404. So `POST {v1,v3}/projects/{project}:testIamPermissions` (cloudresourcemanager) exists, and so does the service-account form on `iam` (path VERIFIED; what it returns for an impersonated caller is not) | VERIFIED |
| `google.colon-encoding` | KBOX-41 | `POST https://firestore.googleapis.com/v1/projects/kbox-probe-none/databases/kbox-d/documents:runQuery`, then `documents%3ArunQuery`, `documents%3arunQuery`, control `documents:kboxnope`, control `documents%3Akboxnope`, all fake bearer, body `{}` | literal `documents:runQuery`: 401 `UNAUTHENTICATED` (reaches the API). `%3A` and `%3a` forms: 404 HTML page, identical to the made-up verb (both literal and encoded). So the front end does NOT decode `%3A` in the verb: it is not the same route | VERIFIED |
| `google.gocspx-length` | KBOX-41 | none: no real client secret may be sent, and no public endpoint states the length | (no doc found that states it; src/data/credential-shapes.json min 28 stays a note) | STILL UNVERIFIED |
| `google.aiza-length` | KBOX-41 | none: no real API key may be sent, and no public endpoint states the length | (no doc found that states it; src/data/credential-shapes.json min 35 stays a note) | STILL UNVERIFIED |
| `google.must-deny-discovery` | KBOX-41 | offline match of every mustDeny and allow-rule sample (method, path, template and parameter patterns) against the 24 fetched discovery documents; see "Discovery check" | 22 of 37 sample lines match a method id; 15 are NOT FOUND (listed below) | STILL UNVERIFIED |

## Facts for the adapter

- STS body is OAuth token exchange: names `grant_type` (`urn:ietf:params:oauth:grant-type:token-exchange`), `audience` (`//iam.googleapis.com/projects/{number}/locations/global/workloadIdentityPools/{pool}/providers/{provider}`; a short project id gave "Invalid value for audience"), `subject_token`, `subject_token_type` (`urn:ietf:params:oauth:token-type:jwt`), `requested_token_type` (`urn:ietf:params:oauth:token-type:access_token`), `scope`. Observed: `https://sts.googleapis.com/v1/token`. Form encoding and JSON camelCase both reached validation. Error body is `{error, error_description}`; a missing pool or provider is `invalid_target`.
- Validation order seen: `subject_token` empty, then `subject_token_type` empty, then `audience`, then `grant_type`, then `requested_token_type`. Source: observed answers above.
- Discovery doc `sts` v1 also lists `actor_token`, `actor_token_type`, `options` as optional (https://sts.googleapis.com/$discovery/rest?version=v1).
- `iamcredentials` `generateAccessToken`: path `v1/{+name}:generateAccessToken`, request fields `scope` (array, required), `lifetime`, `delegates` (https://iamcredentials.googleapis.com/$discovery/rest?version=v1).
- apikeys `PATCH v2/{+name}` takes query `updateMask` (and `checkExistingUsage`), body `V2Key`; `name` pattern `^projects/[^/]+/locations/[^/]+/keys/[^/]+$`; the answer is an `Operation`, not the key (https://apikeys.googleapis.com/$discovery/rest?version=v2). Mutable fields: `display_name`, `restrictions`, `annotations`.
- Secret Manager `addVersion`: `POST v1/{+parent}:addVersion`, parent `projects/*/secrets/*` or `projects/*/locations/*/secrets/*`; response `SecretVersion` (discovery `secretmanager` v1).
- testIamPermissions for the grant check: cloudresourcemanager v1 path `v1/projects/{resource}:testIamPermissions`, v3 `v3/projects/{projectsId}:testIamPermissions`, both POST with `TestIamPermissionsRequest`; also `iam` `v1/projects/{p}/serviceAccounts/{sa}:testIamPermissions` (discovery docs; unauthenticated 401 observed on all three).
- Firestore discovery has `runQuery` only as `v1/{+parent}:runQuery` with parent pattern `^projects/[^/]+/databases/[^/]+/documents/[^/]+/.*$` (a nested document parent), yet the root `documents:runQuery` path routes live (401 vs 404 control). `batchGet` and `commit` are present for the root. So `fs-query` as written is real for the root even though discovery does not describe it.
- Firestore `createDocument` is `POST v1/{+parent}/{collectionId}` with parent `^projects/[^/]+/databases/[^/]+/documents/.*$`; `documents/c` alone (root collection) does not match the discovery pattern, `documents/c/doc/sub` does.
- Storage upload (`gcs-upload`) is described by `storage.objects.insert` as `mediaUpload.protocols.simple.path` = `/upload/storage/v1/b/{bucket}/o`, not as a method path (discovery `storage` v1).
- Template single-segment parameters never contain `:`; `versions/1:access` matches `secretmanager.projects.secrets.versions.access` (flat path `...versions/{versionsId}:access`), not `versions.get`, once colons are excluded. The adapter's matcher must do the same.
- Front end does not percent-decode the custom-verb colon: a request path with `%3A` is a 404 HTML page. Canonicalisation (KBOX-13) must treat `%3A` as a different path, never rewrite it to `:`.
- Unauthenticated errors for Google JSON APIs: 401 `UNAUTHENTICATED`, ErrorInfo `reason: CREDENTIALS_MISSING`, with `metadata.method` and `metadata.service`; unknown routes: 404 with an HTML page (no JSON).

## Discovery check

Method: HTTP verb plus template of every method in the fetched documents (flat path preferred, path second), each parameter checked against its `pattern`. One line per sample path.

- iam (whole host, no sample path): NOT FOUND (no path to match; `iam` v1 fetched only as a control)
- iamcredentials `POST /v1/projects/-/serviceAccounts/x@p.iam.gserviceaccount.com:generateAccessToken`: iamcredentials.projects.serviceAccounts.generateAccessToken
- sts `POST /v1/token`: sts.token
- oauth2 `POST /token` (oauth2.googleapis.com): NOT FOUND (discovery `oauth2` v2 on www.googleapis.com holds only tokeninfo and userinfo)
- accounts.google.com `GET /o/oauth2/v2/auth`: NOT FOUND (not a discovery-described API)
- securetoken `POST /v1/token`: securetoken.token
- apikeys `GET /v2/projects/p/locations/global/keys`: apikeys.projects.locations.keys.list
- cloudresourcemanager `POST /v1/projects/p:getIamPolicy`: cloudresourcemanager.projects.getIamPolicy
- secretmanager `GET /v1/projects/p/secrets/s/versions/1:access`: secretmanager.projects.secrets.versions.access
- identitytoolkit `POST /v1/accounts:signInWithCustomToken`: identitytoolkit.accounts.signInWithCustomToken (v1 document; the v3 document has no match)
- firebase `GET /v1beta1/projects/p/webApps/a/config`: firebase.projects.webApps.getConfig
- run `GET /v1/projects/p`: NOT FOUND (checked run v1 and v2)
- cloudfunctions `GET /v1/projects/p`: NOT FOUND (checked v1 and v2)
- cloudbuild `GET /v1/projects/p`: NOT FOUND
- compute `GET /v1/projects/p`: NOT FOUND (compute's service path is `compute/v1/`, so the path would be `/compute/v1/projects/p`)
- appengine `GET /v1/projects/p`: NOT FOUND
- cloudscheduler `GET /v1/projects/p`: NOT FOUND
- cloudtasks `GET /v1/projects/p`: NOT FOUND (checked v2 with `/v2/projects/p` too)
- workflows `GET /v1/projects/p`: NOT FOUND
- eventarc `GET /v1/projects/p`: NOT FOUND
- pubsub `PUT /v1/projects/p/subscriptions/s`: pubsub.projects.subscriptions.create
- pubsub `PATCH /v1/projects/p/subscriptions/s`: pubsub.projects.subscriptions.patch
- storage `POST /storage/v1/projects/p/hmacKeys?serviceAccountEmail=x`: storage.projects.hmacKeys.create
- storage `GET /storage/v1/b/b/iam`: storage.buckets.getIamPolicy
- storage `PUT /storage/v1/b/b/iam`: storage.buckets.setIamPolicy
- firestore `POST /v1/projects/p/databases/d:setIamPolicy`: NOT FOUND (no `setIamPolicy` anywhere in the `firestore` v1 document)
- fs-doc `GET /v1/projects/p/databases/d/documents/{rest}` (sample `documents/c/doc`): firestore.projects.databases.documents.get
- fs-doc `POST` (sample `documents/c`): NOT FOUND (`documents/c/doc/sub` matches firestore.projects.databases.documents.createDocument; see Facts)
- fs-doc `PATCH` (sample `documents/c/doc`): firestore.projects.databases.documents.patch
- fs-doc `DELETE` (sample `documents/c/doc`): firestore.projects.databases.documents.delete
- fs-query `POST .../documents:runQuery`: NOT FOUND (discovery has only the nested-parent form; the root path routes live, see Facts)
- fs-query `POST .../documents:batchGet`: firestore.projects.databases.documents.batchGet
- fs-query `POST .../documents:commit`: firestore.projects.databases.documents.commit
- gcs-list `GET /storage/v1/b/{bucket}/o`: storage.objects.list
- gcs-object `GET /storage/v1/b/{bucket}/o/{object}`: storage.objects.get
- gcs-object `DELETE /storage/v1/b/{bucket}/o/{object}`: storage.objects.delete
- gcs-upload `POST /upload/storage/v1/b/{bucket}/o`: storage.objects.insert (as its `mediaUpload` simple path)

## Documentation read

- https://sts.googleapis.com/$discovery/rest?version=v1: request field names for `google.sts-exchange`.
- https://iamcredentials.googleapis.com/$discovery/rest?version=v1: `scope` array, required (`google.generateaccesstoken-scope`).
- https://apikeys.googleapis.com/$discovery/rest?version=v2: `V2Restrictions` field names, `updateMask` (`google.apikeys-patch-restrictions`).
- https://secretmanager.googleapis.com/$discovery/rest?version=v1: `addVersion` path and `payload.data` (`google.secretmanager-addversion`).
- https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v1 and `v3`, https://iam.googleapis.com/$discovery/rest?version=v1: testIamPermissions paths (`google.testiampermissions-path`).
- https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers: JWKS rotation advice, 24 h `exp` bound, no cache duration (`google.jwks-cache-duration`).
- Discovery documents for firestore v1, storage v1, pubsub v1, firebase v1beta1, identitytoolkit v1 and v3, securetoken v1, cloudresourcemanager, run, cloudfunctions, cloudbuild, compute, appengine, cloudscheduler, cloudtasks, workflows, eventarc, oauth2 v2 (www.googleapis.com): `google.must-deny-discovery`.

## Left for the box

- `google.generateaccesstoken-scope`: with a real impersonating token for a throwaway service account, `POST .../generateAccessToken` once with `{"scope":["https://www.googleapis.com/auth/datastore"]}` (expect 200 and a token whose tokeninfo scope is `datastore` only), once with `{}` and once with a bogus scope (expect 400 naming `scope`).
- `google.apikeys-patch-restrictions`: with an admin key on a throwaway project, create a key, `PATCH ...?updateMask=restrictions` with `{"restrictions":{"apiTargets":[{"service":"firestore.googleapis.com"}],"browserKeyRestrictions":{"allowedReferrers":["https://x.example/*"]}}}`, poll the returned `Operation`, then GET the key.
- `google.jwks-cache-duration`: on a throwaway pool, publish a JWKS, exchange, add a second key and sign with it, and time how long STS keeps answering with the stale set; repeat after removing the old one.
- `google.gocspx-length` and `google.aiza-length`: create a throwaway OAuth client and an API key on the throwaway project and measure the core lengths (record lengths only, never values).
- `google.must-deny-discovery`: decide with the spec owner whether `fs-doc` POST on a root collection, root `fs-query` `runQuery`, and the code-running host samples (`GET /v1/projects/p`, which no discovery document describes) should be replaced with paths the documents do describe; `oauth2`, `accounts.google.com` and `firestore :setIamPolicy` are not described and are mustDeny by host or name regardless. Then the row can be VERIFIED.
