// KBOX-56: the version-0 table statements of meta.db that db.ts does not own: the rotation store's and the paste tasks'. Release 1's text, moved verbatim and never edited:
// a change to a table is a migration in migrations.ts. This file imports nothing, so any opener can run it.
const RUN_STATES ="('issuing','verifying','pushing','redeploying','checking','promoting','grace','revoking','rolling_back','done','failed','abandoned')";

export const ROTATION_SCHEMA_V0 = `
  CREATE TABLE IF NOT EXISTS rotation_keys (
    keyref TEXT PRIMARY KEY REFERENCES keys (keyref),
    scope_json TEXT NOT NULL,
    region TEXT,
    project TEXT,
    rotated_at INTEGER NOT NULL,
    mark_admin INTEGER NOT NULL DEFAULT 0 CHECK (mark_admin IN (0, 1))
  ) STRICT;
  CREATE TABLE IF NOT EXISTS rotation_runs (
    run_id TEXT PRIMARY KEY,
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    state TEXT NOT NULL CHECK (state IN ${RUN_STATES}),
    gen_old INTEGER NOT NULL,
    gen_new INTEGER NOT NULL,
    intent_name TEXT NOT NULL,
    origin TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    revoke_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    failed_step TEXT,
    reason_code TEXT,
    failed_notified INTEGER NOT NULL DEFAULT 0,
    still_on_notified INTEGER NOT NULL DEFAULT 0,
    failed_at INTEGER,
    CHECK (state <> 'failed' OR failed_at IS NOT NULL)
  ) STRICT;
  CREATE UNIQUE INDEX IF NOT EXISTS rotation_one_active_run_per_key ON rotation_runs (keyref) WHERE state NOT IN ('done', 'failed', 'abandoned');
  CREATE TABLE IF NOT EXISTS rotation_gens (
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    gen INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'current', 'grace', 'retired', 'failed')),
    platform_key_id TEXT,
    region TEXT,
    project TEXT,
    PRIMARY KEY (keyref, gen)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS rotation_receipts (
    run_id TEXT NOT NULL REFERENCES rotation_runs (run_id),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    version TEXT,
    pushed INTEGER NOT NULL CHECK (pushed IN (1, 2, 3)),
    -- 1 once a redeploy's intent is written, before the redeploy is called: the destination may run the new value from then on.
    redeployed INTEGER NOT NULL DEFAULT 0,
    rollback_notified INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, kind, target)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS orphan_notices (
    platform_key_id TEXT PRIMARY KEY
  ) STRICT;
  CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    keyref TEXT NOT NULL REFERENCES keys (keyref),
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    gen INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    acked_at INTEGER,
    notified INTEGER NOT NULL DEFAULT 0
  ) STRICT;
`;

export const PASTE_SCHEMA_V0 = `
  CREATE TABLE IF NOT EXISTS paste_tasks (
    paste_id TEXT PRIMARY KEY,
    slot TEXT NOT NULL,
    action_json TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    revision INTEGER NOT NULL,
    requester TEXT NOT NULL,
    reason_json TEXT,
    opened_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed', 'expired'))
  ) STRICT;
  CREATE UNIQUE INDEX IF NOT EXISTS paste_one_pending_per_slot ON paste_tasks (slot) WHERE status = 'pending';
`;
