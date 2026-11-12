-- Release 1 (tag v1, commit f68e398) table statements, extracted from the tag with `git show v1:<file>`; frozen text (KBOX-56).
-- file: meta.db kernel
CREATE TABLE IF NOT EXISTS keys (
  keyref TEXT PRIMARY KEY,
  platform TEXT NOT NULL,
  name TEXT NOT NULL,
  projects_json TEXT NOT NULL,
  class TEXT NOT NULL CHECK (class IN ('ordinary', 'admin', 'master')),
  status TEXT NOT NULL CHECK (status IN ('works', 'rotating', 'awaiting_approval', 'awaiting_paste', 'failed')),
  gen_current INTEGER NOT NULL,
  rotate_every_days INTEGER NOT NULL,
  grace_hours INTEGER NOT NULL,
  next_due_at INTEGER,
  expires_at INTEGER,
  coverage TEXT CHECK (coverage IS NULL OR coverage IN ('windowed', 'anchored', 'none')),
  last_use_at INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS destinations (
  keyref TEXT NOT NULL REFERENCES keys (keyref),
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  readable_by TEXT NOT NULL CHECK (readable_by IN ('api', 'runtime')),
  PRIMARY KEY (keyref, kind, target)
) STRICT;
CREATE TABLE IF NOT EXISTS grants (
  keyref TEXT NOT NULL REFERENCES keys (keyref),
  machine TEXT NOT NULL,
  PRIMARY KEY (keyref, machine)
) STRICT;
CREATE TABLE IF NOT EXISTS allow_rules (
  keyref TEXT NOT NULL REFERENCES keys (keyref),
  rule_id TEXT NOT NULL,
  PRIMARY KEY (keyref, rule_id)
) STRICT;
CREATE TABLE IF NOT EXISTS machines (
  label TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('control', 'relay')),
  token_sha256 TEXT NOT NULL UNIQUE,
  enrolled_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  last_network TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  slot TEXT NOT NULL,
  opened_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  revision INTEGER NOT NULL DEFAULT 1,
  requester TEXT NOT NULL DEFAULT 'box',
  action_json TEXT NOT NULL DEFAULT '{}',
  digest_hex TEXT NOT NULL DEFAULT '',
  reason_json TEXT,
  decided_at INTEGER,
  decided_by TEXT,
  proof_json TEXT,
  result TEXT CHECK (result IS NULL OR result IN ('done', 'failed')),
  result_code TEXT
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS approvals_one_pending_per_slot ON approvals (slot) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  data_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  ref TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS box_info (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  release TEXT NOT NULL,
  share_version INTEGER NOT NULL,
  share_public_key_ed25519_b64 TEXT,
  oidc_issuer TEXT,
  epoch TEXT NOT NULL
) STRICT;
-- file: meta.db rotation
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
  state TEXT NOT NULL CHECK (state IN ('issuing','verifying','pushing','redeploying','checking','promoting','grace','revoking','rolling_back','done','failed','abandoned')),
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
-- file: meta.db paste
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
-- file: private.db
CREATE TABLE IF NOT EXISTS push_subscriptions (
  endpoint TEXT PRIMARY KEY,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  approver_id TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS approvers (
  approver_id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  device_public_key TEXT,
  phrase TEXT,
  sign_count INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE IF NOT EXISTS vapid_key (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL
) STRICT;
