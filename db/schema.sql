CREATE TABLE IF NOT EXISTS invitation_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  code_prefix TEXT,
  status TEXT NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  note TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_usages (
  id TEXT PRIMARY KEY,
  invite_id TEXT,
  used_at TEXT NOT NULL,
  ip TEXT,
  ua TEXT,
  result TEXT NOT NULL,
  reason TEXT,
  FOREIGN KEY(invite_id) REFERENCES invitation_codes(id)
);

CREATE TABLE IF NOT EXISTS access_sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  invite_id TEXT,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT,
  ip_first TEXT,
  ua_first TEXT,
  status TEXT NOT NULL,
  FOREIGN KEY(invite_id) REFERENCES invitation_codes(id)
);

CREATE INDEX IF NOT EXISTS idx_invitation_codes_status ON invitation_codes(status);
CREATE INDEX IF NOT EXISTS idx_invite_usages_invite_id ON invite_usages(invite_id);
CREATE INDEX IF NOT EXISTS idx_access_sessions_role ON access_sessions(role);
