CREATE TABLE IF NOT EXISTS template_shares (
  template_id TEXT NOT NULL REFERENCES templates(template_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT NULL,
  PRIMARY KEY (template_id, principal_id)
);

CREATE INDEX IF NOT EXISTS idx_template_shares_principal
  ON template_shares (principal_id, template_id);
