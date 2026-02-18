CREATE UNIQUE INDEX IF NOT EXISTS actors_principal_actor_uq ON actors(principal_id, actor_id);

CREATE TABLE principal_subjects (
  principal_id TEXT NOT NULL,
  external_subject_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('HUMAN','AGENT')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, external_subject_id),
  FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE,
  FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE,
  FOREIGN KEY (principal_id, actor_id) REFERENCES actors(principal_id, actor_id) ON DELETE CASCADE
);

CREATE INDEX principal_subjects_lookup_idx ON principal_subjects(principal_id, external_subject_id);
