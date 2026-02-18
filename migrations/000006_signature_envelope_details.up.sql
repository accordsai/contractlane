ALTER TABLE signature_envelopes
ADD COLUMN signing_url TEXT NULL,
ADD COLUMN recipients JSONB NOT NULL DEFAULT '[]'::jsonb;
