ALTER TABLE signature_envelopes
DROP COLUMN IF EXISTS signing_url,
DROP COLUMN IF EXISTS recipients;
