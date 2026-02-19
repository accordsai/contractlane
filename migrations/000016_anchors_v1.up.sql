CREATE TABLE anchors_v1 (
  anchor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id UUID NOT NULL,
  contract_id UUID NOT NULL,
  target TEXT NOT NULL,
  target_hash TEXT NOT NULL,
  anchor_type TEXT NOT NULL,
  status TEXT NOT NULL,
  request JSONB NOT NULL DEFAULT '{}'::jsonb,
  proof JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  anchored_at TIMESTAMPTZ NULL,
  CHECK (target IN ('bundle_hash','manifest_hash')),
  CHECK (status IN ('PENDING','CONFIRMED','FAILED'))
);

CREATE INDEX anchors_v1_principal_contract_created_idx
  ON anchors_v1(principal_id, contract_id, created_at DESC);

CREATE INDEX anchors_v1_principal_target_hash_idx
  ON anchors_v1(principal_id, target, target_hash);
