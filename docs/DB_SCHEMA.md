# DB Schema

The canonical schema is migration-driven under `migrations/`.

## Webhook Receipts

- `webhook_receipts` (introduced in migration `000012_webhook_receipts`) is the legacy receipt table.
- `webhook_endpoints` and `webhook_receipts_v2` are introduced in migration `000015_webhook_endpoints_and_receipts_v2` for deterministic principal routing and raw-byte webhook capture.

### `webhook_endpoints`

- `endpoint_id uuid primary key default gen_random_uuid()`
- `principal_id uuid not null`
- `provider text not null`
- `endpoint_token text not null`
- `secret text not null`
- `created_at timestamptz not null default now()`
- `revoked_at timestamptz null`

Indexes / constraints:

- `unique(provider, endpoint_token)`
- `unique(endpoint_token)`
- index `(principal_id, provider)`

### `webhook_receipts_v2`

- `receipt_id uuid primary key default gen_random_uuid()`
- `principal_id uuid not null`
- `provider text not null`
- `event_type text not null`
- `provider_event_id text null`
- `received_at timestamptz not null`
- `request_method text not null`
- `request_path text not null`
- `raw_body bytea not null`
- `raw_body_sha256 text not null`
- `headers_canonical_json jsonb not null`
- `headers_sha256 text not null`
- `request_sha256 text not null`
- `signature_valid boolean not null`
- `signature_scheme text not null`
- `signature_details jsonb not null`
- `linked_contract_id uuid null`
- `linked_action text null`
- `processing_status text not null`
- `processed_at timestamptz null`

Indexes / constraints:

- unique index `(principal_id, provider, provider_event_id)` where `provider_event_id is not null`
- index `(principal_id, received_at)`
- index `(principal_id, linked_contract_id)`

## Anchors

`anchors_v1` (introduced in migration `000016_anchors_v1`) stores proof-anchoring records for evidence hashes.

- `anchor_id uuid primary key default gen_random_uuid()`
- `principal_id uuid not null`
- `contract_id uuid not null`
- `target text not null` (`bundle_hash` or `manifest_hash`)
- `target_hash text not null`
- `anchor_type text not null`
- `status text not null` (`PENDING`, `CONFIRMED`, `FAILED`)
- `request jsonb not null default '{}'::jsonb`
- `proof jsonb not null default '{}'::jsonb`
- `created_at timestamptz not null default now()`
- `anchored_at timestamptz null`

Indexes / constraints:

- check `target in ('bundle_hash','manifest_hash')`
- check `status in ('PENDING','CONFIRMED','FAILED')`
- index `(principal_id, contract_id, created_at desc)`
- index `(principal_id, target, target_hash)`
