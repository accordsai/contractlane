import { createHmac, createHash, randomUUID, randomBytes, sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import nacl from 'tweetnacl';

export const API_VERSION = 'v1';

export type RetryConfig = {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
};

export type NextStep = { type?: string; continue_url?: string; [k: string]: unknown };
export type GateResult = { status: 'DONE' | 'BLOCKED'; nextStep?: NextStep | null; remediation?: Record<string, unknown>; raw: Record<string, unknown> };
export type ActionResult = { result: 'DONE' | 'BLOCKED' | 'REJECTED'; nextStep?: NextStep | null; rejection?: { reason?: string; errorCode?: string }; remediation?: Record<string, unknown>; raw: Record<string, unknown> };
export type Contract = { id: string; state?: string; template_id?: string; template_version?: string; raw: Record<string, unknown> };
export type ActorContext = {
  principal_id: string;
  actor_id: string;
  actor_type: string;
  idempotency_key?: string;
};
export type CreateContractCounterparty = {
  name: string;
  email: string;
};
export type CreateContractInput = {
  actor_context: ActorContext;
  template_id: string;
  counterparty: CreateContractCounterparty;
  initial_variables?: Record<string, string>;
};
export type CreateContractResponse = {
  contract?: Record<string, unknown>;
  raw: Record<string, unknown>;
};
export type TemplateVariableInput = {
  key: string;
  type: string;
  required: boolean;
  sensitivity: string;
  set_policy: string;
  constraints?: Record<string, unknown>;
};
export type TemplateAdminUpsertInput = {
  template_id: string;
  template_version: string;
  contract_type: string;
  jurisdiction: string;
  display_name: string;
  risk_tier: string;
  visibility: string;
  owner_principal_id?: string | null;
  metadata?: Record<string, unknown>;
  template_gates?: Record<string, string>;
  protected_slots?: string[];
  prohibited_slots?: string[];
  variables?: TemplateVariableInput[];
};
export type TemplateAdminTemplate = {
  template_id: string;
  template_version: string;
  contract_type?: string;
  jurisdiction?: string;
  display_name?: string;
  risk_tier?: string;
  status?: string;
  visibility?: string;
  owner_principal_id?: string | null;
  metadata?: Record<string, unknown>;
  published_at?: string;
  published_by?: string | null;
  [k: string]: unknown;
};
export type TemplateAdminListFilters = {
  status?: string;
  visibility?: string;
  owner_principal_id?: string;
  contract_type?: string;
  jurisdiction?: string;
};
export type TemplateAdminCloneInput = {
  template_id: string;
  template_version?: string;
  display_name?: string;
  visibility?: string;
  owner_principal_id?: string | null;
  metadata?: Record<string, unknown>;
};
export type TemplateShareRequest = {
  principal_id: string;
};
export type TemplateSharesResponse = {
  request_id?: string;
  admin?: string;
  template_id?: string;
  visibility?: string;
  shares?: Record<string, unknown>[];
  raw: Record<string, unknown>;
};
export type Evidence = Record<string, unknown>;
export type ContractEvidenceBundle = Record<string, unknown>;
export type CommerceAmountV1 = { currency: string; amount: string };
export type CommerceIntentItemV1 = { sku: string; qty: number; unit_price: CommerceAmountV1 };
export type CommerceIntentV1 = {
  version: 'commerce-intent-v1';
  intent_id: string;
  contract_id: string;
  buyer_agent: string;
  seller_agent: string;
  items: CommerceIntentItemV1[];
  total: CommerceAmountV1;
  expires_at: string;
  nonce: string;
  metadata: Record<string, unknown>;
};
export type CommerceAcceptV1 = {
  version: 'commerce-accept-v1';
  contract_id: string;
  intent_hash: string;
  accepted_at: string;
  nonce: string;
  metadata: Record<string, unknown>;
};
export type DelegationConstraintsV1 = {
  contract_id: string;
  counterparty_agent: string;
  max_amount?: CommerceAmountV1;
  valid_from: string;
  valid_until: string;
  max_uses?: number;
  purpose?: string;
};
export type DelegationV1 = {
  version: 'delegation-v1';
  delegation_id: string;
  issuer_agent: string;
  subject_agent: string;
  scopes: string[];
  constraints: DelegationConstraintsV1;
  nonce: string;
  issued_at: string;
};
export type SignatureEnvelopeV1 = {
  version: 'sig-v1';
  algorithm: 'ed25519';
  public_key: string;
  signature: string;
  payload_hash: string;
  issued_at: string;
  context?: string;
  key_id?: string;
};
export type SignatureEnvelopeV2 = {
  version: 'sig-v2';
  algorithm: 'es256';
  public_key: string; // base64url no padding SEC1 uncompressed P-256 pubkey
  signature: string; // base64url no padding raw64 r||s
  payload_hash: string;
  issued_at: string;
  context?: string;
  key_id?: string;
};
export type SignatureEnvelope = SignatureEnvelopeV1 | SignatureEnvelopeV2;
export type DelegationRevocationV1 = {
  version: 'delegation-revocation-v1';
  revocation_id: string;
  delegation_id: string;
  issuer_agent: string;
  nonce: string;
  issued_at: string;
  reason?: string;
};
export type ProofBundleV1 = {
  version: 'proof-bundle-v1';
  protocol: 'contract-lane';
  protocol_version: '1' | string;
  bundle: {
    contract: { contract_id: string; [k: string]: unknown };
    evidence: Record<string, unknown>;
    rules?: unknown;
    capabilities?: unknown;
  };
};
export type VerifyFailureCode =
  | 'VERIFIED'
  | 'MALFORMED_INPUT'
  | 'INVALID_SCHEMA'
  | 'INVALID_EVIDENCE'
  | 'INVALID_SIGNATURE'
  | 'AUTHORIZATION_FAILED'
  | 'RULES_FAILED'
  | 'UNKNOWN_ERROR';
export type VerifyReport = {
  ok: boolean;
  code: VerifyFailureCode;
  proof_id?: string;
  message?: string;
};
export type ApprovalDecideInput = {
  actor_context: Record<string, unknown>;
  decision: string;
  signed_payload: Record<string, unknown>;
  signed_payload_hash?: string;
  signature?: Record<string, unknown>;
  signature_envelope?: SignatureEnvelope;
};
export type ContractRender = {
  contract_id: string;
  principal_id?: string;
  template_id?: string;
  template_version?: string;
  contract_state?: string;
  format?: 'text' | 'html';
  locale?: string;
  rendered: string;
  render_hash: string;
  packet_hash?: string;
  variables_hash: string;
  variables_snapshot?: Record<string, string>;
  determinism_version?: string;
  raw: Record<string, unknown>;
};
export type TemplateRender = {
  template_id: string;
  template_version: string;
  format?: 'text' | 'html';
  locale?: string;
  rendered: string;
  render_hash: string;
  variables_hash: string;
  determinism_version?: string;
  raw: Record<string, unknown>;
};
export type Capabilities = {
  protocol: { name?: string; versions?: string[] };
  evidence: { bundle_versions?: string[]; always_present_artifacts?: string[] };
  signatures: { envelopes?: string[]; algorithms?: string[] };
  features?: Record<string, unknown>;
};

export class IncompatibleNodeError extends Error {
  missing: string[];
  constructor(missing: string[]) {
    super(`incompatible contractlane node: missing ${missing.join(', ')}`);
    this.name = 'IncompatibleNodeError';
    this.missing = missing;
  }
}

export class ContractLaneError extends Error {
  status_code: number;
  error_code?: string;
  request_id?: string;
  details?: unknown;
  constructor(init: { status_code: number; error_code?: string; message: string; request_id?: string; details?: unknown }) {
    super(init.message);
    this.status_code = init.status_code;
    this.error_code = init.error_code;
    this.request_id = init.request_id;
    this.details = init.details;
  }
}

export interface AuthStrategy {
  apply(req: RequestInit, ctx: { method: string; pathWithQuery: string; bodyBytes: string }): void;
}

export class PrincipalAuth implements AuthStrategy {
  constructor(private token: string) {}
  apply(req: RequestInit): void {
    if (!this.token) throw new Error('principal bearer token is required');
    (req.headers as Record<string, string>)['Authorization'] = `Bearer ${this.token}`;
  }
}

export class AgentHmacAuth implements AuthStrategy {
  constructor(private agentId: string, private secret: string, private now: () => Date = () => new Date()) {}
  apply(req: RequestInit, ctx: { method: string; pathWithQuery: string; bodyBytes: string }): void {
    if (!this.agentId || !this.secret) throw new Error('agentId and secret are required for hmac auth');
    const ts = Math.floor(this.now().getTime() / 1000).toString();
    const nonce = randomUUID?.() ?? randomBytes(16).toString('hex');
    const bodyHash = ctx.bodyBytes ? createHash('sha256').update(ctx.bodyBytes).digest('hex') : '';
    const signing = `${ctx.method.toUpperCase()}\n${ctx.pathWithQuery}\n${ts}\n${nonce}\n${bodyHash}`;
    const sig = createHmac('sha256', this.secret).update(signing).digest('base64');
    const h = req.headers as Record<string, string>;
    h['X-CL-Agent-Id'] = this.agentId;
    h['X-CL-Timestamp'] = ts;
    h['X-CL-Nonce'] = nonce;
    h['X-CL-Signature'] = sig;
  }
}

export type ClientOptions = {
  baseUrl: string;
  auth?: AuthStrategy;
  timeoutMs?: number;
  retry?: RetryConfig;
  headers?: Record<string, string>;
  userAgentSuffix?: string;
  fetchFn?: typeof fetch;
  disableCapabilityCheck?: boolean;
};

export class ContractLaneClient {
  private baseUrl: string;
  private auth?: AuthStrategy;
  private timeoutMs: number;
  private retry: Required<RetryConfig>;
  private headers: Record<string, string>;
  private userAgentSuffix?: string;
  private fetchFn: typeof fetch;
  private signingKeyEd25519?: Uint8Array;
  private signingKeyES256?: string | Buffer | KeyObject;
  private signingContext: string = 'contract-action';
  private keyId?: string;
  private disableCapabilityCheck: boolean;
  private capsCache?: { caps: Capabilities; fetchedAtMs: number };

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.auth = opts.auth;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.retry = {
      maxAttempts: opts.retry?.maxAttempts ?? 3,
      baseDelayMs: opts.retry?.baseDelayMs ?? 200,
      maxDelayMs: opts.retry?.maxDelayMs ?? 5000,
    };
    this.headers = opts.headers ?? {};
    this.userAgentSuffix = opts.userAgentSuffix;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.disableCapabilityCheck = opts.disableCapabilityCheck ?? false;
  }

  static newIdempotencyKey(): string {
    return randomUUID?.() ?? randomBytes(16).toString('hex');
  }

  async gateStatus(gateKey: string, externalSubjectId: string): Promise<GateResult> {
    const path = `/cel/gates/${encodeURIComponent(gateKey)}/status?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
    const raw = await this.request('GET', path, undefined, undefined, true);
    return this.parseGate(raw);
  }

  async gateResolve(gateKey: string, externalSubjectId: string, actorType?: 'HUMAN' | 'AGENT', idempotencyKey?: string): Promise<GateResult> {
    if (!idempotencyKey) throw new Error('idempotency key is required for gateResolve');
    const body: Record<string, unknown> = { external_subject_id: externalSubjectId, idempotency_key: idempotencyKey };
    if (actorType) body.actor_type = actorType;
    const path = `/cel/gates/${encodeURIComponent(gateKey)}/resolve`;
    const raw = await this.request('POST', path, body, { 'Idempotency-Key': idempotencyKey }, true);
    return this.parseGate(raw);
  }

  async contractAction(contractId: string, action: string, body: Record<string, unknown> | undefined, idempotencyKey?: string): Promise<ActionResult> {
    if (!idempotencyKey) throw new Error('idempotency key is required for contractAction');
    const path = `/cel/contracts/${encodeURIComponent(contractId)}/actions/${encodeURIComponent(action)}`;
    const raw = await this.request('POST', path, body ?? {}, { 'Idempotency-Key': idempotencyKey }, true);
    const result = (raw.result ?? raw.status ?? 'REJECTED') as 'DONE' | 'BLOCKED' | 'REJECTED';
    const next = ((raw.next_step as Record<string, unknown> | undefined) ?? (raw.remediation as Record<string, unknown> | undefined) ?? null) as NextStep | null;
    return {
      result,
      nextStep: next,
      rejection: result === 'REJECTED' ? { reason: raw.reason as string | undefined, errorCode: raw.error_code as string | undefined } : undefined,
      remediation: raw.remediation as Record<string, unknown> | undefined,
      raw,
    };
  }

  async getContract(contractId: string): Promise<Contract> {
    const path = `/cel/contracts/${encodeURIComponent(contractId)}`;
    const raw = await this.request('GET', path, undefined, undefined, true);
    const c = ((raw.contract as Record<string, unknown> | undefined) ?? raw) as Record<string, unknown>;
    return {
      id: (c.id as string | undefined) ?? (c.contract_id as string | undefined) ?? '',
      state: c.state as string | undefined,
      template_id: c.template_id as string | undefined,
      template_version: c.template_version as string | undefined,
      raw: c,
    };
  }

  async createContract(input: CreateContractInput): Promise<CreateContractResponse> {
    const raw = await this.request('POST', '/cel/contracts', input, undefined, true);
    return {
      contract: raw.contract as Record<string, unknown> | undefined,
      raw,
    };
  }

  async evidence(gateKey: string, externalSubjectId: string): Promise<Evidence> {
    const path = `/cel/gates/${encodeURIComponent(gateKey)}/evidence?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
    const raw = await this.request('GET', path, undefined, undefined, true);
    return (raw.evidence as Record<string, unknown> | undefined) ?? raw;
  }

  async getContractEvidence(contractId: string, opts?: { format?: 'json' | 'zip'; include?: Array<'render' | 'signatures' | 'approvals' | 'events' | 'variables'>; redact?: 'none' | 'pii' }): Promise<ContractEvidenceBundle> {
    const q = new URLSearchParams();
    if (opts?.format) q.set('format', opts.format);
    if (opts?.include && opts.include.length > 0) q.set('include', opts.include.join(','));
    if (opts?.redact) q.set('redact', opts.redact);
    const suffix = q.toString() ? `?${q.toString()}` : '';
    const path = `/cel/contracts/${encodeURIComponent(contractId)}/evidence${suffix}`;
    return this.request('GET', path, undefined, undefined, true);
  }

  async getContractRender(contractId: string, opts?: { format?: 'text' | 'html'; locale?: string; includeMeta?: boolean }): Promise<ContractRender> {
    const q = new URLSearchParams();
    if (opts?.format) q.set('format', opts.format);
    if (opts?.locale) q.set('locale', opts.locale);
    if (opts?.includeMeta !== undefined) q.set('include_meta', String(opts.includeMeta));
    const suffix = q.toString() ? `?${q.toString()}` : '';
    const path = `/cel/contracts/${encodeURIComponent(contractId)}/render${suffix}`;
    const raw = await this.request('GET', path, undefined, undefined, true);
    return {
      contract_id: raw.contract_id as string,
      principal_id: raw.principal_id as string | undefined,
      template_id: raw.template_id as string | undefined,
      template_version: raw.template_version as string | undefined,
      contract_state: raw.contract_state as string | undefined,
      format: raw.format as 'text' | 'html' | undefined,
      locale: raw.locale as string | undefined,
      rendered: (raw.rendered as string | undefined) ?? '',
      render_hash: (raw.render_hash as string | undefined) ?? '',
      packet_hash: raw.packet_hash as string | undefined,
      variables_hash: (raw.variables_hash as string | undefined) ?? '',
      variables_snapshot: raw.variables_snapshot as Record<string, string> | undefined,
      determinism_version: raw.determinism_version as string | undefined,
      raw,
    };
  }

  async renderTemplate(templateId: string, version: string, variables: Record<string, string>, opts?: { format?: 'text' | 'html'; locale?: string }): Promise<TemplateRender> {
    const path = `/cel/templates/${encodeURIComponent(templateId)}/versions/${encodeURIComponent(version)}/render`;
    const raw = await this.request('POST', path, { variables, format: opts?.format, locale: opts?.locale }, undefined, true);
    return {
      template_id: (raw.template_id as string | undefined) ?? templateId,
      template_version: (raw.template_version as string | undefined) ?? version,
      format: raw.format as 'text' | 'html' | undefined,
      locale: raw.locale as string | undefined,
      rendered: (raw.rendered as string | undefined) ?? '',
      render_hash: (raw.render_hash as string | undefined) ?? '',
      variables_hash: (raw.variables_hash as string | undefined) ?? '',
      determinism_version: raw.determinism_version as string | undefined,
      raw,
    };
  }

  async createTemplate(input: TemplateAdminUpsertInput, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('POST', '/cel/admin/templates', input as Record<string, unknown>, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  async updateTemplate(templateId: string, input: TemplateAdminUpsertInput, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('PUT', `/cel/admin/templates/${encodeURIComponent(templateId)}`, input as Record<string, unknown>, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  async publishTemplate(templateId: string, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:publish`, {}, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  async archiveTemplate(templateId: string, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:archive`, {}, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  async cloneTemplate(templateId: string, input: TemplateAdminCloneInput, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:clone`, input as Record<string, unknown>, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  async getTemplateAdmin(templateId: string): Promise<Record<string, unknown>> {
    return this.request('GET', `/cel/admin/templates/${encodeURIComponent(templateId)}`, undefined, undefined, true);
  }

  async listTemplatesAdmin(filters?: TemplateAdminListFilters): Promise<Record<string, unknown>> {
    const q = new URLSearchParams();
    if (filters?.status) q.set('status', filters.status);
    if (filters?.visibility) q.set('visibility', filters.visibility);
    if (filters?.owner_principal_id) q.set('owner_principal_id', filters.owner_principal_id);
    if (filters?.contract_type) q.set('contract_type', filters.contract_type);
    if (filters?.jurisdiction) q.set('jurisdiction', filters.jurisdiction);
    const suffix = q.toString() ? `?${q.toString()}` : '';
    return this.request('GET', `/cel/admin/templates${suffix}`, undefined, undefined, true);
  }

  async listTemplateShares(templateId: string): Promise<TemplateSharesResponse> {
    const raw = await this.request('GET', `/cel/admin/templates/${encodeURIComponent(templateId)}/shares`, undefined, undefined, true);
    return {
      request_id: raw.request_id as string | undefined,
      admin: raw.admin as string | undefined,
      template_id: raw.template_id as string | undefined,
      visibility: raw.visibility as string | undefined,
      shares: raw.shares as Record<string, unknown>[] | undefined,
      raw,
    };
  }

  async addTemplateShare(templateId: string, principalId: string, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request(
      'POST',
      `/cel/admin/templates/${encodeURIComponent(templateId)}/shares`,
      { principal_id: principalId } as TemplateShareRequest as Record<string, unknown>,
      this.idempotencyHeaders(opts?.idempotencyKey),
      true,
    );
  }

  async removeTemplateShare(templateId: string, principalId: string, opts?: { idempotencyKey?: string }): Promise<Record<string, unknown>> {
    return this.request('DELETE', `/cel/admin/templates/${encodeURIComponent(templateId)}/shares/${encodeURIComponent(principalId)}`, undefined, this.idempotencyHeaders(opts?.idempotencyKey), true);
  }

  setSigningKeyEd25519(secretKey: Uint8Array, keyId?: string): void {
    if (!secretKey || secretKey.length !== 64) {
      throw new Error('ed25519 secretKey must be 64 bytes (tweetnacl format)');
    }
    this.signingKeyEd25519 = secretKey;
    this.signingKeyES256 = undefined;
    this.keyId = keyId;
  }

  setSigningKeyES256(privateKey: string | Buffer | KeyObject, keyId?: string): void {
    if (!privateKey) {
      throw new Error('es256 private key is required');
    }
    this.signingKeyES256 = privateKey;
    this.signingKeyEd25519 = undefined;
    this.keyId = keyId;
  }

  setSigningContext(context: string): void {
    this.signingContext = context;
  }

  async fetchCapabilities(): Promise<Capabilities> {
    const now = Date.now();
    if (this.capsCache && now - this.capsCache.fetchedAtMs < 5 * 60 * 1000) {
      return this.capsCache.caps;
    }
    const raw = await this.request('GET', '/cel/.well-known/contractlane', undefined, undefined, true);
    const caps = raw as unknown as Capabilities;
    this.capsCache = { caps, fetchedAtMs: now };
    return caps;
  }

  async requireProtocolV1(): Promise<void> {
    const caps = await this.fetchCapabilities();
    const missing: string[] = [];
    const protocolName = caps.protocol?.name;
    const protocolVersions = caps.protocol?.versions ?? [];
    const evidenceBundleVersions = caps.evidence?.bundle_versions ?? [];
    const evidenceAlwaysPresent = caps.evidence?.always_present_artifacts ?? [];
    const signatureEnvelopes = caps.signatures?.envelopes ?? [];
    const signatureAlgorithms = caps.signatures?.algorithms ?? [];

    if (protocolName !== 'contractlane') missing.push('protocol.name:contractlane');
    if (!protocolVersions.includes('v1')) missing.push('protocol.versions:v1');
    if (!evidenceBundleVersions.includes('evidence-v1')) missing.push('evidence.bundle_versions:evidence-v1');
    if (!signatureEnvelopes.includes('sig-v1')) missing.push('signatures.envelopes:sig-v1');
    if (!signatureAlgorithms.includes('ed25519')) missing.push('signatures.algorithms:ed25519');
    if (!evidenceAlwaysPresent.includes('anchors')) missing.push('evidence.always_present_artifacts:anchors');
    if (!evidenceAlwaysPresent.includes('webhook_receipts')) missing.push('evidence.always_present_artifacts:webhook_receipts');

    if (missing.length > 0) {
      throw new IncompatibleNodeError(missing);
    }
  }

  async requireProtocolV2ES256(): Promise<void> {
    const caps = await this.fetchCapabilities();
    const missing: string[] = [];
    const protocolName = caps.protocol?.name;
    const protocolVersions = caps.protocol?.versions ?? [];
    const evidenceBundleVersions = caps.evidence?.bundle_versions ?? [];
    const evidenceAlwaysPresent = caps.evidence?.always_present_artifacts ?? [];
    const signatureEnvelopes = caps.signatures?.envelopes ?? [];
    const signatureAlgorithms = caps.signatures?.algorithms ?? [];

    if (protocolName !== 'contractlane') missing.push('protocol.name:contractlane');
    if (!protocolVersions.includes('v1')) missing.push('protocol.versions:v1');
    if (!evidenceBundleVersions.includes('evidence-v1')) missing.push('evidence.bundle_versions:evidence-v1');
    if (!signatureEnvelopes.includes('sig-v2')) missing.push('signatures.envelopes:sig-v2');
    if (!signatureAlgorithms.includes('es256')) missing.push('signatures.algorithms:es256');
    if (!evidenceAlwaysPresent.includes('anchors')) missing.push('evidence.always_present_artifacts:anchors');
    if (!evidenceAlwaysPresent.includes('webhook_receipts')) missing.push('evidence.always_present_artifacts:webhook_receipts');

    if (missing.length > 0) {
      throw new IncompatibleNodeError(missing);
    }
  }

  async approvalDecide(approvalRequestId: string, input: ApprovalDecideInput): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {
      actor_context: input.actor_context,
      decision: input.decision,
      signed_payload: input.signed_payload ?? {},
    };
    if (input.signed_payload_hash) {
      body.signed_payload_hash = input.signed_payload_hash;
    }

    if (!input.signature_envelope && this.signingKeyEd25519) {
      if (!this.disableCapabilityCheck) {
        await this.requireProtocolV1();
      }
      const env = buildSignatureEnvelopeV1(body.signed_payload, this.signingKeyEd25519, new Date(), this.signingContext, this.keyId);
      body.signature_envelope = env;
      body.signed_payload_hash = env.payload_hash;
    } else if (!input.signature_envelope && this.signingKeyES256) {
      if (!this.disableCapabilityCheck) {
        await this.requireProtocolV2ES256();
      }
      const env = buildSignatureEnvelopeV2(body.signed_payload, this.signingKeyES256, new Date(), this.signingContext, this.keyId);
      body.signature_envelope = env;
      body.signed_payload_hash = env.payload_hash;
    } else if (input.signature_envelope) {
      body.signature_envelope = input.signature_envelope;
    } else {
      body.signature = input.signature ?? { type: 'WEBAUTHN_ASSERTION', assertion_response: {} };
    }

    const path = `/cel/approvals/${encodeURIComponent(approvalRequestId)}:decide`;
    return this.request('POST', path, body, undefined, true);
  }

  private parseGate(raw: Record<string, unknown>): GateResult {
    const next = ((raw.next_step as Record<string, unknown> | undefined) ?? (raw.remediation as Record<string, unknown> | undefined) ?? null) as NextStep | null;
    return { status: (raw.status as 'DONE' | 'BLOCKED') ?? 'BLOCKED', nextStep: next, remediation: raw.remediation as Record<string, unknown> | undefined, raw };
  }

  private async request(method: string, path: string, body?: Record<string, unknown>, extraHeaders?: Record<string, string>, retryable = true): Promise<Record<string, unknown>> {
    const bodyBytes = body === undefined ? '' : stableStringify(body);
    const attempts = retryable ? this.retry.maxAttempts : 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      const headers: Record<string, string> = {
        'Accept': 'application/json',
        'User-Agent': `contractlane-ts-sdk/0.1.0 api/${API_VERSION}${this.userAgentSuffix ? ` ${this.userAgentSuffix}` : ''}`,
        ...this.headers,
        ...(extraHeaders ?? {}),
      };
      if (bodyBytes) headers['Content-Type'] = 'application/json';

      const req: RequestInit = { method, headers, body: bodyBytes || undefined };
      this.auth?.apply(req, { method, pathWithQuery: path, bodyBytes });
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.timeoutMs);
      try {
        const resp = await this.fetchFn(this.baseUrl + path, { ...req, signal: ac.signal });
        const txt = await resp.text();
        const parsed = txt ? (JSON.parse(txt) as Record<string, unknown>) : {};
        if (resp.ok) return parsed;
        if (attempt < attempts && [429, 502, 503, 504].includes(resp.status)) {
          await this.sleep(this.retryDelayMs(attempt, resp.headers.get('Retry-After')));
          continue;
        }
        throw this.toError(resp.status, parsed, txt);
      } catch (err) {
        if (attempt < attempts) {
          await this.sleep(this.retryDelayMs(attempt));
          continue;
        }
        throw err;
      } finally {
        clearTimeout(timer);
      }
    }
    throw new Error('unreachable');
  }

  private retryDelayMs(attempt: number, retryAfter?: string | null): number {
    if (retryAfter) {
      const n = Number(retryAfter.trim());
      if (!Number.isNaN(n) && n > 0) return Math.min(n * 1000, this.retry.maxDelayMs);
    }
    const max = Math.min(this.retry.baseDelayMs * 2 ** (attempt - 1), this.retry.maxDelayMs);
    return Math.floor(Math.random() * Math.max(1, max));
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  private toError(status: number, parsed: Record<string, unknown>, text: string): ContractLaneError {
    const inner = (parsed.error as Record<string, unknown> | undefined) ?? parsed;
    return new ContractLaneError({
      status_code: status,
      error_code: (inner.error_code as string | undefined) ?? (inner.code as string | undefined),
      message: (inner.message as string | undefined) ?? text ?? `HTTP ${status}`,
      request_id: (inner.request_id as string | undefined) ?? (parsed.request_id as string | undefined),
      details: inner.details,
    });
  }

  private idempotencyHeaders(idempotencyKey?: string): Record<string, string> | undefined {
    if (!idempotencyKey || !idempotencyKey.trim()) return undefined;
    return { 'Idempotency-Key': idempotencyKey.trim() };
  }
}

export function stableStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(stableStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

export function canonicalSha256Hex(obj: any): string {
  const json = stableStringify(obj);
  return createHash('sha256').update(json, 'utf8').digest('hex');
}

export function canonicalize(obj: any): string {
  return stableStringify(obj);
}

export function sha256Hex(data: Uint8Array | Buffer | string): string {
  if (typeof data === 'string') {
    return createHash('sha256').update(data, 'utf8').digest('hex');
  }
  return createHash('sha256').update(data).digest('hex');
}

export function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function bytesToBase64URLNoPadding(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64URLNoPaddingToBytes(input: string, field: string): Uint8Array {
  if (input.length === 0) {
    throw new Error(`missing ${field}`);
  }
  if (input.includes('=')) {
    throw new Error('invalid base64url padding');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new Error(`invalid base64url ${field}`);
  }
  const padLen = (4 - (input.length % 4)) % 4;
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLen);
  const decoded = Buffer.from(padded, 'base64');
  if (bytesToBase64URLNoPadding(decoded).replace(/=+$/g, '') !== input) {
    throw new Error(`invalid base64url ${field}`);
  }
  return Uint8Array.from(decoded);
}

export function agentIdFromPublicKey(pub: Uint8Array): string {
  if (!pub || pub.length !== 32) {
    throw new Error('ed25519 public key must be 32 bytes');
  }
  return `agent:pk:ed25519:${bytesToBase64URLNoPadding(pub)}`;
}

export function agentIdV2FromP256PublicKey(pub: Uint8Array): string {
  if (!pub || pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error('p256 public key must be SEC1 uncompressed 65 bytes');
  }
  p256PublicKeyFromSec1Uncompressed(pub);
  return `agent:v2:pk:p256:${bytesToBase64URLNoPadding(pub)}`;
}

export function parseAgentId(id: string): { algo: string; publicKey: Uint8Array } {
  const parts = id.split(':');
  if (parts.length === 4) {
    if (parts[0] !== 'agent' || parts[1] !== 'pk') {
      throw new Error('invalid agent id prefix');
    }
    if (parts[2] !== 'ed25519') {
      throw new Error('unsupported algorithm');
    }
    const decoded = base64URLNoPaddingToBytes(parts[3], 'public key');
    if (decoded.length !== 32) {
      throw new Error('invalid ed25519 public key length');
    }
    return { algo: 'ed25519', publicKey: decoded };
  }
  if (parts.length === 5) {
    if (parts[0] !== 'agent' || parts[1] !== 'v2' || parts[2] !== 'pk') {
      throw new Error('invalid agent id prefix');
    }
    if (parts[3] !== 'p256') {
      throw new Error('unsupported algorithm');
    }
    const decoded = base64URLNoPaddingToBytes(parts[4], 'public key');
    if (decoded.length !== 65 || decoded[0] !== 0x04) {
      throw new Error('invalid p256 public key encoding');
    }
    p256PublicKeyFromSec1Uncompressed(decoded);
    return { algo: 'p256', publicKey: decoded };
  }
  throw new Error('invalid agent id format');
}

export function isValidAgentId(id: string): boolean {
  try {
    parseAgentId(id);
    return true;
  } catch {
    return false;
  }
}

function parseRFC3339UTC(ts: string, field: string): void {
  if (!ts.endsWith('Z')) {
    throw new Error(`${field} must be RFC3339 UTC`);
  }
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`${field} must be RFC3339 UTC`);
  }
}

function validateBase64URLNoPadding(v: string, field: string): void {
  if (!v || v.includes('=') || !/^[A-Za-z0-9_-]+$/.test(v)) {
    throw new Error(`${field} must be base64url without padding`);
  }
  base64URLNoPaddingToBytes(v, field);
}

function normalizeCommerceIntentV1(intent: CommerceIntentV1): CommerceIntentV1 {
  if (intent.version !== 'commerce-intent-v1') throw new Error('version must be commerce-intent-v1');
  if (!intent.intent_id || !intent.contract_id) throw new Error('intent_id and contract_id are required');
  if (!isValidAgentId(intent.buyer_agent) || !isValidAgentId(intent.seller_agent)) throw new Error('buyer_agent and seller_agent must be valid agent-id-v1');
  if (!Array.isArray(intent.items) || intent.items.length === 0) throw new Error('items are required');
  for (const item of intent.items) {
    if (!item?.sku) throw new Error('item.sku is required');
    if (!Number.isInteger(item.qty) || item.qty < 1) throw new Error('item.qty must be integer >= 1');
    if (typeof item.unit_price?.currency !== 'string' || typeof item.unit_price?.amount !== 'string') {
      throw new Error('item.unit_price currency/amount must be strings');
    }
  }
  if (typeof intent.total?.currency !== 'string' || typeof intent.total?.amount !== 'string') {
    throw new Error('total currency/amount must be strings');
  }
  parseRFC3339UTC(intent.expires_at, 'expires_at');
  validateBase64URLNoPadding(intent.nonce, 'nonce');
  return { ...intent, metadata: intent.metadata ?? {} };
}

function normalizeCommerceAcceptV1(acc: CommerceAcceptV1): CommerceAcceptV1 {
  if (acc.version !== 'commerce-accept-v1') throw new Error('version must be commerce-accept-v1');
  if (!acc.contract_id) throw new Error('contract_id is required');
  if (!/^[0-9a-f]{64}$/.test(acc.intent_hash)) throw new Error('intent_hash must be lowercase hex sha256');
  parseRFC3339UTC(acc.accepted_at, 'accepted_at');
  validateBase64URLNoPadding(acc.nonce, 'nonce');
  return { ...acc, metadata: acc.metadata ?? {} };
}

const delegationAllowedKeys = new Set(['version', 'delegation_id', 'issuer_agent', 'subject_agent', 'scopes', 'constraints', 'nonce', 'issued_at']);
const delegationConstraintAllowedKeys = new Set(['contract_id', 'counterparty_agent', 'max_amount', 'valid_from', 'valid_until', 'max_uses', 'purpose']);
const delegationRevocationAllowedKeys = new Set(['version', 'revocation_id', 'delegation_id', 'issuer_agent', 'nonce', 'issued_at', 'reason']);
const knownDelegationScopes = new Set(['commerce:intent:sign', 'commerce:accept:sign', 'cel:action:execute', 'cel:approval:sign', 'settlement:attest']);
const amountExponents: Record<string, number> = { USD: 2, EUR: 2, GBP: 2, JPY: 0, KRW: 0, INR: 2, CHF: 2, CAD: 2, AUD: 2 };

function parseNormalizedAmountToMinor(amount: CommerceAmountV1): bigint {
  const currency = String(amount.currency ?? '').trim().toUpperCase();
  const value = String(amount.amount ?? '').trim();
  if (!/^[A-Z]{3}$/.test(currency)) throw new Error('amount currency must be ISO4217 uppercase 3 letters');
  const exp = amountExponents[currency];
  if (exp === undefined) throw new Error('unknown currency');
  if (!value || value.startsWith('+') || /e|E/.test(value)) throw new Error('amount must be normalized decimal');
  if ((value.match(/\./g) ?? []).length > 1) throw new Error('amount must be normalized decimal');
  const [intPart, fracPartRaw = ''] = value.split('.');
  if (!/^\d+$/.test(intPart)) throw new Error('amount must be normalized decimal');
  if (intPart.length > 1 && intPart.startsWith('0')) throw new Error('amount must be normalized decimal');
  if (fracPartRaw && (!/^\d+$/.test(fracPartRaw) || fracPartRaw.endsWith('0'))) throw new Error('amount must be normalized decimal');
  if (exp === 0) {
    if (fracPartRaw) throw new Error('amount must be normalized decimal');
    return BigInt(intPart);
  }
  if (fracPartRaw.length > exp) throw new Error('amount precision exceeds currency minor units');
  const frac = fracPartRaw.padEnd(exp, '0');
  return BigInt(intPart) * (BigInt(10) ** BigInt(exp)) + BigInt(frac || '0');
}

function normalizeDelegationV1(payload: DelegationV1): DelegationV1 {
  const keys = Object.keys(payload as Record<string, unknown>);
  for (const k of keys) if (!delegationAllowedKeys.has(k)) throw new Error(`unknown delegation key: ${k}`);
  if (payload.version !== 'delegation-v1') throw new Error('version must be delegation-v1');
  if (!payload.delegation_id) throw new Error('delegation_id is required');
  if (!isValidAgentId(payload.issuer_agent) || !isValidAgentId(payload.subject_agent)) throw new Error('issuer_agent and subject_agent must be valid agent-id-v1');
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0) throw new Error('scopes must be non-empty');
  const scopes = Array.from(new Set(payload.scopes.map((s) => String(s).trim()))).sort();
  for (const s of scopes) if (!knownDelegationScopes.has(s)) throw new Error(`unknown scope: ${s}`);
  const c = payload.constraints as Record<string, unknown>;
  if (!c || typeof c !== 'object') throw new Error('constraints is required');
  for (const k of Object.keys(c)) if (!delegationConstraintAllowedKeys.has(k)) throw new Error(`unknown delegation constraint key: ${k}`);
  const contractId = String(c.contract_id ?? '').trim();
  const counterparty = String(c.counterparty_agent ?? '').trim();
  if (!contractId) throw new Error('constraints.contract_id is required');
  if (!counterparty) throw new Error('constraints.counterparty_agent is required');
  if (counterparty !== '*' && !isValidAgentId(counterparty)) throw new Error('constraints.counterparty_agent must be * or valid agent-id-v1');
  parseRFC3339UTC(String(c.valid_from ?? ''), 'constraints.valid_from');
  parseRFC3339UTC(String(c.valid_until ?? ''), 'constraints.valid_until');
  if (new Date(String(c.valid_from)).getTime() > new Date(String(c.valid_until)).getTime()) throw new Error('constraints.valid_from must be <= constraints.valid_until');
  if (c.max_uses !== undefined && c.max_uses !== null && (!Number.isInteger(c.max_uses) || Number(c.max_uses) < 1)) throw new Error('constraints.max_uses must be integer >=1');
  if (c.max_amount !== undefined && c.max_amount !== null) parseNormalizedAmountToMinor(c.max_amount as CommerceAmountV1);
  validateBase64URLNoPadding(payload.nonce, 'nonce');
  parseRFC3339UTC(payload.issued_at, 'issued_at');
  return {
    ...payload,
    scopes,
    constraints: {
      contract_id: contractId,
      counterparty_agent: counterparty,
      valid_from: String(c.valid_from),
      valid_until: String(c.valid_until),
      ...(c.max_amount ? { max_amount: c.max_amount as CommerceAmountV1 } : {}),
      ...(c.max_uses ? { max_uses: Number(c.max_uses) } : {}),
      ...(c.purpose !== undefined ? { purpose: String(c.purpose) } : {}),
    },
  };
}

export function parseSigV1(sig: SignatureEnvelopeV1, expectedContext?: string): SignatureEnvelopeV1 {
  const allowed = new Set(['version', 'algorithm', 'public_key', 'signature', 'payload_hash', 'issued_at', 'context', 'key_id']);
  for (const k of Object.keys(sig as Record<string, unknown>)) if (!allowed.has(k)) throw new Error(`unknown signature key: ${k}`);
  if (sig.version !== 'sig-v1') throw new Error('signature_envelope version must be sig-v1');
  if (sig.algorithm !== 'ed25519') throw new Error('signature_envelope algorithm must be ed25519');
  if (!/^[0-9a-f]{64}$/.test(sig.payload_hash)) throw new Error('payload_hash must be lowercase hex sha256');
  parseRFC3339UTC(sig.issued_at, 'issued_at');
  if (expectedContext && sig.context && sig.context !== expectedContext) throw new Error('signature context mismatch');
  const pub = Buffer.from(sig.public_key, 'base64');
  const signature = Buffer.from(sig.signature, 'base64');
  if (pub.length !== 32 || signature.length !== 64) throw new Error('invalid signature encoding');
  return sig;
}

export function parseSigV2(sig: SignatureEnvelopeV2, expectedContext?: string): SignatureEnvelopeV2 {
  const allowed = new Set(['version', 'algorithm', 'public_key', 'signature', 'payload_hash', 'issued_at', 'context', 'key_id']);
  for (const k of Object.keys(sig as Record<string, unknown>)) if (!allowed.has(k)) throw new Error(`unknown signature key: ${k}`);
  if (sig.version !== 'sig-v2') throw new Error('signature_envelope version must be sig-v2');
  if (sig.algorithm !== 'es256') throw new Error('signature_envelope algorithm must be es256');
  if (!/^[0-9a-f]{64}$/.test(sig.payload_hash)) throw new Error('payload_hash must be lowercase hex sha256');
  parseRFC3339UTC(sig.issued_at, 'issued_at');
  if (expectedContext && sig.context && sig.context !== expectedContext) throw new Error('signature context mismatch');
  const pub = base64URLNoPaddingToBytes(sig.public_key, 'signature public key');
  if (pub.length !== 65 || pub[0] !== 0x04) throw new Error('invalid signature public_key encoding');
  p256PublicKeyFromSec1Uncompressed(pub);
  const rawSig = base64URLNoPaddingToBytes(sig.signature, 'signature');
  if (rawSig.length !== 64) throw new Error('invalid signature encoding');
  return sig;
}

export function parseSignatureEnvelope(sig: SignatureEnvelope, expectedContext?: string): SignatureEnvelope {
  if (!sig || typeof sig !== 'object') throw new Error('signature_envelope must be object');
  if (sig.version === 'sig-v1') return parseSigV1(sig as SignatureEnvelopeV1, expectedContext);
  if (sig.version === 'sig-v2') return parseSigV2(sig as SignatureEnvelopeV2, expectedContext);
  throw new Error('signature_envelope version must be sig-v1 or sig-v2');
}

export function normalizeAmountV1(currency: string, minorUnits: number): CommerceAmountV1 {
  if (!Number.isInteger(minorUnits) || minorUnits < 0) throw new Error('minor units must be non-negative integer');
  const ccy = String(currency ?? '').trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(ccy)) throw new Error('currency must be ISO4217 uppercase 3 letters');
  const exp = amountExponents[ccy];
  if (exp === undefined) throw new Error('unknown currency');
  if (exp === 0) return { currency: ccy, amount: String(minorUnits) };
  const base = 10 ** exp;
  const integer = Math.floor(minorUnits / base);
  const fraction = minorUnits % base;
  let amount = `${integer}.${String(fraction).padStart(exp, '0')}`;
  amount = amount.replace(/0+$/g, '').replace(/\.$/, '');
  if (!amount) amount = '0';
  return { currency: ccy, amount };
}

export function parseAmountV1(amount: CommerceAmountV1): bigint {
  return parseNormalizedAmountToMinor(amount);
}

export function parseDelegationV1(payload: DelegationV1): DelegationV1 {
  return normalizeDelegationV1(payload);
}

export function parseDelegationRevocationV1(payload: DelegationRevocationV1): DelegationRevocationV1 {
  const keys = Object.keys(payload as Record<string, unknown>);
  for (const k of keys) if (!delegationRevocationAllowedKeys.has(k)) throw new Error(`unknown delegation revocation key: ${k}`);
  if (payload.version !== 'delegation-revocation-v1') throw new Error('version must be delegation-revocation-v1');
  if (!payload.revocation_id) throw new Error('revocation_id is required');
  if (!payload.delegation_id) throw new Error('delegation_id is required');
  if (!isValidAgentId(payload.issuer_agent)) throw new Error('issuer_agent must be valid agent-id-v1');
  validateBase64URLNoPadding(payload.nonce, 'nonce');
  parseRFC3339UTC(payload.issued_at, 'issued_at');
  return payload;
}

export function newCommerceIntentV1(payload: Omit<CommerceIntentV1, 'version' | 'nonce' | 'metadata'> & { metadata?: Record<string, unknown> }): CommerceIntentV1 {
  return normalizeCommerceIntentV1({
    version: 'commerce-intent-v1',
    nonce: bytesToBase64URLNoPadding(randomBytes(16)),
    metadata: payload.metadata ?? {},
    ...payload,
  });
}

export function newCommerceAcceptV1(payload: Omit<CommerceAcceptV1, 'version' | 'nonce' | 'metadata'> & { metadata?: Record<string, unknown> }): CommerceAcceptV1 {
  return normalizeCommerceAcceptV1({
    version: 'commerce-accept-v1',
    nonce: bytesToBase64URLNoPadding(randomBytes(16)),
    metadata: payload.metadata ?? {},
    ...payload,
  });
}

export function newDelegationV1(payload: Omit<DelegationV1, 'version' | 'nonce'>): DelegationV1 {
  return normalizeDelegationV1({
    version: 'delegation-v1',
    nonce: bytesToBase64URLNoPadding(randomBytes(16)),
    ...payload,
  });
}

export function newDelegationRevocationV1(payload: Omit<DelegationRevocationV1, 'version' | 'nonce'>): DelegationRevocationV1 {
  return parseDelegationRevocationV1({
    version: 'delegation-revocation-v1',
    nonce: bytesToBase64URLNoPadding(randomBytes(16)),
    ...payload,
  });
}

export function sigV1Sign(context: string, payloadHash: string, secretKey: Uint8Array, issuedAt: Date, keyId?: string): SignatureEnvelopeV1 {
  if (!/^[0-9a-f]{64}$/.test(payloadHash)) throw new Error('payload_hash must be lowercase hex sha256');
  if (!secretKey || secretKey.length !== 64) throw new Error('ed25519 secretKey must be 64 bytes (tweetnacl format)');
  const signature = nacl.sign.detached(hexToBytes(payloadHash), secretKey);
  const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey);
  return {
    version: 'sig-v1',
    algorithm: 'ed25519',
    public_key: bytesToBase64(keyPair.publicKey),
    signature: bytesToBase64(signature),
    payload_hash: payloadHash,
    issued_at: issuedAt.toISOString(),
    context,
    ...(keyId ? { key_id: keyId } : {}),
  };
}

export function sigV2Sign(
  context: string,
  payloadHash: string,
  privateKey: string | Buffer | KeyObject,
  issuedAt: Date,
  keyId?: string,
): SignatureEnvelopeV2 {
  if (!/^[0-9a-f]{64}$/.test(payloadHash)) throw new Error('payload_hash must be lowercase hex sha256');
  if (!privateKey) throw new Error('es256 private key is required');
  const keyObj = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey as any);
  const msg = Buffer.from(payloadHash, 'hex');
  const sigRaw = cryptoSign(null, msg, { key: keyObj, dsaEncoding: 'ieee-p1363' as const });
  if (sigRaw.length !== 64) throw new Error('invalid es256 signature length');
  const pubDer = createPublicKey(keyObj).export({ type: 'spki', format: 'der' }) as Buffer;
  const sec1 = spkiP256ToSec1Uncompressed(pubDer);
  return {
    version: 'sig-v2',
    algorithm: 'es256',
    public_key: bytesToBase64URLNoPadding(sec1),
    signature: bytesToBase64URLNoPadding(sigRaw),
    payload_hash: payloadHash,
    issued_at: issuedAt.toISOString(),
    context,
    ...(keyId ? { key_id: keyId } : {}),
  };
}

export function parseProofBundleV1(proof: any): ProofBundleV1 {
  if (!proof || typeof proof !== 'object') throw new Error('proof bundle must be object');
  const allowed = new Set(['version', 'protocol', 'protocol_version', 'bundle']);
  for (const k of Object.keys(proof as Record<string, unknown>)) if (!allowed.has(k)) throw new Error(`unknown proof bundle key: ${k}`);
  if (proof.version !== 'proof-bundle-v1') throw new Error('version must be proof-bundle-v1');
  if (proof.protocol !== 'contract-lane') throw new Error('protocol must be contract-lane');
  if (String(proof.protocol_version ?? '') !== '1') throw new Error('protocol_version must be 1');
  if (!proof.bundle || typeof proof.bundle !== 'object') throw new Error('bundle is required');
  if (!proof.bundle.contract || !proof.bundle.contract.contract_id) throw new Error('bundle.contract.contract_id is required');
  if (!proof.bundle.evidence || typeof proof.bundle.evidence !== 'object') throw new Error('bundle.evidence is required');
  return proof as ProofBundleV1;
}

export function computeProofId(proof: ProofBundleV1): string {
  parseProofBundleV1(proof);
  return canonicalSha256Hex(proof);
}

function verifyProofBundleSignatures(proof: ProofBundleV1): void {
  const artifacts = (((proof.bundle as any).evidence || {}).artifacts || {}) as Record<string, any>;
  if (!artifacts || typeof artifacts !== 'object') throw new Error('evidence missing artifacts');
  for (const row of artifacts.commerce_intents ?? []) {
    if (row?.intent && row?.buyer_signature) verifyCommerceIntentV1(row.intent, row.buyer_signature);
  }
  for (const row of artifacts.commerce_accepts ?? []) {
    if (row?.accept && row?.seller_signature) verifyCommerceAcceptV1(row.accept, row.seller_signature);
  }
  for (const row of artifacts.delegations ?? []) {
    if (row?.delegation && row?.issuer_signature) verifyDelegationV1(row.delegation, row.issuer_signature);
  }
}

export function verifyProofBundleV1(proof: ProofBundleV1): VerifyReport {
  try {
    const parsed = parseProofBundleV1(proof);
    const proofId = computeProofId(parsed);
    const evContractID = String((((parsed.bundle as any).evidence || {}).contract || {}).contract_id ?? '').trim();
    const contractID = String(((parsed.bundle as any).contract || {}).contract_id ?? '').trim();
    if (!evContractID || evContractID !== contractID) {
      return { ok: false, code: 'INVALID_EVIDENCE', message: 'contract/evidence contract_id mismatch' };
    }
    verifyProofBundleSignatures(parsed);
    return { ok: true, code: 'VERIFIED', proof_id: proofId };
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    let code: VerifyFailureCode = 'UNKNOWN_ERROR';
    if (msg.includes('version must be proof-bundle-v1') || msg.includes('protocol_version must be 1') || msg.includes('bundle.')) code = 'INVALID_SCHEMA';
    else if (msg.includes('evidence')) code = 'INVALID_EVIDENCE';
    else if (msg.includes('signature') || msg.includes('payload hash mismatch')) code = 'INVALID_SIGNATURE';
    else if (msg.includes('delegation_')) code = 'AUTHORIZATION_FAILED';
    else if (msg.includes('rules_')) code = 'RULES_FAILED';
    else code = 'MALFORMED_INPUT';
    return { ok: false, code, message: msg };
  }
}

export function hashDelegationV1(payload: DelegationV1): string {
  const normalized = normalizeDelegationV1(payload);
  return canonicalSha256Hex(normalized);
}

export function signDelegationV1(payload: DelegationV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1 {
  const normalized = normalizeDelegationV1(payload);
  return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'delegation');
}

export function signDelegationV1ES256(payload: DelegationV1, privateKey: string | Buffer | KeyObject, issuedAt: Date): SignatureEnvelopeV2 {
  const normalized = normalizeDelegationV1(payload);
  return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'delegation');
}

export function verifyDelegationV1(payload: DelegationV1, sig: SignatureEnvelope): void {
  const normalized = normalizeDelegationV1(payload);
  const expected = hashDelegationV1(normalized);
  verifySignatureEnvelope(normalized, sig, 'delegation');
  if (sig.payload_hash !== expected) throw new Error('payload hash mismatch');
  if (agentIdFromSignatureEnvelope(sig) !== normalized.issuer_agent) throw new Error('signature public key does not match issuer_agent');
}

export function evaluateDelegationConstraints(constraints: DelegationConstraintsV1, evalCtx: { contract_id: string; counterparty_agent: string; issued_at_utc: string; payment_amount?: CommerceAmountV1 }): void {
  const d = normalizeDelegationV1({
    version: 'delegation-v1',
    delegation_id: 'del_eval',
    issuer_agent: evalCtx.counterparty_agent === '*' ? 'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' : evalCtx.counterparty_agent,
    subject_agent: evalCtx.counterparty_agent === '*' ? 'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' : evalCtx.counterparty_agent,
    scopes: ['commerce:intent:sign'],
    constraints,
    nonce: 'bm9uY2VfdjE',
    issued_at: evalCtx.issued_at_utc,
  });
  if (d.constraints.contract_id !== '*' && d.constraints.contract_id !== evalCtx.contract_id) throw new Error('delegation_constraints_failed');
  if (d.constraints.counterparty_agent !== '*' && d.constraints.counterparty_agent !== evalCtx.counterparty_agent) throw new Error('delegation_constraints_failed');
  const at = new Date(evalCtx.issued_at_utc).getTime();
  const from = new Date(d.constraints.valid_from).getTime();
  const until = new Date(d.constraints.valid_until).getTime();
  if (at < from || at > until) throw new Error('delegation_expired');
  if (d.constraints.max_amount && evalCtx.payment_amount) {
    const maxMinor = parseNormalizedAmountToMinor(d.constraints.max_amount);
    const payMinor = parseNormalizedAmountToMinor(evalCtx.payment_amount);
    if (String(d.constraints.max_amount.currency).toUpperCase() !== String(evalCtx.payment_amount.currency).toUpperCase() || payMinor > maxMinor) {
      throw new Error('delegation_amount_exceeded');
    }
  }
}

export function hashCommerceIntentV1(intent: CommerceIntentV1): string {
  const normalized = normalizeCommerceIntentV1(intent);
  return canonicalSha256Hex(normalized);
}

export function signCommerceIntentV1(intent: CommerceIntentV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1 {
  const normalized = normalizeCommerceIntentV1(intent);
  return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'commerce-intent');
}

export function signCommerceIntentV1ES256(intent: CommerceIntentV1, privateKey: string | Buffer | KeyObject, issuedAt: Date): SignatureEnvelopeV2 {
  const normalized = normalizeCommerceIntentV1(intent);
  return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'commerce-intent');
}

export function verifyCommerceIntentV1(intent: CommerceIntentV1, sig: SignatureEnvelope): void {
  const normalized = normalizeCommerceIntentV1(intent);
  const expectedHash = hashCommerceIntentV1(normalized);
  if (sig.payload_hash !== expectedHash) throw new Error('payload hash mismatch');
  verifySignatureEnvelope(normalized, sig, 'commerce-intent');
}

export function hashCommerceAcceptV1(acc: CommerceAcceptV1): string {
  const normalized = normalizeCommerceAcceptV1(acc);
  return canonicalSha256Hex(normalized);
}

export function signCommerceAcceptV1(acc: CommerceAcceptV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1 {
  const normalized = normalizeCommerceAcceptV1(acc);
  return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'commerce-accept');
}

export function signCommerceAcceptV1ES256(acc: CommerceAcceptV1, privateKey: string | Buffer | KeyObject, issuedAt: Date): SignatureEnvelopeV2 {
  const normalized = normalizeCommerceAcceptV1(acc);
  return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'commerce-accept');
}

export function verifyCommerceAcceptV1(acc: CommerceAcceptV1, sig: SignatureEnvelope): void {
  const normalized = normalizeCommerceAcceptV1(acc);
  const expectedHash = hashCommerceAcceptV1(normalized);
  if (sig.payload_hash !== expectedHash) throw new Error('payload hash mismatch');
  verifySignatureEnvelope(normalized, sig, 'commerce-accept');
}

export function buildSignatureEnvelopeV1(
  payload: any,
  secretKey: Uint8Array,
  issuedAt: Date,
  context: string = 'contract-action',
  keyId?: string,
): SignatureEnvelopeV1 {
  if (!secretKey || secretKey.length !== 64) {
    throw new Error('ed25519 secretKey must be 64 bytes (tweetnacl format)');
  }
  const payloadHash = canonicalSha256Hex(payload);
  const message = hexToBytes(payloadHash);
  const signature = nacl.sign.detached(message, secretKey);
  const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey);

  return {
    version: 'sig-v1',
    algorithm: 'ed25519',
    public_key: bytesToBase64(keyPair.publicKey),
    signature: bytesToBase64(signature),
    payload_hash: payloadHash,
    issued_at: issuedAt.toISOString(),
    context,
    ...(keyId ? { key_id: keyId } : {}),
  };
}

export function buildSignatureEnvelopeV2(
  payload: any,
  privateKey: string | Buffer | KeyObject,
  issuedAt: Date,
  context: string = 'contract-action',
  keyId?: string,
): SignatureEnvelopeV2 {
  const payloadHash = canonicalSha256Hex(payload);
  return sigV2Sign(context, payloadHash, privateKey, issuedAt, keyId);
}

function spkiP256ToSec1Uncompressed(spkiDer: Buffer): Uint8Array {
  // Minimal SPKI parser for EC P-256 keys produced by Node crypto.
  const p256SpkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  if (spkiDer.length === p256SpkiPrefix.length + 65 && spkiDer.subarray(0, p256SpkiPrefix.length).equals(p256SpkiPrefix)) {
    const pub = spkiDer.subarray(p256SpkiPrefix.length);
    if (pub.length === 65 && pub[0] === 0x04) return Uint8Array.from(pub);
  }
  throw new Error('invalid es256 public key encoding');
}

function p256PublicKeyFromSec1Uncompressed(sec1Pub: Uint8Array): KeyObject {
  if (sec1Pub.length !== 65 || sec1Pub[0] !== 0x04) throw new Error('invalid signature public_key encoding');
  const p256SpkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const der = Buffer.concat([p256SpkiPrefix, Buffer.from(sec1Pub)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function parseES256SignatureCompat(sig: string): { raw64?: Buffer; der?: Buffer } {
  try {
    const raw = Buffer.from(base64URLNoPaddingToBytes(sig, 'signature'));
    if (raw.length === 64) return { raw64: raw };
    throw new Error('invalid signature');
  } catch {
    // Compatibility path: accept DER in standard base64 from API boundary.
    const der = Buffer.from(sig, 'base64');
    if (!der.length) throw new Error('invalid signature encoding');
    return { der };
  }
}

function verifySignatureEnvelope(payload: any, sig: SignatureEnvelope, expectedContext?: string): void {
  const parsed = parseSignatureEnvelope(sig, expectedContext);
  const expectedHash = canonicalSha256Hex(payload);
  if (parsed.payload_hash !== expectedHash) throw new Error('payload hash mismatch');
  const msg = Buffer.from(expectedHash, 'hex');

  if (parsed.version === 'sig-v1') {
    const pub = Buffer.from(parsed.public_key, 'base64');
    const signature = Buffer.from(parsed.signature, 'base64');
    if (!nacl.sign.detached.verify(msg, signature, pub)) throw new Error('invalid signature');
    return;
  }

  const pub = p256PublicKeyFromSec1Uncompressed(base64URLNoPaddingToBytes(parsed.public_key, 'signature public key'));
  const sigCompat = parseES256SignatureCompat(parsed.signature);
  if (sigCompat.raw64) {
    if (!cryptoVerify(null, msg, { key: pub, dsaEncoding: 'ieee-p1363' }, sigCompat.raw64)) throw new Error('invalid signature');
    return;
  }
  if (!sigCompat.der || !cryptoVerify(null, msg, pub, sigCompat.der)) throw new Error('invalid signature');
}

function agentIdFromSignatureEnvelope(sig: SignatureEnvelope): string {
  if (sig.algorithm === 'ed25519') {
    return agentIdFromPublicKey(Buffer.from(sig.public_key, 'base64'));
  }
  return agentIdV2FromP256PublicKey(base64URLNoPaddingToBytes(sig.public_key, 'signature public key'));
}
