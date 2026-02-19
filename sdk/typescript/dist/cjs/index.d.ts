export declare const API_VERSION = "v1";
export type RetryConfig = {
    maxAttempts?: number;
    baseDelayMs?: number;
    maxDelayMs?: number;
};
export type NextStep = {
    type?: string;
    continue_url?: string;
    [k: string]: unknown;
};
export type GateResult = {
    status: 'DONE' | 'BLOCKED';
    nextStep?: NextStep | null;
    remediation?: Record<string, unknown>;
    raw: Record<string, unknown>;
};
export type ActionResult = {
    result: 'DONE' | 'BLOCKED' | 'REJECTED';
    nextStep?: NextStep | null;
    rejection?: {
        reason?: string;
        errorCode?: string;
    };
    remediation?: Record<string, unknown>;
    raw: Record<string, unknown>;
};
export type Contract = {
    id: string;
    state?: string;
    template_id?: string;
    template_version?: string;
    raw: Record<string, unknown>;
};
export type Evidence = Record<string, unknown>;
export type ContractEvidenceBundle = Record<string, unknown>;
export type CommerceAmountV1 = {
    currency: string;
    amount: string;
};
export type CommerceIntentItemV1 = {
    sku: string;
    qty: number;
    unit_price: CommerceAmountV1;
};
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
export type ApprovalDecideInput = {
    actor_context: Record<string, unknown>;
    decision: string;
    signed_payload: Record<string, unknown>;
    signed_payload_hash?: string;
    signature?: Record<string, unknown>;
    signature_envelope?: SignatureEnvelopeV1;
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
    protocol: {
        name?: string;
        versions?: string[];
    };
    evidence: {
        bundle_versions?: string[];
        always_present_artifacts?: string[];
    };
    signatures: {
        envelopes?: string[];
        algorithms?: string[];
    };
    features?: Record<string, unknown>;
};
export declare class IncompatibleNodeError extends Error {
    missing: string[];
    constructor(missing: string[]);
}
export declare class ContractLaneError extends Error {
    status_code: number;
    error_code?: string;
    request_id?: string;
    details?: Record<string, unknown>;
    constructor(init: {
        status_code: number;
        error_code?: string;
        message: string;
        request_id?: string;
        details?: Record<string, unknown>;
    });
}
export interface AuthStrategy {
    apply(req: RequestInit, ctx: {
        method: string;
        pathWithQuery: string;
        bodyBytes: string;
    }): void;
}
export declare class PrincipalAuth implements AuthStrategy {
    private token;
    constructor(token: string);
    apply(req: RequestInit): void;
}
export declare class AgentHmacAuth implements AuthStrategy {
    private agentId;
    private secret;
    private now;
    constructor(agentId: string, secret: string, now?: () => Date);
    apply(req: RequestInit, ctx: {
        method: string;
        pathWithQuery: string;
        bodyBytes: string;
    }): void;
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
export declare class ContractLaneClient {
    private baseUrl;
    private auth?;
    private timeoutMs;
    private retry;
    private headers;
    private userAgentSuffix?;
    private fetchFn;
    private signingKey?;
    private signingContext;
    private keyId?;
    private disableCapabilityCheck;
    private capsCache?;
    constructor(opts: ClientOptions);
    static newIdempotencyKey(): string;
    gateStatus(gateKey: string, externalSubjectId: string): Promise<GateResult>;
    gateResolve(gateKey: string, externalSubjectId: string, actorType?: 'HUMAN' | 'AGENT', idempotencyKey?: string): Promise<GateResult>;
    contractAction(contractId: string, action: string, body: Record<string, unknown> | undefined, idempotencyKey?: string): Promise<ActionResult>;
    getContract(contractId: string): Promise<Contract>;
    evidence(gateKey: string, externalSubjectId: string): Promise<Evidence>;
    getContractEvidence(contractId: string, opts?: {
        format?: 'json' | 'zip';
        include?: Array<'render' | 'signatures' | 'approvals' | 'events' | 'variables'>;
        redact?: 'none' | 'pii';
    }): Promise<ContractEvidenceBundle>;
    getContractRender(contractId: string, opts?: {
        format?: 'text' | 'html';
        locale?: string;
        includeMeta?: boolean;
    }): Promise<ContractRender>;
    renderTemplate(templateId: string, version: string, variables: Record<string, string>, opts?: {
        format?: 'text' | 'html';
        locale?: string;
    }): Promise<TemplateRender>;
    setSigningKeyEd25519(secretKey: Uint8Array, keyId?: string): void;
    setSigningContext(context: string): void;
    fetchCapabilities(): Promise<Capabilities>;
    requireProtocolV1(): Promise<void>;
    approvalDecide(approvalRequestId: string, input: ApprovalDecideInput): Promise<Record<string, unknown>>;
    private parseGate;
    private request;
    private retryDelayMs;
    private sleep;
    private toError;
}
export declare function stableStringify(obj: any): string;
export declare function canonicalSha256Hex(obj: any): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToBase64(bytes: Uint8Array): string;
export declare function agentIdFromPublicKey(pub: Uint8Array): string;
export declare function parseAgentId(id: string): {
    algo: string;
    publicKey: Uint8Array;
};
export declare function isValidAgentId(id: string): boolean;
export declare function hashDelegationV1(payload: DelegationV1): string;
export declare function signDelegationV1(payload: DelegationV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1;
export declare function verifyDelegationV1(payload: DelegationV1, sig: SignatureEnvelopeV1): void;
export declare function evaluateDelegationConstraints(constraints: DelegationConstraintsV1, evalCtx: {
    contract_id: string;
    counterparty_agent: string;
    issued_at_utc: string;
    payment_amount?: CommerceAmountV1;
}): void;
export declare function hashCommerceIntentV1(intent: CommerceIntentV1): string;
export declare function signCommerceIntentV1(intent: CommerceIntentV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1;
export declare function verifyCommerceIntentV1(intent: CommerceIntentV1, sig: SignatureEnvelopeV1): void;
export declare function hashCommerceAcceptV1(acc: CommerceAcceptV1): string;
export declare function signCommerceAcceptV1(acc: CommerceAcceptV1, secretKey: Uint8Array, issuedAt: Date): SignatureEnvelopeV1;
export declare function verifyCommerceAcceptV1(acc: CommerceAcceptV1, sig: SignatureEnvelopeV1): void;
export declare function buildSignatureEnvelopeV1(payload: any, secretKey: Uint8Array, issuedAt: Date, context?: string, keyId?: string): SignatureEnvelopeV1;
