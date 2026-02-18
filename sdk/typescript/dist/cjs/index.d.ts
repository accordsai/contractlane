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
};
export declare class ContractLaneClient {
    private baseUrl;
    private auth?;
    private timeoutMs;
    private retry;
    private headers;
    private userAgentSuffix?;
    private fetchFn;
    constructor(opts: ClientOptions);
    static newIdempotencyKey(): string;
    gateStatus(gateKey: string, externalSubjectId: string): Promise<GateResult>;
    gateResolve(gateKey: string, externalSubjectId: string, actorType?: 'HUMAN' | 'AGENT', idempotencyKey?: string): Promise<GateResult>;
    contractAction(contractId: string, action: string, body: Record<string, unknown> | undefined, idempotencyKey?: string): Promise<ActionResult>;
    getContract(contractId: string): Promise<Contract>;
    evidence(gateKey: string, externalSubjectId: string): Promise<Evidence>;
    private parseGate;
    private request;
    private retryDelayMs;
    private sleep;
    private toError;
}
export declare function stableStringify(value: unknown): string;
