import { createHmac, createHash, randomUUID, randomBytes } from 'crypto';

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
export type Evidence = Record<string, unknown>;

export class ContractLaneError extends Error {
  status_code: number;
  error_code?: string;
  request_id?: string;
  details?: Record<string, unknown>;
  constructor(init: { status_code: number; error_code?: string; message: string; request_id?: string; details?: Record<string, unknown> }) {
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
};

export class ContractLaneClient {
  private baseUrl: string;
  private auth?: AuthStrategy;
  private timeoutMs: number;
  private retry: Required<RetryConfig>;
  private headers: Record<string, string>;
  private userAgentSuffix?: string;
  private fetchFn: typeof fetch;

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

  async evidence(gateKey: string, externalSubjectId: string): Promise<Evidence> {
    const path = `/cel/gates/${encodeURIComponent(gateKey)}/evidence?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
    const raw = await this.request('GET', path, undefined, undefined, true);
    return (raw.evidence as Record<string, unknown> | undefined) ?? raw;
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
      details: inner.details as Record<string, unknown> | undefined,
    });
  }
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(sortRec(value));
}

function sortRec(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortRec);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    Object.keys(o).sort().forEach((k) => { out[k] = sortRec(o[k]); });
    return out;
  }
  return v;
}
