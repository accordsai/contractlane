import { createHmac, createHash, randomUUID, randomBytes } from 'crypto';
export const API_VERSION = 'v1';
export class ContractLaneError extends Error {
    constructor(init) {
        super(init.message);
        this.status_code = init.status_code;
        this.error_code = init.error_code;
        this.request_id = init.request_id;
        this.details = init.details;
    }
}
export class PrincipalAuth {
    constructor(token) {
        this.token = token;
    }
    apply(req) {
        if (!this.token)
            throw new Error('principal bearer token is required');
        req.headers['Authorization'] = `Bearer ${this.token}`;
    }
}
export class AgentHmacAuth {
    constructor(agentId, secret, now = () => new Date()) {
        this.agentId = agentId;
        this.secret = secret;
        this.now = now;
    }
    apply(req, ctx) {
        if (!this.agentId || !this.secret)
            throw new Error('agentId and secret are required for hmac auth');
        const ts = Math.floor(this.now().getTime() / 1000).toString();
        const nonce = randomUUID?.() ?? randomBytes(16).toString('hex');
        const bodyHash = ctx.bodyBytes ? createHash('sha256').update(ctx.bodyBytes).digest('hex') : '';
        const signing = `${ctx.method.toUpperCase()}\n${ctx.pathWithQuery}\n${ts}\n${nonce}\n${bodyHash}`;
        const sig = createHmac('sha256', this.secret).update(signing).digest('base64');
        const h = req.headers;
        h['X-CL-Agent-Id'] = this.agentId;
        h['X-CL-Timestamp'] = ts;
        h['X-CL-Nonce'] = nonce;
        h['X-CL-Signature'] = sig;
    }
}
export class ContractLaneClient {
    constructor(opts) {
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
    static newIdempotencyKey() {
        return randomUUID?.() ?? randomBytes(16).toString('hex');
    }
    async gateStatus(gateKey, externalSubjectId) {
        const path = `/cel/gates/${encodeURIComponent(gateKey)}/status?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
        const raw = await this.request('GET', path, undefined, undefined, true);
        return this.parseGate(raw);
    }
    async gateResolve(gateKey, externalSubjectId, actorType, idempotencyKey) {
        if (!idempotencyKey)
            throw new Error('idempotency key is required for gateResolve');
        const body = { external_subject_id: externalSubjectId, idempotency_key: idempotencyKey };
        if (actorType)
            body.actor_type = actorType;
        const path = `/cel/gates/${encodeURIComponent(gateKey)}/resolve`;
        const raw = await this.request('POST', path, body, { 'Idempotency-Key': idempotencyKey }, true);
        return this.parseGate(raw);
    }
    async contractAction(contractId, action, body, idempotencyKey) {
        if (!idempotencyKey)
            throw new Error('idempotency key is required for contractAction');
        const path = `/cel/contracts/${encodeURIComponent(contractId)}/actions/${encodeURIComponent(action)}`;
        const raw = await this.request('POST', path, body ?? {}, { 'Idempotency-Key': idempotencyKey }, true);
        const result = (raw.result ?? raw.status ?? 'REJECTED');
        const next = (raw.next_step ?? raw.remediation ?? null);
        return {
            result,
            nextStep: next,
            rejection: result === 'REJECTED' ? { reason: raw.reason, errorCode: raw.error_code } : undefined,
            remediation: raw.remediation,
            raw,
        };
    }
    async getContract(contractId) {
        const path = `/cel/contracts/${encodeURIComponent(contractId)}`;
        const raw = await this.request('GET', path, undefined, undefined, true);
        const c = (raw.contract ?? raw);
        return {
            id: c.id ?? c.contract_id ?? '',
            state: c.state,
            template_id: c.template_id,
            template_version: c.template_version,
            raw: c,
        };
    }
    async evidence(gateKey, externalSubjectId) {
        const path = `/cel/gates/${encodeURIComponent(gateKey)}/evidence?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
        const raw = await this.request('GET', path, undefined, undefined, true);
        return raw.evidence ?? raw;
    }
    parseGate(raw) {
        const next = (raw.next_step ?? raw.remediation ?? null);
        return { status: raw.status ?? 'BLOCKED', nextStep: next, remediation: raw.remediation, raw };
    }
    async request(method, path, body, extraHeaders, retryable = true) {
        const bodyBytes = body === undefined ? '' : stableStringify(body);
        const attempts = retryable ? this.retry.maxAttempts : 1;
        for (let attempt = 1; attempt <= attempts; attempt++) {
            const headers = {
                'Accept': 'application/json',
                'User-Agent': `contractlane-ts-sdk/0.1.0 api/${API_VERSION}${this.userAgentSuffix ? ` ${this.userAgentSuffix}` : ''}`,
                ...this.headers,
                ...(extraHeaders ?? {}),
            };
            if (bodyBytes)
                headers['Content-Type'] = 'application/json';
            const req = { method, headers, body: bodyBytes || undefined };
            this.auth?.apply(req, { method, pathWithQuery: path, bodyBytes });
            const ac = new AbortController();
            const timer = setTimeout(() => ac.abort(), this.timeoutMs);
            try {
                const resp = await this.fetchFn(this.baseUrl + path, { ...req, signal: ac.signal });
                const txt = await resp.text();
                const parsed = txt ? JSON.parse(txt) : {};
                if (resp.ok)
                    return parsed;
                if (attempt < attempts && [429, 502, 503, 504].includes(resp.status)) {
                    await this.sleep(this.retryDelayMs(attempt, resp.headers.get('Retry-After')));
                    continue;
                }
                throw this.toError(resp.status, parsed, txt);
            }
            catch (err) {
                if (attempt < attempts) {
                    await this.sleep(this.retryDelayMs(attempt));
                    continue;
                }
                throw err;
            }
            finally {
                clearTimeout(timer);
            }
        }
        throw new Error('unreachable');
    }
    retryDelayMs(attempt, retryAfter) {
        if (retryAfter) {
            const n = Number(retryAfter.trim());
            if (!Number.isNaN(n) && n > 0)
                return Math.min(n * 1000, this.retry.maxDelayMs);
        }
        const max = Math.min(this.retry.baseDelayMs * 2 ** (attempt - 1), this.retry.maxDelayMs);
        return Math.floor(Math.random() * Math.max(1, max));
    }
    async sleep(ms) {
        await new Promise((resolve) => setTimeout(resolve, ms));
    }
    toError(status, parsed, text) {
        const inner = parsed.error ?? parsed;
        return new ContractLaneError({
            status_code: status,
            error_code: inner.error_code ?? inner.code,
            message: inner.message ?? text ?? `HTTP ${status}`,
            request_id: inner.request_id ?? parsed.request_id,
            details: inner.details,
        });
    }
}
export function stableStringify(value) {
    return JSON.stringify(sortRec(value));
}
function sortRec(v) {
    if (Array.isArray(v))
        return v.map(sortRec);
    if (v && typeof v === 'object') {
        const o = v;
        const out = {};
        Object.keys(o).sort().forEach((k) => { out[k] = sortRec(o[k]); });
        return out;
    }
    return v;
}
