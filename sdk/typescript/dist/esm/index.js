import { createHmac, createHash, randomUUID, randomBytes, sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import nacl from 'tweetnacl';
export const API_VERSION = 'v1';
export class IncompatibleNodeError extends Error {
    constructor(missing) {
        super(`incompatible contractlane node: missing ${missing.join(', ')}`);
        this.name = 'IncompatibleNodeError';
        this.missing = missing;
    }
}
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
        this.signingContext = 'contract-action';
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
    async createContract(input) {
        const raw = await this.request('POST', '/cel/contracts', input, undefined, true);
        return {
            contract: raw.contract,
            raw,
        };
    }
    async evidence(gateKey, externalSubjectId) {
        const path = `/cel/gates/${encodeURIComponent(gateKey)}/evidence?external_subject_id=${encodeURIComponent(externalSubjectId)}`;
        const raw = await this.request('GET', path, undefined, undefined, true);
        return raw.evidence ?? raw;
    }
    async getContractEvidence(contractId, opts) {
        const q = new URLSearchParams();
        if (opts?.format)
            q.set('format', opts.format);
        if (opts?.include && opts.include.length > 0)
            q.set('include', opts.include.join(','));
        if (opts?.redact)
            q.set('redact', opts.redact);
        const suffix = q.toString() ? `?${q.toString()}` : '';
        const path = `/cel/contracts/${encodeURIComponent(contractId)}/evidence${suffix}`;
        return this.request('GET', path, undefined, undefined, true);
    }
    async getContractRender(contractId, opts) {
        const q = new URLSearchParams();
        if (opts?.format)
            q.set('format', opts.format);
        if (opts?.locale)
            q.set('locale', opts.locale);
        if (opts?.includeMeta !== undefined)
            q.set('include_meta', String(opts.includeMeta));
        const suffix = q.toString() ? `?${q.toString()}` : '';
        const path = `/cel/contracts/${encodeURIComponent(contractId)}/render${suffix}`;
        const raw = await this.request('GET', path, undefined, undefined, true);
        return {
            contract_id: raw.contract_id,
            principal_id: raw.principal_id,
            template_id: raw.template_id,
            template_version: raw.template_version,
            contract_state: raw.contract_state,
            format: raw.format,
            locale: raw.locale,
            rendered: raw.rendered ?? '',
            render_hash: raw.render_hash ?? '',
            packet_hash: raw.packet_hash,
            variables_hash: raw.variables_hash ?? '',
            variables_snapshot: raw.variables_snapshot,
            determinism_version: raw.determinism_version,
            raw,
        };
    }
    async renderTemplate(templateId, version, variables, opts) {
        const path = `/cel/templates/${encodeURIComponent(templateId)}/versions/${encodeURIComponent(version)}/render`;
        const raw = await this.request('POST', path, { variables, format: opts?.format, locale: opts?.locale }, undefined, true);
        return {
            template_id: raw.template_id ?? templateId,
            template_version: raw.template_version ?? version,
            format: raw.format,
            locale: raw.locale,
            rendered: raw.rendered ?? '',
            render_hash: raw.render_hash ?? '',
            variables_hash: raw.variables_hash ?? '',
            determinism_version: raw.determinism_version,
            raw,
        };
    }
    async createTemplate(input, opts) {
        return this.request('POST', '/cel/admin/templates', input, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async updateTemplate(templateId, input, opts) {
        return this.request('PUT', `/cel/admin/templates/${encodeURIComponent(templateId)}`, input, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async publishTemplate(templateId, opts) {
        return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:publish`, {}, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async archiveTemplate(templateId, opts) {
        return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:archive`, {}, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async cloneTemplate(templateId, input, opts) {
        return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}:clone`, input, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async getTemplateAdmin(templateId) {
        return this.request('GET', `/cel/admin/templates/${encodeURIComponent(templateId)}`, undefined, undefined, true);
    }
    async listTemplatesAdmin(filters) {
        const q = new URLSearchParams();
        if (filters?.status)
            q.set('status', filters.status);
        if (filters?.visibility)
            q.set('visibility', filters.visibility);
        if (filters?.owner_principal_id)
            q.set('owner_principal_id', filters.owner_principal_id);
        if (filters?.contract_type)
            q.set('contract_type', filters.contract_type);
        if (filters?.jurisdiction)
            q.set('jurisdiction', filters.jurisdiction);
        const suffix = q.toString() ? `?${q.toString()}` : '';
        return this.request('GET', `/cel/admin/templates${suffix}`, undefined, undefined, true);
    }
    async listTemplateShares(templateId) {
        const raw = await this.request('GET', `/cel/admin/templates/${encodeURIComponent(templateId)}/shares`, undefined, undefined, true);
        return {
            request_id: raw.request_id,
            admin: raw.admin,
            template_id: raw.template_id,
            visibility: raw.visibility,
            shares: raw.shares,
            raw,
        };
    }
    async addTemplateShare(templateId, principalId, opts) {
        return this.request('POST', `/cel/admin/templates/${encodeURIComponent(templateId)}/shares`, { principal_id: principalId }, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    async removeTemplateShare(templateId, principalId, opts) {
        return this.request('DELETE', `/cel/admin/templates/${encodeURIComponent(templateId)}/shares/${encodeURIComponent(principalId)}`, undefined, this.idempotencyHeaders(opts?.idempotencyKey), true);
    }
    setSigningKeyEd25519(secretKey, keyId) {
        if (!secretKey || secretKey.length !== 64) {
            throw new Error('ed25519 secretKey must be 64 bytes (tweetnacl format)');
        }
        this.signingKeyEd25519 = secretKey;
        this.signingKeyES256 = undefined;
        this.keyId = keyId;
    }
    setSigningKeyES256(privateKey, keyId) {
        if (!privateKey) {
            throw new Error('es256 private key is required');
        }
        this.signingKeyES256 = privateKey;
        this.signingKeyEd25519 = undefined;
        this.keyId = keyId;
    }
    setSigningContext(context) {
        this.signingContext = context;
    }
    async fetchCapabilities() {
        const now = Date.now();
        if (this.capsCache && now - this.capsCache.fetchedAtMs < 5 * 60 * 1000) {
            return this.capsCache.caps;
        }
        const raw = await this.request('GET', '/cel/.well-known/contractlane', undefined, undefined, true);
        const caps = raw;
        this.capsCache = { caps, fetchedAtMs: now };
        return caps;
    }
    async requireProtocolV1() {
        const caps = await this.fetchCapabilities();
        const missing = [];
        const protocolName = caps.protocol?.name;
        const protocolVersions = caps.protocol?.versions ?? [];
        const evidenceBundleVersions = caps.evidence?.bundle_versions ?? [];
        const evidenceAlwaysPresent = caps.evidence?.always_present_artifacts ?? [];
        const signatureEnvelopes = caps.signatures?.envelopes ?? [];
        const signatureAlgorithms = caps.signatures?.algorithms ?? [];
        if (protocolName !== 'contractlane')
            missing.push('protocol.name:contractlane');
        if (!protocolVersions.includes('v1'))
            missing.push('protocol.versions:v1');
        if (!evidenceBundleVersions.includes('evidence-v1'))
            missing.push('evidence.bundle_versions:evidence-v1');
        if (!signatureEnvelopes.includes('sig-v1'))
            missing.push('signatures.envelopes:sig-v1');
        if (!signatureAlgorithms.includes('ed25519'))
            missing.push('signatures.algorithms:ed25519');
        if (!evidenceAlwaysPresent.includes('anchors'))
            missing.push('evidence.always_present_artifacts:anchors');
        if (!evidenceAlwaysPresent.includes('webhook_receipts'))
            missing.push('evidence.always_present_artifacts:webhook_receipts');
        if (missing.length > 0) {
            throw new IncompatibleNodeError(missing);
        }
    }
    async requireProtocolV2ES256() {
        const caps = await this.fetchCapabilities();
        const missing = [];
        const protocolName = caps.protocol?.name;
        const protocolVersions = caps.protocol?.versions ?? [];
        const evidenceBundleVersions = caps.evidence?.bundle_versions ?? [];
        const evidenceAlwaysPresent = caps.evidence?.always_present_artifacts ?? [];
        const signatureEnvelopes = caps.signatures?.envelopes ?? [];
        const signatureAlgorithms = caps.signatures?.algorithms ?? [];
        if (protocolName !== 'contractlane')
            missing.push('protocol.name:contractlane');
        if (!protocolVersions.includes('v1'))
            missing.push('protocol.versions:v1');
        if (!evidenceBundleVersions.includes('evidence-v1'))
            missing.push('evidence.bundle_versions:evidence-v1');
        if (!signatureEnvelopes.includes('sig-v2'))
            missing.push('signatures.envelopes:sig-v2');
        if (!signatureAlgorithms.includes('es256'))
            missing.push('signatures.algorithms:es256');
        if (!evidenceAlwaysPresent.includes('anchors'))
            missing.push('evidence.always_present_artifacts:anchors');
        if (!evidenceAlwaysPresent.includes('webhook_receipts'))
            missing.push('evidence.always_present_artifacts:webhook_receipts');
        if (missing.length > 0) {
            throw new IncompatibleNodeError(missing);
        }
    }
    async approvalDecide(approvalRequestId, input) {
        const body = {
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
        }
        else if (!input.signature_envelope && this.signingKeyES256) {
            if (!this.disableCapabilityCheck) {
                await this.requireProtocolV2ES256();
            }
            const env = buildSignatureEnvelopeV2(body.signed_payload, this.signingKeyES256, new Date(), this.signingContext, this.keyId);
            body.signature_envelope = env;
            body.signed_payload_hash = env.payload_hash;
        }
        else if (input.signature_envelope) {
            body.signature_envelope = input.signature_envelope;
        }
        else {
            body.signature = input.signature ?? { type: 'WEBAUTHN_ASSERTION', assertion_response: {} };
        }
        const path = `/cel/approvals/${encodeURIComponent(approvalRequestId)}:decide`;
        return this.request('POST', path, body, undefined, true);
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
    idempotencyHeaders(idempotencyKey) {
        if (!idempotencyKey || !idempotencyKey.trim())
            return undefined;
        return { 'Idempotency-Key': idempotencyKey.trim() };
    }
}
export function stableStringify(obj) {
    if (obj === null || typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return '[' + obj.map(stableStringify).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}
export function canonicalSha256Hex(obj) {
    const json = stableStringify(obj);
    return createHash('sha256').update(json, 'utf8').digest('hex');
}
export function canonicalize(obj) {
    return stableStringify(obj);
}
export function sha256Hex(data) {
    if (typeof data === 'string') {
        return createHash('sha256').update(data, 'utf8').digest('hex');
    }
    return createHash('sha256').update(data).digest('hex');
}
export function hexToBytes(hex) {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
}
export function bytesToBase64(bytes) {
    return Buffer.from(bytes).toString('base64');
}
function bytesToBase64URLNoPadding(bytes) {
    return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function base64URLNoPaddingToBytes(input, field) {
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
export function agentIdFromPublicKey(pub) {
    if (!pub || pub.length !== 32) {
        throw new Error('ed25519 public key must be 32 bytes');
    }
    return `agent:pk:ed25519:${bytesToBase64URLNoPadding(pub)}`;
}
export function agentIdV2FromP256PublicKey(pub) {
    if (!pub || pub.length !== 65 || pub[0] !== 0x04) {
        throw new Error('p256 public key must be SEC1 uncompressed 65 bytes');
    }
    p256PublicKeyFromSec1Uncompressed(pub);
    return `agent:v2:pk:p256:${bytesToBase64URLNoPadding(pub)}`;
}
export function parseAgentId(id) {
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
export function isValidAgentId(id) {
    try {
        parseAgentId(id);
        return true;
    }
    catch {
        return false;
    }
}
function parseRFC3339UTC(ts, field) {
    if (!ts.endsWith('Z')) {
        throw new Error(`${field} must be RFC3339 UTC`);
    }
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) {
        throw new Error(`${field} must be RFC3339 UTC`);
    }
}
function validateBase64URLNoPadding(v, field) {
    if (!v || v.includes('=') || !/^[A-Za-z0-9_-]+$/.test(v)) {
        throw new Error(`${field} must be base64url without padding`);
    }
    base64URLNoPaddingToBytes(v, field);
}
function normalizeCommerceIntentV1(intent) {
    if (intent.version !== 'commerce-intent-v1')
        throw new Error('version must be commerce-intent-v1');
    if (!intent.intent_id || !intent.contract_id)
        throw new Error('intent_id and contract_id are required');
    if (!isValidAgentId(intent.buyer_agent) || !isValidAgentId(intent.seller_agent))
        throw new Error('buyer_agent and seller_agent must be valid agent-id-v1');
    if (!Array.isArray(intent.items) || intent.items.length === 0)
        throw new Error('items are required');
    for (const item of intent.items) {
        if (!item?.sku)
            throw new Error('item.sku is required');
        if (!Number.isInteger(item.qty) || item.qty < 1)
            throw new Error('item.qty must be integer >= 1');
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
function normalizeCommerceAcceptV1(acc) {
    if (acc.version !== 'commerce-accept-v1')
        throw new Error('version must be commerce-accept-v1');
    if (!acc.contract_id)
        throw new Error('contract_id is required');
    if (!/^[0-9a-f]{64}$/.test(acc.intent_hash))
        throw new Error('intent_hash must be lowercase hex sha256');
    parseRFC3339UTC(acc.accepted_at, 'accepted_at');
    validateBase64URLNoPadding(acc.nonce, 'nonce');
    return { ...acc, metadata: acc.metadata ?? {} };
}
const delegationAllowedKeys = new Set(['version', 'delegation_id', 'issuer_agent', 'subject_agent', 'scopes', 'constraints', 'nonce', 'issued_at']);
const delegationConstraintAllowedKeys = new Set(['contract_id', 'counterparty_agent', 'max_amount', 'valid_from', 'valid_until', 'max_uses', 'purpose']);
const delegationRevocationAllowedKeys = new Set(['version', 'revocation_id', 'delegation_id', 'issuer_agent', 'nonce', 'issued_at', 'reason']);
const knownDelegationScopes = new Set(['commerce:intent:sign', 'commerce:accept:sign', 'cel:action:execute', 'cel:approval:sign', 'settlement:attest']);
const amountExponents = { USD: 2, EUR: 2, GBP: 2, JPY: 0, KRW: 0, INR: 2, CHF: 2, CAD: 2, AUD: 2 };
function parseNormalizedAmountToMinor(amount) {
    const currency = String(amount.currency ?? '').trim().toUpperCase();
    const value = String(amount.amount ?? '').trim();
    if (!/^[A-Z]{3}$/.test(currency))
        throw new Error('amount currency must be ISO4217 uppercase 3 letters');
    const exp = amountExponents[currency];
    if (exp === undefined)
        throw new Error('unknown currency');
    if (!value || value.startsWith('+') || /e|E/.test(value))
        throw new Error('amount must be normalized decimal');
    if ((value.match(/\./g) ?? []).length > 1)
        throw new Error('amount must be normalized decimal');
    const [intPart, fracPartRaw = ''] = value.split('.');
    if (!/^\d+$/.test(intPart))
        throw new Error('amount must be normalized decimal');
    if (intPart.length > 1 && intPart.startsWith('0'))
        throw new Error('amount must be normalized decimal');
    if (fracPartRaw && (!/^\d+$/.test(fracPartRaw) || fracPartRaw.endsWith('0')))
        throw new Error('amount must be normalized decimal');
    if (exp === 0) {
        if (fracPartRaw)
            throw new Error('amount must be normalized decimal');
        return BigInt(intPart);
    }
    if (fracPartRaw.length > exp)
        throw new Error('amount precision exceeds currency minor units');
    const frac = fracPartRaw.padEnd(exp, '0');
    return BigInt(intPart) * (BigInt(10) ** BigInt(exp)) + BigInt(frac || '0');
}
function normalizeDelegationV1(payload) {
    const keys = Object.keys(payload);
    for (const k of keys)
        if (!delegationAllowedKeys.has(k))
            throw new Error(`unknown delegation key: ${k}`);
    if (payload.version !== 'delegation-v1')
        throw new Error('version must be delegation-v1');
    if (!payload.delegation_id)
        throw new Error('delegation_id is required');
    if (!isValidAgentId(payload.issuer_agent) || !isValidAgentId(payload.subject_agent))
        throw new Error('issuer_agent and subject_agent must be valid agent-id-v1');
    if (!Array.isArray(payload.scopes) || payload.scopes.length === 0)
        throw new Error('scopes must be non-empty');
    const scopes = Array.from(new Set(payload.scopes.map((s) => String(s).trim()))).sort();
    for (const s of scopes)
        if (!knownDelegationScopes.has(s))
            throw new Error(`unknown scope: ${s}`);
    const c = payload.constraints;
    if (!c || typeof c !== 'object')
        throw new Error('constraints is required');
    for (const k of Object.keys(c))
        if (!delegationConstraintAllowedKeys.has(k))
            throw new Error(`unknown delegation constraint key: ${k}`);
    const contractId = String(c.contract_id ?? '').trim();
    const counterparty = String(c.counterparty_agent ?? '').trim();
    if (!contractId)
        throw new Error('constraints.contract_id is required');
    if (!counterparty)
        throw new Error('constraints.counterparty_agent is required');
    if (counterparty !== '*' && !isValidAgentId(counterparty))
        throw new Error('constraints.counterparty_agent must be * or valid agent-id-v1');
    parseRFC3339UTC(String(c.valid_from ?? ''), 'constraints.valid_from');
    parseRFC3339UTC(String(c.valid_until ?? ''), 'constraints.valid_until');
    if (new Date(String(c.valid_from)).getTime() > new Date(String(c.valid_until)).getTime())
        throw new Error('constraints.valid_from must be <= constraints.valid_until');
    if (c.max_uses !== undefined && c.max_uses !== null && (!Number.isInteger(c.max_uses) || Number(c.max_uses) < 1))
        throw new Error('constraints.max_uses must be integer >=1');
    if (c.max_amount !== undefined && c.max_amount !== null)
        parseNormalizedAmountToMinor(c.max_amount);
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
            ...(c.max_amount ? { max_amount: c.max_amount } : {}),
            ...(c.max_uses ? { max_uses: Number(c.max_uses) } : {}),
            ...(c.purpose !== undefined ? { purpose: String(c.purpose) } : {}),
        },
    };
}
export function parseSigV1(sig, expectedContext) {
    const allowed = new Set(['version', 'algorithm', 'public_key', 'signature', 'payload_hash', 'issued_at', 'context', 'key_id']);
    for (const k of Object.keys(sig))
        if (!allowed.has(k))
            throw new Error(`unknown signature key: ${k}`);
    if (sig.version !== 'sig-v1')
        throw new Error('signature_envelope version must be sig-v1');
    if (sig.algorithm !== 'ed25519')
        throw new Error('signature_envelope algorithm must be ed25519');
    if (!/^[0-9a-f]{64}$/.test(sig.payload_hash))
        throw new Error('payload_hash must be lowercase hex sha256');
    parseRFC3339UTC(sig.issued_at, 'issued_at');
    if (expectedContext && sig.context && sig.context !== expectedContext)
        throw new Error('signature context mismatch');
    const pub = Buffer.from(sig.public_key, 'base64');
    const signature = Buffer.from(sig.signature, 'base64');
    if (pub.length !== 32 || signature.length !== 64)
        throw new Error('invalid signature encoding');
    return sig;
}
export function parseSigV2(sig, expectedContext) {
    const allowed = new Set(['version', 'algorithm', 'public_key', 'signature', 'payload_hash', 'issued_at', 'context', 'key_id']);
    for (const k of Object.keys(sig))
        if (!allowed.has(k))
            throw new Error(`unknown signature key: ${k}`);
    if (sig.version !== 'sig-v2')
        throw new Error('signature_envelope version must be sig-v2');
    if (sig.algorithm !== 'es256')
        throw new Error('signature_envelope algorithm must be es256');
    if (!/^[0-9a-f]{64}$/.test(sig.payload_hash))
        throw new Error('payload_hash must be lowercase hex sha256');
    parseRFC3339UTC(sig.issued_at, 'issued_at');
    if (expectedContext && sig.context && sig.context !== expectedContext)
        throw new Error('signature context mismatch');
    const pub = base64URLNoPaddingToBytes(sig.public_key, 'signature public key');
    if (pub.length !== 65 || pub[0] !== 0x04)
        throw new Error('invalid signature public_key encoding');
    p256PublicKeyFromSec1Uncompressed(pub);
    const rawSig = base64URLNoPaddingToBytes(sig.signature, 'signature');
    if (rawSig.length !== 64)
        throw new Error('invalid signature encoding');
    return sig;
}
export function parseSignatureEnvelope(sig, expectedContext) {
    if (!sig || typeof sig !== 'object')
        throw new Error('signature_envelope must be object');
    if (sig.version === 'sig-v1')
        return parseSigV1(sig, expectedContext);
    if (sig.version === 'sig-v2')
        return parseSigV2(sig, expectedContext);
    throw new Error('signature_envelope version must be sig-v1 or sig-v2');
}
export function normalizeAmountV1(currency, minorUnits) {
    if (!Number.isInteger(minorUnits) || minorUnits < 0)
        throw new Error('minor units must be non-negative integer');
    const ccy = String(currency ?? '').trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(ccy))
        throw new Error('currency must be ISO4217 uppercase 3 letters');
    const exp = amountExponents[ccy];
    if (exp === undefined)
        throw new Error('unknown currency');
    if (exp === 0)
        return { currency: ccy, amount: String(minorUnits) };
    const base = 10 ** exp;
    const integer = Math.floor(minorUnits / base);
    const fraction = minorUnits % base;
    let amount = `${integer}.${String(fraction).padStart(exp, '0')}`;
    amount = amount.replace(/0+$/g, '').replace(/\.$/, '');
    if (!amount)
        amount = '0';
    return { currency: ccy, amount };
}
export function parseAmountV1(amount) {
    return parseNormalizedAmountToMinor(amount);
}
export function parseDelegationV1(payload) {
    return normalizeDelegationV1(payload);
}
export function parseDelegationRevocationV1(payload) {
    const keys = Object.keys(payload);
    for (const k of keys)
        if (!delegationRevocationAllowedKeys.has(k))
            throw new Error(`unknown delegation revocation key: ${k}`);
    if (payload.version !== 'delegation-revocation-v1')
        throw new Error('version must be delegation-revocation-v1');
    if (!payload.revocation_id)
        throw new Error('revocation_id is required');
    if (!payload.delegation_id)
        throw new Error('delegation_id is required');
    if (!isValidAgentId(payload.issuer_agent))
        throw new Error('issuer_agent must be valid agent-id-v1');
    validateBase64URLNoPadding(payload.nonce, 'nonce');
    parseRFC3339UTC(payload.issued_at, 'issued_at');
    return payload;
}
export function newCommerceIntentV1(payload) {
    return normalizeCommerceIntentV1({
        version: 'commerce-intent-v1',
        nonce: bytesToBase64URLNoPadding(randomBytes(16)),
        metadata: payload.metadata ?? {},
        ...payload,
    });
}
export function newCommerceAcceptV1(payload) {
    return normalizeCommerceAcceptV1({
        version: 'commerce-accept-v1',
        nonce: bytesToBase64URLNoPadding(randomBytes(16)),
        metadata: payload.metadata ?? {},
        ...payload,
    });
}
export function newDelegationV1(payload) {
    return normalizeDelegationV1({
        version: 'delegation-v1',
        nonce: bytesToBase64URLNoPadding(randomBytes(16)),
        ...payload,
    });
}
export function newDelegationRevocationV1(payload) {
    return parseDelegationRevocationV1({
        version: 'delegation-revocation-v1',
        nonce: bytesToBase64URLNoPadding(randomBytes(16)),
        ...payload,
    });
}
export function sigV1Sign(context, payloadHash, secretKey, issuedAt, keyId) {
    if (!/^[0-9a-f]{64}$/.test(payloadHash))
        throw new Error('payload_hash must be lowercase hex sha256');
    if (!secretKey || secretKey.length !== 64)
        throw new Error('ed25519 secretKey must be 64 bytes (tweetnacl format)');
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
export function sigV2Sign(context, payloadHash, privateKey, issuedAt, keyId) {
    if (!/^[0-9a-f]{64}$/.test(payloadHash))
        throw new Error('payload_hash must be lowercase hex sha256');
    if (!privateKey)
        throw new Error('es256 private key is required');
    const keyObj = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
    const msg = Buffer.from(payloadHash, 'hex');
    const sigRaw = cryptoSign(null, msg, { key: keyObj, dsaEncoding: 'ieee-p1363' });
    if (sigRaw.length !== 64)
        throw new Error('invalid es256 signature length');
    const pubDer = createPublicKey(keyObj).export({ type: 'spki', format: 'der' });
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
export function parseProofBundleV1(proof) {
    if (!proof || typeof proof !== 'object')
        throw new Error('proof bundle must be object');
    const allowed = new Set(['version', 'protocol', 'protocol_version', 'bundle']);
    for (const k of Object.keys(proof))
        if (!allowed.has(k))
            throw new Error(`unknown proof bundle key: ${k}`);
    if (proof.version !== 'proof-bundle-v1')
        throw new Error('version must be proof-bundle-v1');
    if (proof.protocol !== 'contract-lane')
        throw new Error('protocol must be contract-lane');
    if (String(proof.protocol_version ?? '') !== '1')
        throw new Error('protocol_version must be 1');
    if (!proof.bundle || typeof proof.bundle !== 'object')
        throw new Error('bundle is required');
    if (!proof.bundle.contract || !proof.bundle.contract.contract_id)
        throw new Error('bundle.contract.contract_id is required');
    if (!proof.bundle.evidence || typeof proof.bundle.evidence !== 'object')
        throw new Error('bundle.evidence is required');
    return proof;
}
export function computeProofId(proof) {
    parseProofBundleV1(proof);
    return canonicalSha256Hex(proof);
}
function verifyProofBundleSignatures(proof) {
    const artifacts = ((proof.bundle.evidence || {}).artifacts || {});
    if (!artifacts || typeof artifacts !== 'object')
        throw new Error('evidence missing artifacts');
    for (const row of artifacts.commerce_intents ?? []) {
        if (row?.intent && row?.buyer_signature)
            verifyCommerceIntentV1(row.intent, row.buyer_signature);
    }
    for (const row of artifacts.commerce_accepts ?? []) {
        if (row?.accept && row?.seller_signature)
            verifyCommerceAcceptV1(row.accept, row.seller_signature);
    }
    for (const row of artifacts.delegations ?? []) {
        if (row?.delegation && row?.issuer_signature)
            verifyDelegationV1(row.delegation, row.issuer_signature);
    }
}
export function verifyProofBundleV1(proof) {
    try {
        const parsed = parseProofBundleV1(proof);
        const proofId = computeProofId(parsed);
        const evContractID = String(((parsed.bundle.evidence || {}).contract || {}).contract_id ?? '').trim();
        const contractID = String((parsed.bundle.contract || {}).contract_id ?? '').trim();
        if (!evContractID || evContractID !== contractID) {
            return { ok: false, code: 'INVALID_EVIDENCE', message: 'contract/evidence contract_id mismatch' };
        }
        verifyProofBundleSignatures(parsed);
        return { ok: true, code: 'VERIFIED', proof_id: proofId };
    }
    catch (err) {
        const msg = String(err?.message ?? err);
        let code = 'UNKNOWN_ERROR';
        if (msg.includes('version must be proof-bundle-v1') || msg.includes('protocol_version must be 1') || msg.includes('bundle.'))
            code = 'INVALID_SCHEMA';
        else if (msg.includes('evidence'))
            code = 'INVALID_EVIDENCE';
        else if (msg.includes('signature') || msg.includes('payload hash mismatch'))
            code = 'INVALID_SIGNATURE';
        else if (msg.includes('delegation_'))
            code = 'AUTHORIZATION_FAILED';
        else if (msg.includes('rules_'))
            code = 'RULES_FAILED';
        else
            code = 'MALFORMED_INPUT';
        return { ok: false, code, message: msg };
    }
}
export function hashDelegationV1(payload) {
    const normalized = normalizeDelegationV1(payload);
    return canonicalSha256Hex(normalized);
}
export function signDelegationV1(payload, secretKey, issuedAt) {
    const normalized = normalizeDelegationV1(payload);
    return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'delegation');
}
export function signDelegationV1ES256(payload, privateKey, issuedAt) {
    const normalized = normalizeDelegationV1(payload);
    return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'delegation');
}
export function verifyDelegationV1(payload, sig) {
    const normalized = normalizeDelegationV1(payload);
    const expected = hashDelegationV1(normalized);
    verifySignatureEnvelope(normalized, sig, 'delegation');
    if (sig.payload_hash !== expected)
        throw new Error('payload hash mismatch');
    if (agentIdFromSignatureEnvelope(sig) !== normalized.issuer_agent)
        throw new Error('signature public key does not match issuer_agent');
}
export function evaluateDelegationConstraints(constraints, evalCtx) {
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
    if (d.constraints.contract_id !== '*' && d.constraints.contract_id !== evalCtx.contract_id)
        throw new Error('delegation_constraints_failed');
    if (d.constraints.counterparty_agent !== '*' && d.constraints.counterparty_agent !== evalCtx.counterparty_agent)
        throw new Error('delegation_constraints_failed');
    const at = new Date(evalCtx.issued_at_utc).getTime();
    const from = new Date(d.constraints.valid_from).getTime();
    const until = new Date(d.constraints.valid_until).getTime();
    if (at < from || at > until)
        throw new Error('delegation_expired');
    if (d.constraints.max_amount && evalCtx.payment_amount) {
        const maxMinor = parseNormalizedAmountToMinor(d.constraints.max_amount);
        const payMinor = parseNormalizedAmountToMinor(evalCtx.payment_amount);
        if (String(d.constraints.max_amount.currency).toUpperCase() !== String(evalCtx.payment_amount.currency).toUpperCase() || payMinor > maxMinor) {
            throw new Error('delegation_amount_exceeded');
        }
    }
}
export function hashCommerceIntentV1(intent) {
    const normalized = normalizeCommerceIntentV1(intent);
    return canonicalSha256Hex(normalized);
}
export function signCommerceIntentV1(intent, secretKey, issuedAt) {
    const normalized = normalizeCommerceIntentV1(intent);
    return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'commerce-intent');
}
export function signCommerceIntentV1ES256(intent, privateKey, issuedAt) {
    const normalized = normalizeCommerceIntentV1(intent);
    return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'commerce-intent');
}
export function verifyCommerceIntentV1(intent, sig) {
    const normalized = normalizeCommerceIntentV1(intent);
    const expectedHash = hashCommerceIntentV1(normalized);
    if (sig.payload_hash !== expectedHash)
        throw new Error('payload hash mismatch');
    verifySignatureEnvelope(normalized, sig, 'commerce-intent');
}
export function hashCommerceAcceptV1(acc) {
    const normalized = normalizeCommerceAcceptV1(acc);
    return canonicalSha256Hex(normalized);
}
export function signCommerceAcceptV1(acc, secretKey, issuedAt) {
    const normalized = normalizeCommerceAcceptV1(acc);
    return buildSignatureEnvelopeV1(normalized, secretKey, issuedAt, 'commerce-accept');
}
export function signCommerceAcceptV1ES256(acc, privateKey, issuedAt) {
    const normalized = normalizeCommerceAcceptV1(acc);
    return buildSignatureEnvelopeV2(normalized, privateKey, issuedAt, 'commerce-accept');
}
export function verifyCommerceAcceptV1(acc, sig) {
    const normalized = normalizeCommerceAcceptV1(acc);
    const expectedHash = hashCommerceAcceptV1(normalized);
    if (sig.payload_hash !== expectedHash)
        throw new Error('payload hash mismatch');
    verifySignatureEnvelope(normalized, sig, 'commerce-accept');
}
export function buildSignatureEnvelopeV1(payload, secretKey, issuedAt, context = 'contract-action', keyId) {
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
export function buildSignatureEnvelopeV2(payload, privateKey, issuedAt, context = 'contract-action', keyId) {
    const payloadHash = canonicalSha256Hex(payload);
    return sigV2Sign(context, payloadHash, privateKey, issuedAt, keyId);
}
function spkiP256ToSec1Uncompressed(spkiDer) {
    // Minimal SPKI parser for EC P-256 keys produced by Node crypto.
    const p256SpkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
    if (spkiDer.length === p256SpkiPrefix.length + 65 && spkiDer.subarray(0, p256SpkiPrefix.length).equals(p256SpkiPrefix)) {
        const pub = spkiDer.subarray(p256SpkiPrefix.length);
        if (pub.length === 65 && pub[0] === 0x04)
            return Uint8Array.from(pub);
    }
    throw new Error('invalid es256 public key encoding');
}
function p256PublicKeyFromSec1Uncompressed(sec1Pub) {
    if (sec1Pub.length !== 65 || sec1Pub[0] !== 0x04)
        throw new Error('invalid signature public_key encoding');
    const p256SpkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
    const der = Buffer.concat([p256SpkiPrefix, Buffer.from(sec1Pub)]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
}
function parseES256SignatureCompat(sig) {
    try {
        const raw = Buffer.from(base64URLNoPaddingToBytes(sig, 'signature'));
        if (raw.length === 64)
            return { raw64: raw };
        throw new Error('invalid signature');
    }
    catch {
        // Compatibility path: accept DER in standard base64 from API boundary.
        const der = Buffer.from(sig, 'base64');
        if (!der.length)
            throw new Error('invalid signature encoding');
        return { der };
    }
}
function verifySignatureEnvelope(payload, sig, expectedContext) {
    const parsed = parseSignatureEnvelope(sig, expectedContext);
    const expectedHash = canonicalSha256Hex(payload);
    if (parsed.payload_hash !== expectedHash)
        throw new Error('payload hash mismatch');
    const msg = Buffer.from(expectedHash, 'hex');
    if (parsed.version === 'sig-v1') {
        const pub = Buffer.from(parsed.public_key, 'base64');
        const signature = Buffer.from(parsed.signature, 'base64');
        if (!nacl.sign.detached.verify(msg, signature, pub))
            throw new Error('invalid signature');
        return;
    }
    const pub = p256PublicKeyFromSec1Uncompressed(base64URLNoPaddingToBytes(parsed.public_key, 'signature public key'));
    const sigCompat = parseES256SignatureCompat(parsed.signature);
    if (sigCompat.raw64) {
        if (!cryptoVerify(null, msg, { key: pub, dsaEncoding: 'ieee-p1363' }, sigCompat.raw64))
            throw new Error('invalid signature');
        return;
    }
    if (!sigCompat.der || !cryptoVerify(null, msg, pub, sigCompat.der))
        throw new Error('invalid signature');
}
function agentIdFromSignatureEnvelope(sig) {
    if (sig.algorithm === 'ed25519') {
        return agentIdFromPublicKey(Buffer.from(sig.public_key, 'base64'));
    }
    return agentIdV2FromP256PublicKey(base64URLNoPaddingToBytes(sig.public_key, 'signature public key'));
}
