import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import nacl from 'tweetnacl';
import { ContractLaneClient, PrincipalAuth, AgentHmacAuth, IncompatibleNodeError, buildSignatureEnvelopeV1, canonicalSha256Hex, agentIdFromPublicKey, parseAgentId, isValidAgentId, hashCommerceIntentV1, signCommerceIntentV1, verifyCommerceIntentV1, hashCommerceAcceptV1, signCommerceAcceptV1, verifyCommerceAcceptV1, hashDelegationV1, signDelegationV1, verifyDelegationV1, evaluateDelegationConstraints } from '../src/index.ts';

test('gateResolve requires idempotency key', async () => {
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn: async () => new Response('{}', { status: 200 }) as any });
  await assert.rejects(() => client.gateResolve('terms_current', 'sub', 'HUMAN', undefined));
});

test('retry 429 then success', async () => {
  let n = 0;
  const fetchFn: typeof fetch = async () => {
    n++;
    if (n === 1) return new Response(JSON.stringify({ error_code: 'RATE_LIMIT', message: 'slow' }), { status: 429 }) as any;
    return new Response(JSON.stringify({ status: 'DONE' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn, retry: { maxAttempts: 3, baseDelayMs: 1 } });
  const out = await client.gateStatus('terms_current', 'x');
  assert.equal(out.status, 'DONE');
});

test('auth strategies set headers', () => {
  const req = { headers: {} as Record<string, string> };
  new PrincipalAuth('abc').apply(req as any, { method: 'GET', pathWithQuery: '/x', bodyBytes: '' });
  assert.equal(req.headers.Authorization, 'Bearer abc');

  const req2 = { headers: {} as Record<string, string> };
  new AgentHmacAuth('agt_1', 'sec').apply(req2 as any, { method: 'POST', pathWithQuery: '/x?a=1', bodyBytes: '{"a":1}' });
  assert.ok(req2.headers['X-CL-Signature']);
});

test('error model 401 surfaces structured error', async () => {
  const fetchFn: typeof fetch = async () => new Response(JSON.stringify({ error_code: 'UNAUTHORIZED', message: 'bad token', request_id: 'req_1' }), { status: 401 }) as any;
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('bad'), fetchFn, retry: { maxAttempts: 1 } });
  await assert.rejects(async () => client.gateStatus('terms_current', 'unauth'));
});

test('conformance cases exist', () => {
  const root = path.resolve(process.cwd(), '..', '..');
  const names = [
    'well_known_protocol_capabilities.json',
    'gate_status_done.json',
    'gate_status_blocked.json',
    'gate_resolve_requires_idempotency.json',
    'error_model_401.json',
    'retry_429_then_success.json',
    'sig_v1_approval_happy_path.json',
    'evidence_contains_anchors_and_receipts.json',
    'evp_verify_bundle_good.json',
    'agent_id_v1_roundtrip.json',
  ];
  for (const name of names) {
    const p = path.join(root, 'conformance', 'cases', name);
    assert.ok(fs.existsSync(p), `missing ${p}`);
  }
});

test('agent-id-v1 roundtrip and strict parsing', () => {
  const pub = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
  const expected = 'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
  const id = agentIdFromPublicKey(pub);
  assert.equal(id, expected);
  const parsed = parseAgentId(id);
  assert.equal(parsed.algo, 'ed25519');
  assert.deepEqual(Array.from(parsed.publicKey), Array.from(pub));
  assert.equal(isValidAgentId(id), true);
});

test('agent-id-v1 rejects invalid forms', () => {
  const invalid = [
    'Agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    'agent:pk:rsa:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
    'agent:pk:ed25519:AAECAwQF$gcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg',
  ];
  for (const id of invalid) {
    assert.throws(() => parseAgentId(id));
    assert.equal(isValidAgentId(id), false);
  }
  assert.throws(() => agentIdFromPublicKey(new Uint8Array(31)));
  assert.throws(() => agentIdFromPublicKey(new Uint8Array(33)));
});

test('agent-id-v1 conformance fixture', () => {
  const root = path.resolve(process.cwd(), '..', '..');
  const fixture = JSON.parse(fs.readFileSync(path.join(root, 'conformance', 'cases', 'agent_id_v1_roundtrip.json'), 'utf8'));
  const pub = Uint8Array.from(Buffer.from(fixture.public_key_hex, 'hex'));
  const id = agentIdFromPublicKey(pub);
  assert.equal(id, fixture.expected_agent_id);
  const parsed = parseAgentId(fixture.expected_agent_id);
  assert.equal(parsed.algo, 'ed25519');
  assert.deepEqual(Array.from(parsed.publicKey), Array.from(pub));
  assert.equal(isValidAgentId(fixture.expected_agent_id), true);
  for (const bad of fixture.invalid_agent_ids as string[]) {
    assert.equal(isValidAgentId(bad), false);
  }
});

function fixedIntent() {
  return {
    version: 'commerce-intent-v1' as const,
    intent_id: 'ci_test_001',
    contract_id: 'ctr_test_001',
    buyer_agent: 'agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    seller_agent: 'agent:pk:ed25519:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
    items: [
      { sku: 'sku_alpha', qty: 2, unit_price: { currency: 'USD', amount: '10.50' } },
      { sku: 'sku_beta', qty: 1, unit_price: { currency: 'USD', amount: '5.00' } },
    ],
    total: { currency: 'USD', amount: '26.00' },
    expires_at: '2026-02-20T12:00:00Z',
    nonce: 'bm9uY2VfdjE',
    metadata: {},
  };
}

function fixedAccept() {
  return {
    version: 'commerce-accept-v1' as const,
    contract_id: 'ctr_test_001',
    intent_hash: 'f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f',
    accepted_at: '2026-02-20T12:05:00Z',
    nonce: 'YWNjZXB0X25vbmNlX3Yx',
    metadata: {},
  };
}

test('commerce-intent-v1 known vector hash', () => {
  assert.equal(hashCommerceIntentV1(fixedIntent()), 'f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f');
});

test('commerce-accept-v1 known vector hash', () => {
  assert.equal(hashCommerceAcceptV1(fixedAccept()), '670a209431d7b80bc997fabf40a707952a6494af07ddf374d4efdd4532449e21');
});

test('commerce-intent-v1 sign and verify', () => {
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(11));
  const sig = signCommerceIntentV1(fixedIntent(), keyPair.secretKey, new Date('2026-02-20T11:00:00Z'));
  assert.equal(sig.context, 'commerce-intent');
  assert.doesNotThrow(() => verifyCommerceIntentV1(fixedIntent(), sig));
});

test('commerce-accept-v1 sign and verify', () => {
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(12));
  const sig = signCommerceAcceptV1(fixedAccept(), keyPair.secretKey, new Date('2026-02-20T11:05:00Z'));
  assert.equal(sig.context, 'commerce-accept');
  assert.doesNotThrow(() => verifyCommerceAcceptV1(fixedAccept(), sig));
});

test('commerce verify rejects wrong context and payload hash', () => {
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(13));
  const sig = signCommerceIntentV1(fixedIntent(), keyPair.secretKey, new Date('2026-02-20T11:10:00Z'));

  const badContext = { ...sig, context: 'commerce-accept' };
  assert.throws(() => verifyCommerceIntentV1(fixedIntent(), badContext as any));

  const badHash = { ...sig, payload_hash: '0'.repeat(64) };
  assert.throws(() => verifyCommerceIntentV1(fixedIntent(), badHash as any));
});

function fixedDelegation() {
  return {
    version: 'delegation-v1' as const,
    delegation_id: 'del_01HZX9Y0H2J7F2S0P5R8M6T4YA',
    issuer_agent: 'agent:pk:ed25519:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No',
    subject_agent: 'agent:pk:ed25519:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No',
    scopes: ['commerce:intent:sign', 'commerce:accept:sign'],
    constraints: {
      contract_id: 'ctr_offline_reference',
      counterparty_agent: 'agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo',
      max_amount: { currency: 'USD', amount: '250' },
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: '2026-12-31T23:59:59Z',
      max_uses: 5,
    },
    nonce: 'ZGVsZWdhdGlvbl9ub25jZV92MQ',
    issued_at: '2026-02-20T12:06:00Z',
  };
}

test('delegation-v1 known vector hash', () => {
  assert.equal(hashDelegationV1(fixedDelegation()), '75ef154464ecbfd012b7dc7e6fca65d81f10d6d56938cb085ec222f9790fb357');
});

test('delegation-v1 sign and verify', () => {
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(21));
  const sig = signDelegationV1(fixedDelegation(), keyPair.secretKey, new Date('2026-02-20T12:06:00Z'));
  assert.equal(sig.context, 'delegation');
  assert.doesNotThrow(() => verifyDelegationV1(fixedDelegation(), sig));
  const bad = { ...sig, context: 'commerce-intent' };
  assert.throws(() => verifyDelegationV1(fixedDelegation(), bad as any));
});

test('delegation constraints evaluation', () => {
  const c = fixedDelegation().constraints;
  assert.doesNotThrow(() => evaluateDelegationConstraints(c, {
    contract_id: 'ctr_offline_reference',
    counterparty_agent: c.counterparty_agent,
    issued_at_utc: '2026-02-18T00:00:00Z',
    payment_amount: { currency: 'USD', amount: '26' },
  }));
  assert.throws(() => evaluateDelegationConstraints(c, {
    contract_id: 'ctr_other',
    counterparty_agent: c.counterparty_agent,
    issued_at_utc: '2026-02-18T00:00:00Z',
  }));
  assert.throws(() => evaluateDelegationConstraints(c, {
    contract_id: 'ctr_offline_reference',
    counterparty_agent: c.counterparty_agent,
    issued_at_utc: '2027-01-01T00:00:00Z',
  }));
  assert.throws(() => evaluateDelegationConstraints(c, {
    contract_id: 'ctr_offline_reference',
    counterparty_agent: c.counterparty_agent,
    issued_at_utc: '2026-02-18T00:00:00Z',
    payment_amount: { currency: 'USD', amount: '251' },
  }));
});

test('buildSignatureEnvelopeV1 creates sig-v1 envelope', () => {
  const keyPair = nacl.sign.keyPair();
  const payload = { b: 2, a: 1 };
  const env = buildSignatureEnvelopeV1(payload, keyPair.secretKey, new Date('2026-02-18T12:00:00.000Z'));
  assert.equal(env.version, 'sig-v1');
  assert.equal(env.algorithm, 'ed25519');
  assert.equal(env.payload_hash, canonicalSha256Hex(payload));
  assert.ok(env.issued_at.endsWith('Z'));
  assert.equal(Buffer.from(env.public_key, 'base64').length, 32);
  assert.equal(Buffer.from(env.signature, 'base64').length, 64);
});

test('approvalDecide uses signature_envelope when signing key configured', async () => {
  let captured: Record<string, unknown> = {};
  let capsHits = 0;
  const fetchFn: typeof fetch = async (_url, init) => {
    if (String(_url).endsWith('/cel/.well-known/contractlane')) {
      capsHits++;
      return new Response(JSON.stringify({
        protocol: { name: 'contractlane', versions: ['v1'] },
        evidence: { bundle_versions: ['evidence-v1'], always_present_artifacts: ['anchors', 'webhook_receipts'] },
        signatures: { envelopes: ['sig-v1'], algorithms: ['ed25519'] },
      }), { status: 200 }) as any;
    }
    captured = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ approval_request_id: 'aprq_1', status: 'APPROVED' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn });
  const keyPair = nacl.sign.keyPair();
  client.setSigningKeyEd25519(keyPair.secretKey, 'kid_ts_1');

  await client.approvalDecide('aprq_1', {
    actor_context: { principal_id: 'prn_1', actor_id: 'act_1', actor_type: 'HUMAN' },
    decision: 'APPROVE',
    signed_payload: { contract_id: 'ctr_1', approval_request_id: 'aprq_1', nonce: 'n1' },
  });

  assert.equal(typeof captured.signature_envelope, 'object');
  assert.equal((captured as any).signature_envelope.version, 'sig-v1');
  assert.equal((captured as any).signed_payload_hash, canonicalSha256Hex((captured as any).signed_payload));
  assert.equal((captured as any).signature, undefined);
  assert.equal(capsHits, 1);
});

test('approvalDecide uses legacy signature when signing key is not configured', async () => {
  let captured: Record<string, unknown> = {};
  const fetchFn: typeof fetch = async (_url, init) => {
    captured = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ approval_request_id: 'aprq_1', status: 'APPROVED' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn });
  await client.approvalDecide('aprq_1', {
    actor_context: { principal_id: 'prn_1', actor_id: 'act_1', actor_type: 'HUMAN' },
    decision: 'APPROVE',
    signed_payload: { contract_id: 'ctr_1', approval_request_id: 'aprq_1', nonce: 'n1' },
    signature: { type: 'WEBAUTHN_ASSERTION', assertion_response: {} },
  });

  assert.equal(typeof captured.signature, 'object');
  assert.equal((captured as any).signature_envelope, undefined);
});

test('approvalDecide sig-v1 default path passes with valid capabilities', async () => {
  const keyPair = nacl.sign.keyPair();
  let decideHits = 0;
  const fetchFn: typeof fetch = async (url, init) => {
    const u = String(url);
    if (u.endsWith('/cel/.well-known/contractlane')) {
      return new Response(JSON.stringify({
        protocol: { name: 'contractlane', versions: ['v1'] },
        evidence: { bundle_versions: ['evidence-v1'], always_present_artifacts: ['anchors', 'webhook_receipts'] },
        signatures: { envelopes: ['sig-v1'], algorithms: ['ed25519'] },
      }), { status: 200 }) as any;
    }
    decideHits++;
    return new Response(JSON.stringify({ approval_request_id: 'aprq_1', status: 'APPROVED' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn });
  client.setSigningKeyEd25519(keyPair.secretKey);

  await assert.doesNotReject(async () => client.approvalDecide('aprq_1', {
    actor_context: { principal_id: 'prn_1', actor_id: 'act_1', actor_type: 'HUMAN' },
    decision: 'APPROVE',
    signed_payload: { contract_id: 'ctr_1', approval_request_id: 'aprq_1', nonce: 'n1' },
  }));
  assert.equal(decideHits, 1);
});

test('approvalDecide sig-v1 default path throws IncompatibleNodeError when sig-v1 missing', async () => {
  const keyPair = nacl.sign.keyPair();
  const fetchFn: typeof fetch = async (url) => {
    const u = String(url);
    if (u.endsWith('/cel/.well-known/contractlane')) {
      return new Response(JSON.stringify({
        protocol: { name: 'contractlane', versions: ['v1'] },
        evidence: { bundle_versions: ['evidence-v1'], always_present_artifacts: ['anchors', 'webhook_receipts'] },
        signatures: { envelopes: [], algorithms: ['ed25519'] },
      }), { status: 200 }) as any;
    }
    return new Response(JSON.stringify({ approval_request_id: 'aprq_1', status: 'APPROVED' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn });
  client.setSigningKeyEd25519(keyPair.secretKey);

  await assert.rejects(
    async () => client.approvalDecide('aprq_1', {
      actor_context: { principal_id: 'prn_1', actor_id: 'act_1', actor_type: 'HUMAN' },
      decision: 'APPROVE',
      signed_payload: { contract_id: 'ctr_1', approval_request_id: 'aprq_1', nonce: 'n1' },
    }),
    (err: any) => {
      assert.ok(err instanceof IncompatibleNodeError);
      assert.ok(Array.isArray(err.missing));
      assert.ok(err.missing.includes('signatures.envelopes:sig-v1'));
      return true;
    },
  );
});

test('approvalDecide disableCapabilityCheck skips capabilities fetch', async () => {
  const keyPair = nacl.sign.keyPair();
  let capsHits = 0;
  let decideHits = 0;
  const fetchFn: typeof fetch = async (url, init) => {
    const u = String(url);
    if (u.endsWith('/cel/.well-known/contractlane')) {
      capsHits++;
      throw new Error('capability fetch should not be called');
    }
    decideHits++;
    const parsed = JSON.parse(String(init?.body ?? '{}'));
    assert.equal(typeof parsed.signature_envelope, 'object');
    return new Response(JSON.stringify({ approval_request_id: 'aprq_1', status: 'APPROVED' }), { status: 200 }) as any;
  };
  const client = new ContractLaneClient({ baseUrl: 'http://example.com', auth: new PrincipalAuth('tok'), fetchFn, disableCapabilityCheck: true });
  client.setSigningKeyEd25519(keyPair.secretKey);

  await assert.doesNotReject(async () => client.approvalDecide('aprq_1', {
    actor_context: { principal_id: 'prn_1', actor_id: 'act_1', actor_type: 'HUMAN' },
    decision: 'APPROVE',
    signed_payload: { contract_id: 'ctr_1', approval_request_id: 'aprq_1', nonce: 'n1' },
  }));
  assert.equal(capsHits, 0);
  assert.equal(decideHits, 1);
});
