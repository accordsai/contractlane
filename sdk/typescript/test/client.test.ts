import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ContractLaneClient, PrincipalAuth, AgentHmacAuth } from '../src/index.ts';

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
    'gate_status_done.json',
    'gate_status_blocked.json',
    'gate_resolve_requires_idempotency.json',
    'error_model_401.json',
    'retry_429_then_success.json',
  ];
  for (const name of names) {
    const p = path.join(root, 'conformance', 'cases', name);
    assert.ok(fs.existsSync(p), `missing ${p}`);
  }
});
