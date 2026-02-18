import test from 'node:test';
import assert from 'node:assert/strict';
import { ContractLaneClient, PrincipalAuth } from '../src/index.ts';

const CL_INTEGRATION = process.env.CL_INTEGRATION === '1';
const CL_CONFORMANCE = process.env.CL_CONFORMANCE === '1';
const CL_BASE_URL = process.env.CL_BASE_URL ?? 'http://localhost:8080';
const CL_IAL_BASE_URL = process.env.CL_IAL_BASE_URL ?? 'http://localhost:8081';

type Env = { baseUrl: string; ialUrl: string; token: string };

test('integration: gate status + resolve unions', { skip: !CL_INTEGRATION }, async () => {
  const env = await setup();
  const client = new ContractLaneClient({ baseUrl: env.baseUrl, auth: new PrincipalAuth(env.token) });
  const subject = `ts-sub-${ContractLaneClient.newIdempotencyKey()}`;

  const status = await client.gateStatus('terms_current', subject);
  assert.ok(status.status === 'DONE' || status.status === 'BLOCKED');

  const resolved = await client.gateResolve('terms_current', subject, 'HUMAN', ContractLaneClient.newIdempotencyKey());
  assert.ok(resolved.status === 'DONE' || resolved.status === 'BLOCKED');
  if (resolved.status === 'BLOCKED') {
    assert.ok(Boolean(resolved.nextStep || resolved.remediation));
  }
});

test('conformance: shared cases live smoke', { skip: !CL_CONFORMANCE }, async () => {
  const env = await setup();
  const client = new ContractLaneClient({ baseUrl: env.baseUrl, auth: new PrincipalAuth(env.token) });
  const blocked = await client.gateStatus('terms_current', `ts-conf-${ContractLaneClient.newIdempotencyKey()}`);
  assert.ok(blocked.status === 'DONE' || blocked.status === 'BLOCKED');
});

async function setup(): Promise<Env> {
  const principal = await postJSON(`${CL_IAL_BASE_URL}/ial/principals`, {
    name: 'SDK TS', jurisdiction: 'US', timezone: 'UTC',
  });
  const principalId = principal.principal.principal_id as string;

  const agent = await postJSON(`${CL_IAL_BASE_URL}/ial/actors/agents`, {
    principal_id: principalId,
    name: 'SDKTSAgent',
    auth: { mode: 'HMAC', scopes: ['cel.contracts:write', 'exec.signatures:send'] },
  });
  const token = agent.credentials.token as string;
  const agentId = agent.agent.actor_id as string;

  await postJSON(`${CL_BASE_URL}/cel/dev/seed-template`, { principal_id: principalId });
  await postJSON(`${CL_BASE_URL}/cel/programs`, {
    actor_context: { principal_id: principalId, actor_id: agentId, actor_type: 'AGENT', idempotency_key: ContractLaneClient.newIdempotencyKey() },
    key: 'terms_current',
    mode: 'STRICT_RECONSENT',
  }, token);
  await postJSON(`${CL_BASE_URL}/cel/programs/terms_current/publish`, {
    actor_context: { principal_id: principalId, actor_id: agentId, actor_type: 'AGENT', idempotency_key: ContractLaneClient.newIdempotencyKey() },
    required_template_id: 'tpl_nda_us_v1',
    required_template_version: 'v1',
  }, token);

  return { baseUrl: CL_BASE_URL, ialUrl: CL_IAL_BASE_URL, token };
}

async function postJSON(url: string, body: Record<string, unknown>, token?: string): Promise<any> {
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const txt = await resp.text();
  if (!resp.ok) throw new Error(`POST ${url} failed ${resp.status}: ${txt}`);
  return txt ? JSON.parse(txt) : {};
}
