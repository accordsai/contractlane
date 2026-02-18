import { ContractLaneClient, PrincipalAuth } from '@contractlane/sdk';

const client = new ContractLaneClient({
  baseUrl: process.env.CONTRACTLANE_BASE_URL ?? 'http://localhost:8082',
  auth: new PrincipalAuth(process.env.CONTRACTLANE_TOKEN ?? ''),
});

const gate = 'terms_current';
const subject = process.env.EXTERNAL_SUBJECT_ID ?? 'platform-user-1';

const status = await client.gateStatus(gate, subject);
if (status.status === 'BLOCKED') {
  const res = await client.gateResolve(gate, subject, 'HUMAN', ContractLaneClient.newIdempotencyKey());
  console.log('continue_url:', res.nextStep?.continue_url ?? (res.remediation?.continue_url as string | undefined));
} else {
  console.log('already compliant');
}
const evidence = await client.evidence(gate, subject);
console.log('evidence keys:', Object.keys(evidence).length);
