import fs from 'node:fs';
import path from 'node:path';
import { computeProofId, parseProofBundleV1, verifyProofBundleV1 } from '../src/index.ts';

const root = path.resolve(process.cwd(), '..', '..');
const proof = JSON.parse(fs.readFileSync(path.join(root, 'conformance', 'fixtures', 'agent-commerce-offline', 'proof_bundle_v1.json'), 'utf8'));
parseProofBundleV1(proof);
const proofId = computeProofId(proof);
const report = verifyProofBundleV1(proof);
console.log(JSON.stringify({ proof_id: proofId, report }, null, 2));
