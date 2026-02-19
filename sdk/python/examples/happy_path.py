from __future__ import annotations

import json
from pathlib import Path

from contractlane import compute_proof_id, parse_proof_bundle_v1, verify_proof_bundle_v1


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    proof = json.loads((root / "conformance" / "fixtures" / "agent-commerce-offline" / "proof_bundle_v1.json").read_text())
    parse_proof_bundle_v1(proof)
    proof_id = compute_proof_id(proof)
    report = verify_proof_bundle_v1(proof)
    print(json.dumps({"proof_id": proof_id, "report": report.__dict__}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
