import os

from contractlane import ContractLaneClient, PrincipalAuth, new_idempotency_key

client = ContractLaneClient(
    base_url=os.getenv("CONTRACTLANE_BASE_URL", "http://localhost:8082"),
    auth=PrincipalAuth(os.getenv("CONTRACTLANE_TOKEN", "")),
)

subject = os.getenv("EXTERNAL_SUBJECT_ID", "platform-user-1")
status = client.gate_status("terms_current", subject)
if status.get("status") == "BLOCKED":
    res = client.gate_resolve("terms_current", subject, "HUMAN", new_idempotency_key())
    next_step = res.get("next_step") or res.get("remediation") or {}
    print("continue_url:", next_step.get("continue_url"))
else:
    print("already compliant")

evidence = client.evidence("terms_current", subject)
print("evidence keys:", len(evidence.keys()))
