"""Policy rules and exact output-operation mappings."""

from __future__ import annotations

import csv
from pathlib import Path


OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

ALLOWED_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


class PolicyEngine:
    def __init__(self, dataset_dir: Path) -> None:
        self.rules: dict[str, str] = {}
        self.conditions: dict[str, str] = {}
        with (dataset_dir / "deletion_rules.csv").open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                self.rules[row["data_category"]] = row["required_action"]
                self.conditions[row["data_category"]] = row.get("condition", "")

    def action_for(self, category: str) -> str | None:
        return self.rules.get(category)

    def expected_state(self, category: str) -> str | None:
        action = self.action_for(category)
        return {"DELETE": "ABSENT", "REDACT": "REDACTED", "ANONYMIZE": "ANONYMIZED", "RETAIN": "PRESENT"}.get(action)

    def remediation_operation(self, category: str) -> str | None:
        if category == "DATA_FLOW":
            return "DISABLE_DATA_FLOW"
        if category == "BACKUP_ARCHIVE":
            return "BLOCK_RESTORE"
        return {
            "DELETE": "DELETE_RECORD",
            "REDACT": "REDACT_RECORD",
            "ANONYMIZE": "ANONYMIZE_RECORD",
        }.get(self.action_for(category,))

    def verification_operation(self, category: str, state: str | None = None) -> str | None:
        if category == "DATA_FLOW":
            return "VERIFY_DATA_FLOW_DISABLED"
        if category == "BACKUP_ARCHIVE":
            return "VERIFY_RESTORE_BLOCKED"
        expected = state or self.expected_state(category)
        return {
            "ABSENT": "VERIFY_RECORD_ABSENT",
            "PRESENT": "VERIFY_RECORD_PRESENT",
            "REDACTED": "VERIFY_RECORD_REDACTED",
            "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED",
        }.get(expected or "")

    def finding_operation(self, category: str, state: str) -> str | None:
        if state == "UNKNOWN":
            return None
        if category == "DATA_FLOW" and state == "ACTIVE":
            return "REPORT_ACTIVE_DATA_FLOW"
        if category == "BACKUP_ARCHIVE" and state == "ACTIVE":
            return "REPORT_RESTORE_RISK"
        action = self.action_for(category)
        if action == "DELETE" and state != "ABSENT":
            return "REPORT_REMAINING_RECORD"
        if action in {"REDACT", "ANONYMIZE"} and state not in {"REDACTED", "ANONYMIZED"}:
            return "REPORT_EXPOSED_PII"
        return None

