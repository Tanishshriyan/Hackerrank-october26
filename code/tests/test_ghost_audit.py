"""Small deterministic regression and team-created edge-case tests."""

from __future__ import annotations

import unittest
import csv
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from ghost_audit.decision import AuditEngine, authorizes_deletion  # noqa: E402
from ghost_audit.identity import IdentityResolver  # noqa: E402
from ghost_audit.models import Case, EvidenceFact  # noqa: E402
from ghost_audit.policy import PolicyEngine  # noqa: E402
from pipeline import run  # noqa: E402


UTC = timezone.utc
WHEN = datetime(2026, 9, 15, 12, tzinfo=UTC)


class StubResolver:
    def resolve_email(self, email: str) -> str | None:
        return "user_test" if email.lower() == "person@example.test" else None


def fact(resource: str, category: str, state: str, *, evidence: str = "evidence_test", users: set[str] | None = None) -> EvidenceFact:
    return EvidenceFact(
        evidence_id=evidence,
        captured_at=WHEN,
        observed_at=WHEN,
        system_id={
            "USER_PROFILE": "account_service",
            "ACCOUNT_TOMBSTONE": "identity_service",
            "BACKUP_ARCHIVE": "backup_service",
            "DATA_FLOW": "integration_service",
            "SECURITY_AUDIT_LOG": "security_service",
            "LEGAL_HOLD_RECORD": "legal_service",
        }.get(category, "analytics_platform"),
        resource_id=resource,
        category=category,
        state=state,
        user_ids=users or {"user_test"},
    )


def deletion_case(text: str = "Please permanently delete my account.") -> Case:
    return Case("team_case", "person@example.test", WHEN, "COMPLETE", WHEN, WHEN, text)


class GhostAuditTests(unittest.TestCase):
    def test_historical_identifier_resolves_from_participant_data(self) -> None:
        resolver = IdentityResolver(ROOT / "dataset")
        self.assertTrue(resolver.resolve_email("noah.f438085@outlook.com"))
        user_id = resolver.resolve_email("noah.f438085@outlook.com")
        self.assertIsNotNone(user_id)
        explanation = resolver.explain(user_id, "noah.f438085@outlook.com")
        self.assertEqual(explanation["match_type"], "historical_identifier")

    def test_team_tombstone_with_exposed_identifier_requires_redaction(self) -> None:
        engine = AuditEngine(
            StubResolver(),
            PolicyEngine(ROOT / "dataset"),
            [fact("tombstone_test", "ACCOUNT_TOMBSTONE", "PRESENT")],
        )
        result = engine.audit_case(deletion_case("Please delete my account but retain the internal tombstone."))
        operations = [step["operation"] for step in result.steps]
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(operations, ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"])
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_test")
        self.assertEqual(result.steps[1]["evidence_id"], "")

    def test_team_active_flow_and_restore_are_reported_before_record_work(self) -> None:
        engine = AuditEngine(
            StubResolver(),
            PolicyEngine(ROOT / "dataset"),
            [
                fact("account_test", "USER_PROFILE", "ABSENT"),
                fact("data_flow_test", "DATA_FLOW", "ACTIVE"),
                fact("backup_test", "BACKUP_ARCHIVE", "ACTIVE"),
            ],
        )
        result = engine.audit_case(deletion_case())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in result.steps],
            [
                "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW",
                "BLOCK_RESTORE",
                "VERIFY_RECORD_ABSENT",
                "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED",
            ],
        )

    def test_non_deletion_request_is_not_applicable(self) -> None:
        self.assertFalse(authorizes_deletion("Please change my email and keep the account active."))
        self.assertFalse(authorizes_deletion("Please stop the promotional emails only."))

    def test_public_pipeline_statuses_and_known_ambiguity_regression(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghost-audit-test-") as temp_dir:
            output_path = Path(temp_dir) / "sample.csv"
            run(ROOT / "dataset", output_path, request_file="sample_deletion_requests.csv")
            with output_path.open(encoding="utf-8-sig", newline="") as handle:
                actual = {row["case_id"]: row for row in csv.DictReader(handle)}
        with (ROOT / "dataset" / "sample_output.csv").open(encoding="utf-8-sig", newline="") as handle:
            expected = {row["case_id"]: row for row in csv.DictReader(handle)}
        self.assertEqual(set(actual), set(expected))
        self.assertTrue(all(actual[case_id]["deletion_status"] == expected[case_id]["deletion_status"] for case_id in expected))
        mismatch_ids = {case_id for case_id in expected if json.loads(actual[case_id]["steps_json"]) != json.loads(expected[case_id]["steps_json"])}
        self.assertEqual(mismatch_ids, {"case_09", "case_18", "case_20", "case_23", "case_24", "case_25", "case_27", "case_29"})

    def test_retained_security_and_legal_records_are_verified_in_order(self) -> None:
        engine = AuditEngine(
            StubResolver(),
            PolicyEngine(ROOT / "dataset"),
            [
                fact("account_test", "USER_PROFILE", "ABSENT"),
                fact("audit_test", "SECURITY_AUDIT_LOG", "PRESENT"),
                fact("hold_test", "LEGAL_HOLD_RECORD", "PRESENT"),
            ],
        )
        result = engine.audit_case(deletion_case())
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            [(step["operation"], step["resource_id"]) for step in result.steps],
            [
                ("VERIFY_RECORD_ABSENT", "account_test"),
                ("VERIFY_RECORD_PRESENT", "hold_test"),
                ("VERIFY_RECORD_PRESENT", "audit_test"),
            ],
        )

    def test_image_activity_mapping_keeps_real_evidence_provenance(self) -> None:
        resolver = IdentityResolver(ROOT / "dataset")
        from ghost_audit.ingest import EvidenceLoader

        loader = EvidenceLoader(ROOT / "dataset", resolver)
        facts = loader.load()
        marketing = [fact for fact in facts if fact.resource_id == "marketing_001"]
        self.assertTrue(marketing)
        self.assertTrue(any("user_09" in fact.user_ids and fact.evidence_id == "evidence_60" for fact in marketing))

    def test_pipeline_does_not_invent_high_numbered_profile_resource(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghost-audit-full-") as temp_dir:
            output_path = Path(temp_dir) / "full.csv"
            run(ROOT / "dataset", output_path)
            with output_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = {row["case_id"]: row for row in csv.DictReader(handle)}
        self.assertNotIn("account_009", rows["case_63"]["steps_json"])


if __name__ == "__main__":
    unittest.main()
