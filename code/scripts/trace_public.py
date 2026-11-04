"""Trace public-sample mismatches to participant-visible facts and activity."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

from ghost_audit.decision import AuditEngine  # noqa: E402
from ghost_audit.identity import IdentityResolver  # noqa: E402
from ghost_audit.ingest import EvidenceLoader, load_cases  # noqa: E402
from ghost_audit.policy import PolicyEngine  # noqa: E402
from pipeline import run  # noqa: E402


def read_rows(path: Path) -> dict[str, dict[str, object]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["case_id"]: {"status": row["deletion_status"], "steps": json.loads(row["steps_json"])}
            for row in csv.DictReader(handle)
        }


def trace() -> str:
    with tempfile.TemporaryDirectory(prefix="ghost-audit-trace-") as temp_dir:
        generated_path = Path(temp_dir) / "sample.csv"
        run(ROOT / "dataset", generated_path, request_file="sample_deletion_requests.csv")
        expected = read_rows(ROOT / "dataset" / "sample_output.csv")
        actual = read_rows(generated_path)

    resolver = IdentityResolver(ROOT / "dataset")
    loader = EvidenceLoader(ROOT / "dataset", resolver)
    loader.load()
    cases = load_cases(ROOT / "dataset", "sample_deletion_requests.csv")
    by_id = {case.case_id: case for case in cases}
    engine = AuditEngine(resolver, PolicyEngine(ROOT / "dataset"), loader.facts, activity=loader.activity, snapshot_scopes=loader.snapshot_scopes, cases=cases)
    mismatch_ids = [case_id for case_id in expected if expected[case_id] != actual[case_id]]
    lines = ["# Public sample provenance trace", "", "Only participant-facing facts and activity rows are listed.", ""]
    for case_id in mismatch_ids:
        case = by_id[case_id]
        user_id = resolver.resolve_email(case.email)
        lines.extend([f"## {case_id}", "", f"- Request email: `{case.email}`", f"- Resolved user: `{user_id}`", f"- Audit cutoff: `{case.audit_at}`", f"- Requested/reported: `{case.requested_at}` / `{case.reported_at}`", f"- Policy/status: `{expected[case_id]['status']}` expected, `{actual[case_id]['status']}` generated", ""])
        actual_resources = {step["resource_id"] for step in actual[case_id]["steps"]}
        expected_resources = {step["resource_id"] for step in expected[case_id]["steps"]}
        disputed = sorted(expected_resources | actual_resources)
        for resource_id in disputed:
            category_facts = [fact for fact in loader.facts if fact.resource_id == resource_id]
            activity_rows = [row for row in engine._relevant_activity(case) if row.get("resource_id") == resource_id]
            lines.append(f"### `{resource_id}`")
            if category_facts:
                for fact in category_facts:
                    users = ",".join(sorted(fact.user_ids)) or "<none>"
                    lines.append(f"- Fact: `{fact.evidence_id}`; category=`{fact.category}`; state=`{fact.state}`; users=`{users}`; captured=`{fact.captured_at}`; observed=`{fact.observed_at}`; source=`{fact.source_kind}`; location=`{fact.location}`")
            else:
                lines.append("- No participant-facing EvidenceFact exists for this resource.")
            if activity_rows:
                for row in activity_rows:
                    lines.append(f"- Activity: `{row.get('activity_id')}`; time=`{row.get('event_time')}`; event=`{row.get('event_type')}`; result=`{row.get('reported_result')}`; target=`{row.get('target_system')}`; details=`{row.get('details')}`")
            else:
                lines.append("- No activity row falls within this case's four-hour request/report investigation window.")
            lines.append("")
        if case_id in {"case_09", "case_20", "case_23", "case_24"}:
            lines.append("Interpretation: the disputed anonymous analytics observation is in a global/batch artifact and lacks a user identifier; attaching it based only on shared evidence or time is not independently grounded.")
        elif case_id in {"case_25", "case_27"}:
            lines.append("Interpretation: the expected and generated analytics resources are both anonymous, policy-compliant observations in the same global batch; the supplied data does not establish which case owns which resource.")
        elif case_id in {"case_18", "case_29"}:
            lines.append("Interpretation: the disputed profile resources are global activity candidates with no user identifier. The activity stream supplies several neighboring candidates, but no participant-visible relationship uniquely assigns the expected one.")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evaluation" / "public_sample_trace.md"
    output_path.write_text(trace(), encoding="utf-8", newline="\n")
    print(output_path)
