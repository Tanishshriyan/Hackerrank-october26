"""Validate a generated submission against the participant-facing contract."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

from ghost_audit.ingest import EvidenceLoader, load_cases  # noqa: E402
from ghost_audit.identity import IdentityResolver  # noqa: E402
from ghost_audit.models import AuditResult  # noqa: E402
from ghost_audit.output import HEADER, case_sort_key, validate_results  # noqa: E402


def validate_file(output_path: Path, dataset_dir: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    cases = load_cases(dataset_dir)
    expected_ids = [case.case_id for case in cases]
    resolver = IdentityResolver(dataset_dir)
    loader = EvidenceLoader(dataset_dir, resolver)
    facts = loader.load()
    known_evidence = {row["file_id"] for row in loader.manifest}
    known_evidence.update(row.get("activity_id", "") for row in loader.activity)
    known_evidence.update(row.get("audit_id", "") for row in loader.activity)
    known_resources = {fact.resource_id for fact in facts}
    known_resources.update(row.get("resource_id", "") for row in loader.activity)

    if not output_path.exists():
        return [f"missing output file: {output_path}"], warnings
    with output_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != HEADER:
            errors.append(f"header {reader.fieldnames!r} != {HEADER!r}")
        raw_rows = list(reader)
    if len(raw_rows) != len(expected_ids):
        errors.append(f"row count {len(raw_rows)} != expected {len(expected_ids)}")
    ids = [row.get("case_id", "") for row in raw_rows]
    if len(ids) != len(set(ids)):
        errors.append("duplicate case_id values")
    if set(ids) != set(expected_ids):
        errors.append("output case_id set differs from deletion_requests.csv")
    if ids != sorted(ids, key=case_sort_key):
        errors.append("rows are not sorted by natural case_id order")

    results: list[AuditResult] = []
    for row in raw_rows:
        case_id = row.get("case_id", "")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except json.JSONDecodeError as exc:
            errors.append(f"{case_id}: invalid steps_json: {exc}")
            steps = []
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not an array")
            steps = []
        for step in steps:
            if isinstance(step, dict):
                evidence_id = step.get("evidence_id", "")
                resource_id = step.get("resource_id", "")
                if evidence_id and evidence_id not in known_evidence:
                    errors.append(f"{case_id}: unknown evidence reference {evidence_id}")
                if resource_id and resource_id not in known_resources:
                    warnings.append(f"{case_id}: resource not directly observed in facts/activity: {resource_id}")
        results.append(AuditResult(case_id, row.get("deletion_status", ""), steps))
    errors.extend(validate_results(results, sorted(expected_ids, key=case_sort_key)))
    return sorted(set(errors)), sorted(set(warnings))


def main() -> int:
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "output.csv"
    errors, warnings = validate_file(output_path, ROOT / "dataset")
    print(json.dumps({"errors": errors, "warnings": warnings, "error_count": len(errors), "warning_count": len(warnings)}, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
