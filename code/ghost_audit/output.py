"""CSV serialization and strict contract validation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .models import AuditResult
from .policy import ALLOWED_STATE, OPERATION_ORDER

HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASES = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
REQUIRED_STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def case_sort_key(case_id: str) -> tuple[str, int | str]:
    prefix, separator, suffix = str(case_id).rpartition("_")
    if separator and suffix.isdigit():
        return prefix, int(suffix)
    return str(case_id), str(case_id)


def validate_results(results: Iterable[AuditResult], expected_case_ids: list[str] | None = None) -> list[str]:
    rows = list(results)
    errors: list[str] = []
    if expected_case_ids is not None:
        actual = [row.case_id for row in rows]
        if len(actual) != len(expected_case_ids):
            errors.append(f"row count {len(actual)} != {len(expected_case_ids)}")
        if set(actual) != set(expected_case_ids):
            errors.append("case id set differs from input")
    for row in rows:
        if row.deletion_status not in STATUSES:
            errors.append(f"{row.case_id}: invalid deletion_status {row.deletion_status}")
        if row.deletion_status == "NOT_APPLICABLE" and row.steps:
            errors.append(f"{row.case_id}: NOT_APPLICABLE must have no steps")
        numbers = [step.get("step_no") for step in row.steps]
        if numbers != list(range(1, len(row.steps) + 1)):
            errors.append(f"{row.case_id}: step numbers are not consecutive")
        previous = (-1, -1, "", "")
        for step in row.steps:
            if set(step) != REQUIRED_STEP_FIELDS:
                errors.append(f"{row.case_id}: step fields differ from contract")
            phase = step.get("phase")
            operation = step.get("operation")
            if phase not in PHASES or operation not in OPERATION_ORDER:
                errors.append(f"{row.case_id}: invalid phase or operation")
                continue
            if step.get("state") != ALLOWED_STATE[operation]:
                errors.append(f"{row.case_id}: invalid state for {operation}")
            if not isinstance(step.get("step_no"), int):
                errors.append(f"{row.case_id}: step_no is not an integer")
            current = (PHASES[phase], OPERATION_ORDER[operation], str(step.get("system_id")), str(step.get("resource_id")))
            if current < previous:
                errors.append(f"{row.case_id}: step ordering violation")
            previous = current
            evidence = step.get("evidence_id")
            if phase == "FINDING" and not evidence:
                errors.append(f"{row.case_id}: finding lacks evidence_id")
            if row.deletion_status == "COMPLETE" and phase == "VERIFICATION" and not evidence:
                errors.append(f"{row.case_id}: complete verification lacks evidence_id")
            if row.deletion_status == "INCOMPLETE" and phase in {"REMEDIATION", "VERIFICATION"} and evidence != "":
                errors.append(f"{row.case_id}: future step has non-empty evidence_id")
        if row.deletion_status == "COMPLETE" and any(step.get("phase") != "VERIFICATION" for step in row.steps):
            errors.append(f"{row.case_id}: complete case contains non-verification step")
    return errors


def write_output(path: Path, results: Iterable[AuditResult], expected_case_ids: list[str] | None = None) -> None:
    ordered = sorted(results, key=lambda row: case_sort_key(row.case_id))
    errors = validate_results(ordered, sorted(expected_case_ids, key=case_sort_key) if expected_case_ids is not None else None)
    if errors:
        raise ValueError("Output validation failed:\n" + "\n".join(errors[:100]))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER, lineterminator="\n")
        writer.writeheader()
        for result in ordered:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "deletion_status": result.deletion_status,
                    "steps_json": json.dumps(result.steps, ensure_ascii=False, separators=(",", ":")),
                }
            )


def read_output(path: Path) -> dict[str, tuple[str, list[dict[str, object]]]]:
    rows: dict[str, tuple[str, list[dict[str, object]]]] = {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != HEADER:
            raise ValueError(f"Unexpected output header: {reader.fieldnames}")
        for row in reader:
            rows[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))
    return rows

