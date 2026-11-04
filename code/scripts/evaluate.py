"""Evaluate public-sample output without using organizer-only data."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

from ghost_audit.models import AuditResult  # noqa: E402
from ghost_audit.output import validate_results  # noqa: E402
from pipeline import run  # noqa: E402


def read_rows(path: Path) -> dict[str, dict[str, object]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        result: dict[str, dict[str, object]] = {}
        for row in csv.DictReader(handle):
            result[row["case_id"]] = {
                "status": row["deletion_status"],
                "steps": json.loads(row["steps_json"]),
            }
        return result


def step_key(step: dict[str, object], *, include_evidence: bool = True) -> tuple[object, ...]:
    fields = ("phase", "system_id", "resource_id", "operation", "state")
    values = tuple(step.get(field) for field in fields)
    return values + ((step.get("evidence_id"),) if include_evidence else ())


def evaluate(reference_path: Path = ROOT / "dataset" / "sample_output.csv") -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="ghost-audit-eval-") as temp_dir:
        generated_path = Path(temp_dir) / "sample_output.csv"
        run(ROOT / "dataset", generated_path, request_file="sample_deletion_requests.csv")
        expected = read_rows(reference_path)
        actual = read_rows(generated_path)

    status_correct = sum(expected[cid]["status"] == actual[cid]["status"] for cid in expected)
    exact_cases = sum(expected[cid]["steps"] == actual[cid]["steps"] for cid in expected)
    expected_steps = [step for row in expected.values() for step in row["steps"]]
    actual_steps = [step for row in actual.values() for step in row["steps"]]
    expected_counter = Counter(step_key(step) for step in expected_steps)
    actual_counter = Counter(step_key(step) for step in actual_steps)
    overlap = sum((expected_counter & actual_counter).values())
    precision = overlap / len(actual_steps) if actual_steps else 1.0
    recall = overlap / len(expected_steps) if expected_steps else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    sequence_correct = 0
    field_total = 0
    field_correct = 0
    evidence_total = 0
    evidence_correct = 0
    false_completion = 0
    false_incompletion = 0
    for cid in expected:
        exp = expected[cid]
        got = actual[cid]
        sequence_correct += [step_key(s, include_evidence=False) for s in exp["steps"]] == [step_key(s, include_evidence=False) for s in got["steps"]]
        if exp["status"] == "COMPLETE" and got["status"] != "COMPLETE":
            false_completion += 1
        if exp["status"] != "COMPLETE" and got["status"] == "COMPLETE":
            false_incompletion += 1
        for exp_step, got_step in zip(exp["steps"], got["steps"]):
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                field_correct += exp_step.get(field) == got_step.get(field)
            if "evidence_id" in exp_step:
                evidence_total += 1
                evidence_correct += exp_step.get("evidence_id") == got_step.get("evidence_id")

    validation_rows = [AuditResult(cid, str(row["status"]), list(row["steps"])) for cid, row in actual.items()]
    validation_errors = validate_results(validation_rows, list(expected))
    return {
        "sample_cases": len(expected),
        "status_accuracy": status_correct / len(expected),
        "status_correct": status_correct,
        "exact_step_array_cases": exact_cases,
        "exact_step_array_accuracy": exact_cases / len(expected),
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "field_accuracy_aligned": field_correct / field_total if field_total else 1.0,
        "evidence_accuracy_aligned": evidence_correct / evidence_total if evidence_total else 1.0,
        "sequence_accuracy": sequence_correct / len(expected),
        "false_completion_cases": false_completion,
        "false_incompletion_cases": false_incompletion,
        "validation_error_count": len(validation_errors),
        "validation_errors": validation_errors,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), ensure_ascii=False, indent=2, sort_keys=True))
