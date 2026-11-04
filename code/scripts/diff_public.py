"""Create an auditable, key-order-insensitive diff of public sample output."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

from pipeline import run  # noqa: E402


FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def read(path: Path) -> dict[str, dict[str, object]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["case_id"]: {
                "status": row["deletion_status"],
                "steps": json.loads(row["steps_json"]),
            }
            for row in csv.DictReader(handle)
        }


def canonical(step: dict[str, object]) -> tuple[object, ...]:
    return tuple(step.get(field) for field in FIELDS)


def format_step(step: dict[str, object]) -> str:
    return " / ".join(f"{field}={step.get(field)!r}" for field in ("step_no",) + FIELDS)


def create_diff() -> str:
    with tempfile.TemporaryDirectory(prefix="ghost-audit-public-diff-") as temp_dir:
        generated = Path(temp_dir) / "sample_generated.csv"
        run(ROOT / "dataset", generated, request_file="sample_deletion_requests.csv")
        expected = read(ROOT / "dataset" / "sample_output.csv")
        actual = read(generated)

    lines = ["# Public sample structural diff", "", "Object-key order and JSON whitespace are ignored; array order is preserved.", ""]
    mismatch_count = 0
    for case_id in expected:
        exp = expected[case_id]
        got = actual[case_id]
        if exp["status"] == got["status"] and exp["steps"] == got["steps"]:
            continue
        mismatch_count += 1
        exp_steps = list(exp["steps"])
        got_steps = list(got["steps"])
        expected_counter = Counter(canonical(step) for step in exp_steps)
        actual_counter = Counter(canonical(step) for step in got_steps)
        missing = expected_counter - actual_counter
        unexpected = actual_counter - expected_counter
        lines.extend([f"## {case_id}", "", f"- Expected status: `{exp['status']}`", f"- Actual status: `{got['status']}`", ""])
        lines.append("### Missing steps")
        if missing:
            for key, count in missing.items():
                lines.append(f"- `{count}x` " + " / ".join(f"{field}={value!r}" for field, value in zip(FIELDS, key)))
        else:
            lines.append("- None")
        lines.append("\n### Unexpected steps")
        if unexpected:
            for key, count in unexpected.items():
                lines.append(f"- `{count}x` " + " / ".join(f"{field}={value!r}" for field, value in zip(FIELDS, key)))
        else:
            lines.append("- None")
        lines.append("\n### Aligned field differences")
        aligned = False
        for index, (exp_step, got_step) in enumerate(zip(exp_steps, got_steps), 1):
            differences = [field for field in ("step_no",) + FIELDS if exp_step.get(field) != got_step.get(field)]
            if differences:
                aligned = True
                lines.append(f"- Position {index}: differing fields `{', '.join(differences)}`")
                lines.append(f"  - expected: `{format_step(exp_step)}`")
                lines.append(f"  - actual: `{format_step(got_step)}`")
        if not aligned:
            lines.append("- None")
        exp_sequence = [canonical(step) for step in exp_steps]
        got_sequence = [canonical(step) for step in got_steps]
        lines.append("\n### Array-order comparison")
        opcodes = SequenceMatcher(a=exp_sequence, b=got_sequence, autojunk=False).get_opcodes()
        for tag, i1, i2, j1, j2 in opcodes:
            if tag != "equal":
                lines.append(f"- `{tag}` expected[{i1}:{i2}] vs actual[{j1}:{j2}]")
        lines.append("")
    lines.insert(3, f"Mismatched cases: **{mismatch_count}**")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evaluation" / "public_sample_diff.md"
    output_path.write_text(create_diff(), encoding="utf-8", newline="\n")
    print(output_path)
