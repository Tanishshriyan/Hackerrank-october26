"""Command-line orchestration for the full deterministic audit."""

from __future__ import annotations

import json
from pathlib import Path

from ghost_audit.decision import AuditEngine
from ghost_audit.identity import IdentityResolver
from ghost_audit.ingest import EvidenceLoader, load_cases
from ghost_audit.output import write_output
from ghost_audit.policy import PolicyEngine


def run(dataset_dir: Path, output_path: Path, *, request_file: str = "deletion_requests.csv") -> dict[str, object]:
    resolver = IdentityResolver(dataset_dir)
    policy = PolicyEngine(dataset_dir)
    loader = EvidenceLoader(dataset_dir, resolver)
    facts = loader.load()
    cases = load_cases(dataset_dir, request_file)
    engine = AuditEngine(resolver, policy, facts, activity=loader.activity, snapshot_scopes=loader.snapshot_scopes, cases=cases)
    results = [engine.audit_case(case) for case in cases]
    write_output(output_path, results, [case.case_id for case in cases])
    counts: dict[str, int] = {}
    for result in results:
        counts[result.deletion_status] = counts.get(result.deletion_status, 0) + 1
    return {"cases": len(cases), "facts": len(facts), "status_counts": counts, "output": str(output_path)}


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    dataset_dir = repo_root / "dataset"
    output_path = repo_root / "output.csv"
    summary = run(dataset_dir, output_path)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()

