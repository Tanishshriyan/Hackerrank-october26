# Ghost Data Still Exists

Deterministic Python solution for the HackerRank Orchestrate October 2026
deletion-audit challenge.

## What is implemented

- Resolves current and historical user identifiers.
- Parses the supplied CSV, JSON, SQL, text, PDF, and image-linked evidence.
- Reconstructs resource state at each request's `audit_at` cutoff.
- Applies the supplied deletion policy, including retained records and account
  tombstones.
- Produces ordered finding, remediation, and verification steps in the
  required `output.csv` format.
- Includes a contract validator, public-sample evaluator, and regression tests.

The production path is local and deterministic. It makes no model API calls
and requires no API keys.

## Requirements

- Python 3.10 or newer.
- The optional `pypdf` dependency listed in `requirements.txt` for PDF text
  extraction. The implementation has a fallback when it is unavailable.

## Run

Run these commands from the repository root:

```powershell
python -m pip install -r requirements.txt
python code/main.py
python code/scripts/validate_output.py
python -m unittest discover -s code/tests -v
python code/scripts/evaluate.py
```

The pipeline reads participant-facing files from `dataset/` and writes the
generated prediction file to `output.csv`.

## Recorded results

The included evaluation report records a full run over 518 requests, with
2,437 normalized evidence facts and zero validator errors. The public sample
status accuracy was 32/32; exact step-array accuracy was 24/32. The remaining
step-array differences and one resource-grounding warning are documented in
`evaluation/evaluation_report.md`.

The included usage report records zero model calls and zero model-token cost.
