# Evaluation report

Run date: 2026-10-24. Results below are measured from the supplied
participant-facing dataset and the public reference sample. Public-sample
performance does not guarantee hidden-test performance.

## Dataset and final full run

- Requests processed: **518**.
- Normalized evidence facts: **2,437**.
- Evidence manifest entries: **94**.
- Output rows: **518**.
- Status counts: **171 `COMPLETE`**, **337 `INCOMPLETE`**, **10 `NOT_APPLICABLE`**.
- Validator errors: **0**.
- Validator warnings: **1**, for the documented inferred `account_003` in
  `case_45`. The earlier `account_009` warning was removed by deleting an
  unsupported `user_N -> account_N` fallback for suffixes above the narrow
  starter-account compatibility range.

## Public sample: before and after the final audit

The pipeline was run on all 32 rows of `sample_deletion_requests.csv` and
compared with `sample_output.csv`. JSON object-key order and whitespace are
ignored; array order is preserved.

| Metric | Before audit | Final measured |
| --- | ---: | ---: |
| Status accuracy | 32/32 = 1.0000 | 32/32 = 1.0000 |
| Exact step-array cases | 24/32 = 0.7500 | 24/32 = 0.7500 |
| Step precision | 0.9538 | 0.9538 |
| Step recall | 0.9637 | 0.9637 |
| Step F1 | 0.9588 | 0.9588 |
| Aligned field accuracy | 0.9814 | 0.9814 |
| Aligned evidence accuracy | 1.0000 | 1.0000 |
| Exact sequence accuracy | 24/32 = 0.7500 | 24/32 = 0.7500 |
| False completion cases | 0 | 0 |
| False incompletion cases | 0 | 0 |

The audit added diagnostics and regression coverage and made one full-dataset
grounding correction. It did not force a public-label match: the public metrics
are unchanged because the eight disputed sample cases remain participant-data
ambiguities rather than serialization defects.

## Case-by-case root causes for the eight mismatches

All eight cases have the correct status. Their step-array differences are:

| Case | Difference | Evidence-grounded root cause |
| --- | --- | --- |
| `case_09` | Extra verification for `analytics_5718` | `analytics_5718` is an anonymous `evidence_93` SQL observation with no user identifier. Its successful activity row is global batch activity, not a user link. |
| `case_18` | `account_5037` selected instead of `account_5521`; expected `audit_record_6645` is missing | The two profile resources have activity rows but no participant-facing identity mapping. `audit_record_6645` does not occur in participant evidence or activity, so the expected future verification target cannot be grounded. |
| `case_20` | Extra verification for `analytics_2265`; expected `audit_record_5569` is missing | `analytics_2265` is an anonymous global log observation. `audit_record_5569` is not present in participant evidence or activity. `account_5037` is the activity-linked profile selected by the available data. |
| `case_23` | `account_6440` selected instead of `account_410`; extra `analytics_5335` | `account_410` and `account_6440` are neighboring activity candidates without a user link. `analytics_5335` is anonymous in `evidence_02`/`evidence_92` and cannot be assigned to `user_23` from supplied facts. |
| `case_24` | Extra verification for `analytics_1895` | The analytics row is anonymous and global; the user is directly linked only to the account, search, and retained audit resources. |
| `case_25` | `analytics_4566` selected instead of `analytics_1895` | Both are anonymous anonymized rows in the same `evidence_92` batch. No user ID, email, hash, or explicit relationship selects one for `user_25`. |
| `case_27` | `analytics_6077` selected instead of `analytics_4574` | Both are anonymous anonymized rows in the same global batch. The supplied evidence does not distinguish ownership for `user_27`. |
| `case_29` | `account_5482` selected instead of `account_7012` | Both are anonymous profile candidates in the same report-time batch; neither is linked to the historical/current identity for `user_29`. |

`evaluation/public_sample_diff.md` contains the parsed expected/actual arrays,
missing and unexpected canonical steps, aligned field differences, and
array-order comparison. `evaluation/public_sample_trace.md` traces every
disputed resource to the participant facts and activity rows. The two missing
expected audit IDs are explicitly documented as absent rather than fabricated.

## Team-created regression tests

The production pipeline and deterministic components were exercised by **8
tests, 8 passed, 0 failed**:

1. Historical email resolution to a stable user ID.
2. Tombstone with a forbidden direct identifier requiring redaction.
3. Active synchronization and restore risks before record remediation.
4. Non-deletion requests classified as `NOT_APPLICABLE`.
5. Public pipeline status regression and explicit mismatch inventory.
6. Retained security/legal records and exact operation ordering.
7. Image activity mapping preserving real evidence provenance.
8. Full-pipeline regression preventing the removed high-numbered
   `account_009` inference.

These are team tests, not official answers.

## Improvements made

- Added deterministic, key-order-insensitive public diffing with array-order
  preservation.
- Added provenance tracing for every disputed public resource.
- Removed the unsupported numeric-user fallback that generated `account_009`
  without a participant-facing relationship.
- Preserved strict evidence validation and surfaced the remaining
  `account_003` inference as a warning.
- Added regression coverage for historical identities, tombstones, active
  flows/restores, retained records, image links, ordering, global-resource
  ambiguity, and grounding behavior.

## Remaining semantic risks

The eight resource-array mismatches remain unresolved by participant evidence.
The main risk is a global batch containing several anonymous resources whose
organizer-side ownership is not represented in the supplied files. The
implementation deliberately avoids assigning such a resource solely by
proximity. The `account_003` warning is a second, narrower risk caused by the
public starter-account convention; it should not be treated as direct evidence.
These limitations block a claim of fully submission-ready semantic accuracy,
even though the output is structurally valid and status accuracy on the public
sample is perfect.
