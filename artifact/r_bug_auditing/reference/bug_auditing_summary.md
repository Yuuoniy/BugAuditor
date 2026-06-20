# Reproduced Bug Auditing

Pattern inputs: `26` defensive patterns from `artifact/r_bug_auditing/reference/defensive_patterns.csv`.
Default candidate plan: up to `10` comparable functions per pattern; detected bug cases are always included first.
Planned audit candidates: `224` (`20` detected bugs and `204` deterministic random comparable functions).
Detected-bug recall in the recorded run: `20/20`.
Completed audit candidates: `224/224`.
Unfinished records: `0` LLM errors, `0` missing-source records, `0` missing audit records.
Additional comparable-function reports in the recorded run: `31`.
Total bug reports produced in the recorded run: `51`.
Live LLM runs can vary; use the recall line and report files as the primary check.
Total tokens in the recorded run: `327356`.

Key files:

- `audit_candidate_plan.csv`: per-pattern comparable-function audit plan.
- `bug_reports.json`: vulnerability reports produced by the audit.
- `detected_bug_reports.json`: vulnerability reports for detected benchmark bugs only.
- `bug_auditing_results.csv`: recorded verdicts for all selected audit candidates.
- `detected_bug_overlap.csv`: overlap between detected benchmark bugs and detected bug reports.
- `bug_auditing_summary.json`: aggregate counts for the run.
