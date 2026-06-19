# Reproduced Bug Auditing

Pattern inputs: `26` defensive patterns from `artifact/r_bug_auditing/reference/defensive_patterns.csv`.
Default candidate plan: up to `10` comparable functions per pattern; confirmed bugs are always included first.
Planned audit candidates: `224` (`20` confirmed bugs and `204` deterministic random comparable functions).
Known-bug recall in the recorded run: `20/20`.
Bug reports produced in the recorded run: `20`.
Live LLM runs can vary; use the recall line and report files as the primary check.
Total tokens in the recorded run: `40087`.

Key files:

- `audit_candidate_plan.csv`: per-pattern comparable-function audit plan.
- `bug_reports.json`: vulnerability reports for confirmed missing-defense cases.
- `bug_auditing_results.csv`: recorded verdicts for confirmed missing-defense cases.
- `bug_auditing_summary.json`: aggregate counts for the run.

