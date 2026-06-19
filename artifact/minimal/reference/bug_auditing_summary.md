# clk_put Bug-Auditing Run

This stage uses one mined defensive pattern from the previous stage:

- pattern source function: `berlin2q_clock_setup`
- security-sensitive operation: `of_clk_get_by_name`
- defensive operation: `clk_put`
- expected defense: release the acquired clock reference with `clk_put` on cleanup/error paths.

The script first builds the Weggli query for the pattern, records the comparable functions located by that query, and audits a fixed 10-function sample.

| metric | value |
|---|---:|
| pattern used | `berlin2q_clock_setup` |
| generated query | `_ $func(_){of_clk_get_by_name(_);}` |
| located comparable functions | 66 |
| sampled functions audited | 10 |
| reported issues | 6 |
| consistent functions | 4 |

Key files:

- `loaded_pattern.json`: the defensive pattern used by the audit.
- `generated_query.json`: the generated Weggli query.
- `located_comparable_functions.csv`: comparable functions found by the query.
- `sampled_comparable_functions.csv`: the fixed 10-function sample.
- `bug_auditing_results.csv`: LLM verdicts for the sampled functions.
- `bug_auditing_clk_put.json`: full LLM audit output for the fixed sample.
- `bug_reports_clk_put.json`: generated bug reports with vulnerability explanations.
- `runtime_cpu.csv`: runtime recorded for this reference run.
