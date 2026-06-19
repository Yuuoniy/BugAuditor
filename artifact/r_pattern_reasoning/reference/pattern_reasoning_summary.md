# Reproduced Defensive Pattern Reasoning

Default per-seed sample size: `200`.
Minimum accepted per-seed sample size: `50`.

| seed | defensive code samples | table operations included | reference inferred patterns | estimated tokens | estimated LLM seconds |
|---|---:|---:|---:|---:|---:|
| kfree | 200 | 30/30 | 200 | 251084 | 112.0 |
| of_node_put | 200 | 30/30 | 113 | 225235 | 64.508 |
| clk_put | 200 | 8/8 | 12 | 217700 | 596.967 |
| null-ptr-check | 200 | 30/30 | 198 | 220450 | 115.112 |
| negative-check | 200 | 30/30 | 200 | 226473 | 107.897 |
| err-ptr-check | 200 | 30/30 | 200 | 225471 | 111.378 |
| **TOTAL** | 1200 | 158/158 | 923 | 1366413 | 1107.862 |

Token/runtime values are estimates for the reduced sample, derived from packaged historical full pattern-reasoning logs.
The packaged `--reference` command copies these outputs without invoking Weggli, Joern, or an LLM.

Key files:

- `defensive_code_samples.csv`: selected defensive-code examples for each seed.
- `inferred_patterns.csv`: reference inferred patterns available for the selected examples.
- `inferred_pattern_files.csv`: where to find aggregate reference patterns and live per-seed parsed pattern files.
- `pattern_reasoning_summary.csv`: per-seed counts.
- `runtime_and_tokens.csv`: estimated token/runtime cost for the default sample.
- `table18_top30_security_sensitive_ops/*.txt`: top Table 18 security-sensitive operations used for coverage checks.
- `table18_top30_coverage.csv`: coverage of those operations by the packaged inferred patterns.
