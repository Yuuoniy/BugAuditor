# BugAuditor

## Overview
BugAuditor is an LLM-driven bug detection framework that uses inconsistent defensive handling as a new oracle for detecting project-specific bugs. Its key insight is that large software systems already contain abundant defensive code, where developers apply security operations to prevent bugs in security-sensitive contexts. When similar security-sensitive behaviors are handled defensively in some places but not in others, the inconsistency may indicate a real bug. 

BugAuditor first (1) identifies defensive code snippets across the codebase, then (2) infers defensive patterns that capture both the security-sensitive behavior and the required defensive handling. It finally (3) applies these patterns to audit similar code contexts and detect missing or inconsistent handling.




## Typical commands

1) locate defensvie code
```bash
python defensive_code_locate.py clk_put  linux --workers 32
```

2) infer the defensive pattern
```bash
python run_vuln_reasoner.py clk_put --step dominator
python run_vuln_reasoner.py clk_put --step llm
```

3) bug auditing
```bash
python defensive_pattern_auditor.py \
  --secop clk_put --repo linux \
  --all-patterns \
  --limit-per-pattern 100 \
  --llm-model xxxx \
  --workers 20 \
  --output output/vuln_data/linux/audit/clk_put_xxxx.json
```


## Prereqs
- Python packages: `networkx`, `tqdm`, `icecream`, `timeout_decorator`, plus `pydot`/`pygraphviz` if needed for DOT parsing.
- Tools: `weggli` in `weggli_path`; `joern` (with `joern-parse` and `joern-export` on PATH); Graphviz for dot support.
- Tree-sitter helpers are under `src/utils` (imports already adjusted).



## TODO
Improve the artifact to support reproducibility.
