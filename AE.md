
## BugAuditor‘s Components

### Main Pipeline Scripts

| Component                      | Purpose                                                                                                                                                   | Output                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `secop_extend.py`              | Expands a seed security operation into related security operations.                                                                                       | `output/secop_data/<repo>_<seed>_extend_<iterations>.txt` |
| `run_pipeline.py`              | Controls the full BugAuditor pipeline. It runs defensive-code locating, pattern reasoning, and specification merging.                                     | Outputs under `output/vuln_data/<repo>/`                  |
| `defensivecodelocate.py`       | Defines `DefensiveCodeLocator`. It uses Weggli to locate defensive-code contexts and filters the results.                                                 | `contexts/<secop>.json`                                   |
| `vuln_op_reasoner.py`          | Defines `VulnOpReasoner` and `VulnOpReasonerRunner`. It reasons about defensive patterns and generates raw results, detailed results, and specifications. | `raw/`, `detail/`, `spec/`                                |
| `run_vuln_reasoner.py`         | Runs Stage 2 directly. It supports dominator analysis, LLM reporting, cached outputs, concurrency, and timeout control.                                   | `llm_inputs/`, `llm_reports/`, `raw/`, `detail/`, `spec/` |
| `defensive_pattern_auditor.py` | Audits generated defensive patterns and performs bug detection with LLM support.                                                                          | `output/vuln_data/<repo>/audit/*.json`                    |


```bash
run_pipeline.py
├── Stage 1: DefensiveCodeLocator (defensivecodelocate.py)
│   └── Weggli query -> filtering -> write contexts/<secop>.json
│
└── Stage 2: VulnOpReasonerRunner (vuln_op_reasoner.py)
    ├── read contexts/<secop>.json
    ├── VulnOpReasoner (per function)
    │   └── SecOpDominateAnalyzer
    │       └── BuildFuncCFG / CFGAnalyzer
    └── output raw / detail / spec -> combine -> spec_all
```


### Auxiliary Scripts and Utilities

| Component                          | Purpose                                                                                | Notes                                             |
| ---------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `secop_domination.py`              | Defines `SecOpDominateAnalyzer` for CFG-based domination analysis.                     | Used by `VulnOpReasoner`.                         |
| `src/utils/BuildFuncCFG.py`        | Integrates Joern to build function-level CFGs.                                         | Requires Joern.                                   |
| `src/utils/CFGAnalyzer.py`         | Provides CFG analysis utilities.                                                       | Used during domination analysis.                  |
| `scripts/utils/openai_client.py`   | Handles LLM API calls.                                                                 | Reads LLM configuration from YAML.                |
| `scripts/utils/openai_config.yaml` | Stores LLM API configuration.                                                          | Can be created from `openai_config.example.yaml`. |
| `config.json`                      | Stores paths, tool locations, model settings, iteration depth, and blacklist settings. | Main configuration file.                          |
| `config.example.json`              | Template configuration file.                                                           | Copy to `config.json` and edit local paths.       |

