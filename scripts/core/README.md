# Core Scripts

## Entry Points

- `defensive_code_locating.py`: Stage 1, locate defensive-code contexts for a seed defensive operation.
- `defensive_pattern_reasoning.py`: Stage 2, run defensive pattern reasoning over located contexts.
- `bug_auditing.py`: Stage 3, audit comparable functions for inconsistent defensive handling.
- `defensive_op_extension.py`: expand a seed defensive operation to related wrapper operations.

## Internal Modules

- `internal/defensive_op_dominator_analysis.py`: Joern/CFG dominator analysis for a defensive operation.
- `internal/reasoning_engine.py`: core defensive pattern reasoning engine; extracts variable-related operation sequences and persists internal cache files.
- `internal/reasoning_llm.py`: runs LLM reasoning and saves parsed defensive patterns.
- `internal/prompt_builder.py`: builds prompts and calls the OpenAI-compatible API.

## Wrappers

- `wrappers/full_pipeline.py`: convenience wrapper for older full-pipeline runs. AE entry points live under `artifact/`.
