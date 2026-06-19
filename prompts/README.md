# Prompts

BugAuditor keeps only the prompts used by the artifact pipeline:

- `defensive_pattern_reasoning.txt`: used in defensive pattern reasoning to infer security-sensitive behavior and defensive behavior from a full function context.
- `extract_ast_query_operations.txt`: used in bug auditing to translate security-sensitive behavior into key AST query operations.
- `bug_detection_inconsistency_auditing.txt`: used in bug auditing to judge whether a comparable function is missing the expected defensive behavior.
- `defensive_pattern_validation.txt`: optional validation prompt used by `bug_auditing.py --pattern-llm-validate`.
