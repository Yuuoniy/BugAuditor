# DeepSeek Rerun Summary

## Scope
- Correct the mistaken `gpt-4o-mini` LLM stage with official DeepSeek runs.
- Keep the same OpenSSL/FFmpeg seeds:
  - `null-ptr-check`
  - `OPENSSL_free`
  - `av_free`
- Evaluate three things separately:
  - LLM source-grounding quality
  - pattern-to-query coverage quality
  - full inconsistency judgement quality

## LLM Quality

| Repo | Seed | Correct | Incorrect | Unknown |
|------|------|---------|-----------|---------|
| openssl | `null-ptr-check` | 245 | 11 | 2 |
| openssl | `OPENSSL_free` | 39 | 0 | 85 |
| FFmpeg | `null-ptr-check` | 245 | 5 | 26 |
| FFmpeg | `av_free` | 40 | 1 | 54 |

## Pattern Coverage

| Repo | Seed | Patterns With Candidates | Total Candidates | Empty Query Patterns |
|------|------|--------------------------|------------------|----------------------|
| openssl | `null-ptr-check` | 159 / 258 | 1881 | 0 |
| openssl | `OPENSSL_free` | 66 / 124 | 910 | 7 |
| FFmpeg | `null-ptr-check` | 149 / 276 | 2938 | 2 |
| FFmpeg | `av_free` | 52 / 95 | 1325 | 2 |

## Full Inconsistency Judgement

| Repo | Seed | Patterns With Judged Candidates | Checked Functions | Bug Judgements | Uncertain |
|------|------|---------------------------------|-------------------|----------------|-----------|
| openssl | `null-ptr-check` | 159 / 258 | 1854 | 89 | 0 |
| openssl | `OPENSSL_free` | 66 / 124 | 905 | 7 | 0 |
| FFmpeg | `null-ptr-check` | 147 / 276 | 2941 | 92 | 0 |
| FFmpeg | `av_free` | 51 / 95 | 1320 | 24 | 1 |

## Main Findings
- The official DeepSeek endpoint completed the corrected LLM reruns successfully; only transient retryable connection errors remained.
- The old configured DeepSeek endpoint is unstable enough to leave clustered empty responses on `FFmpeg/av_free`.
- Pattern generation is still effectively one function to one template on all four runs; there is no meaningful deduplication yet.
- The earlier non-Linux null-check recall problem was largely caused by reusing Linux summary key-calls. Once those were disabled and queries were translated per pattern, OpenSSL/FFmpeg null-check coverage increased sharply.
- Free-style seeds still show much weaker source grounding and broad query expansion around allocation helpers such as `OPENSSL_malloc`, `OPENSSL_zalloc`, `av_malloc`, and `av_mallocz`.
- The corrected DeepSeek final judgement is far more conservative than the old `gpt-4o-mini` full bundle on free-style seeds:
  - OpenSSL `OPENSSL_free`: `905` checked, `7` bug judgements
  - FFmpeg `av_free`: `1320` checked, `24` bug judgements
- The corrected DeepSeek final judgement is much stronger on null-check seeds than the old bundle:
  - OpenSSL `null-ptr-check`: `1854` checked, `89` bug judgements
  - FFmpeg `null-ptr-check`: `2941` checked, `92` bug judgements
- Coverage counts and final checked counts are close but not identical because the real audit pass applies the actual per-pattern cap, source/reference exclusion, and cross-pattern de-dup during candidate judgement.

## Key Files
- OpenSSL `null-ptr-check`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/null-ptr-check_llm_accuracy_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/null-ptr-check_pattern_coverage_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/null-ptr-check_audit_all_deepseek-chat.json`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/null-ptr-check_all_deepseek_chat_summary.csv`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/null-ptr-check_all_deepseek_chat_bugs.json`
- OpenSSL `OPENSSL_free`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/OPENSSL_free_llm_accuracy_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/OPENSSL_free_pattern_coverage_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/OPENSSL_free_audit_all_deepseek-chat.json`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/OPENSSL_free_all_deepseek_chat_summary.csv`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/openssl/OPENSSL_free_all_deepseek_chat_bugs.json`
- FFmpeg `null-ptr-check`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/null-ptr-check_llm_accuracy_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/null-ptr-check_pattern_coverage_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/null-ptr-check_audit_all_deepseek-chat.json`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/null-ptr-check_all_deepseek_chat_summary.csv`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/null-ptr-check_all_deepseek_chat_bugs.json`
- FFmpeg `av_free`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/av_free_llm_accuracy_official_repaired.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/av_free_pattern_coverage_official.md`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/av_free_audit_all_deepseek-chat.json`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/av_free_all_deepseek_chat_summary.csv`
  - `output/full_eval/full_eval_20260418_stage2_llm_audit_deepseek_v3_2/FFmpeg/av_free_all_deepseek_chat_bugs.json`
