# Cross-Project Generalizability
This experiment shows how BugAuditor can be applied to a codebase beyond Linux.

## Defensive pattern reasoning
```bash
bash artifact/cross_project/run.sh <repo> <seed_defensive_operation>
```

Prepare `config.json:program_paths.<repo>` with the target source tree.
The script uses 8 workers by default. You can adjust the `--workers` option according to your machine's CPU cores and memory to further improve efficiency.


```bash
bash artifact/cross_project/run.sh FFmpeg av_free --workers 8
# bash artifact/cross_project/run.sh FFmpeg av_free --workers 8  2976.65s user 82.93s system 650% cpu 7:50.32 total
```

Packaged OpenSSL/FFmpeg examples:
```bash
bash artifact/cross_project/run.sh openssl null-ptr-check
bash artifact/cross_project/run.sh openssl OPENSSL_free
bash artifact/cross_project/run.sh FFmpeg null-ptr-check
bash artifact/cross_project/run.sh FFmpeg av_free
```

Outputs are written under `output/security_sensitive_data/<repo>/cross_project_live/`. At the end, it prints the located usage count, valid defensive-code context count, reasoning input count, inferred pattern count, and the pattern JSON path. It also writes `live_summary.csv` and `live_output_paths.md` to `artifact/results/cross_project/`.

Use reference mode to inspect the historical OpenSSL/FFmpeg aggregate counts without real running.:

```bash
bash artifact/cross_project/run.sh --reference
bash artifact/cross_project/run.sh openssl OPENSSL_free --reference
```

Reference mode prints the located usages, valid defensive-code snippets, and inferred defensive-pattern counts for the packaged examples. It also writes the corresponding pattern JSON files under `artifact/results/cross_project/reference_patterns/`, prints each JSON path, and writes `expected_output.txt` and `reference_output_paths.md` under `artifact/results/cross_project/`. 


For new projects, add a new key to `config.json:program_paths`, then run the same command shape with the new repo key and seed defensive operation.

## Bug auditing

After defensive pattern reasoning, use the inferred pattern JSON for bug auditing. 
```bash
bash artifact/cross_project/run_bug_detection.sh openssl OPENSSL_free --pattern-limit 30 --candidate-limit 10 --workers 8
```

Parameters:

- `openssl`: repository key in `config.json:program_paths`.
- `OPENSSL_free`: seed defensive operation used to select generated patterns.
- `--pattern-limit 30`: use the first 30 inferred patterns from the pattern JSON.
- `--candidate-limit 10`: audit up to 10 comparable functions for each pattern.
- `--workers 8`: run up to 8 LLM audit workers.
- 
By default, the wrapper first looks for live mined patterns under `output/security_sensitive_data/openssl/cross_project_live/llm_reports/`.  You may also provide a pattern file explicitly:

```bash
bash artifact/cross_project/run_bug_detection.sh openssl OPENSSL_free \
  --pattern-file artifact/cross_project/reference/patterns/openssl_OPENSSL_free_patterns.json \
  --pattern-limit 30 --candidate-limit 10 --workers 8
```


Fo example, when audit the OpenSSL at commit `ac5592812d921`. We can obtain the bug report as below:
```json
{
  "pattern_index": 38,
  "pattern_name": "OPENSSL_free:enc_new:38",
  "pattern_source_func": "enc_new",
  "pattern_security_sensitive_behaviors": [
    "When OPENSSL_zalloc allocates memory for ctx, it creates memory leak risk because failure to free on error leads to resource exhaustion."
  ],
  "pattern_defensive_behaviors": [
    "The OPENSSL_free is executed when EVP_CIPHER_CTX_new returns NULL to prevent memory leaks by releasing ctx before function exit."
  ],
  "weggli_query": "_ $func(_){OPENSSL_zalloc(_);}",
  "buggy_function": "setup_trace_category",
  "buggy_function_path": "apps/openssl.c",
  "missing_defenses": [
    "OPENSSL_free(trace_data)"
  ],
  "bug_explanation": "The function allocates memory for trace_data using OPENSSL_zalloc but fails to free it in the error path when trace_data is non-NULL. In the error handling block, BIO_free_all(channel) is called but trace_data is not freed. Since trace_data is allocated locally and does not escape the function when the error path is taken, it creates a memory leak. ..."
},
```

This is buggy function `setup_trace_category` in OpenSSL `apps/openssl.c`, and the bug has been fixed in the latest version. You may also find some new bugs which haven't been fixed using this tool.
