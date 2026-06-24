# Cross-Project Generalizability

This experiment shows how BugAuditor can be applied to a codebase beyond Linux by taking two inputs:

```bash
bash artifact/cross_project/run.sh <repo> <seed_defensive_operation>
```

Prepare `config.json:program_paths.<repo>` with the target source tree.

```bash
bash artifact/cross_project/run.sh FFmpeg av_free --workers 8
```

Packaged OpenSSL/FFmpeg examples:

```bash
bash artifact/cross_project/run.sh openssl null-ptr-check
bash artifact/cross_project/run.sh openssl OPENSSL_free
bash artifact/cross_project/run.sh FFmpeg null-ptr-check
bash artifact/cross_project/run.sh FFmpeg av_free
```

Live outputs are written under `output/security_sensitive_data/<repo>/cross_project_live/`. The wrapper prints preflight, locating/reasoning, and summary-collection progress. During the long locating/reasoning stage, it prints a compact progress bar every 30 seconds with the elapsed time. At the end, it prints the located usage count, valid defensive-code context count, reasoning input count, inferred pattern count, and the pattern JSON path. It also writes `live_summary.csv` and `live_output_paths.md` to `artifact/results/cross_project/`.

Use reference mode to inspect the historical OpenSSL/FFmpeg aggregate counts without rerunning Weggli, Joern, or LLM calls:

```bash
bash artifact/cross_project/run.sh --reference
bash artifact/cross_project/run.sh openssl OPENSSL_free --reference
```

Reference mode prints the located usages, valid defensive-code snippets, and inferred defensive-pattern counts for the packaged examples. It also writes the corresponding pattern JSON files under `artifact/results/cross_project/reference_patterns/`, prints each JSON path, and writes `expected_output.txt` and `reference_output_paths.md` under `artifact/results/cross_project/`. It does not copy internal manifests or validation notes into the public result directory.

For new projects, add a new key to `config.json:program_paths`, then run the same command shape with the new repo key and seed defensive operation.
