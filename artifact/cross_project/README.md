# Cross-Project Generalizability
This experiment shows how BugAuditor can be applied to a codebase beyond Linux by taking two inputs:

```bash
bash artifact/cross_project/run.sh <repo> <seed_defensive_operation>
```

Prepare `config.json:program_paths.<repo>` with the target source tree.
The script uses **8 workers by default**. You can adjust the `--workers` option according to your machine's CPU cores and memory to further improve efficiency.


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

Outputs are written under `output/security_sensitive_data/<repo>/cross_project_live/`.At the end, it prints the located usage count, valid defensive-code context count, reasoning input count, inferred pattern count, and the pattern JSON path. It also writes `live_summary.csv` and `live_output_paths.md` to `artifact/results/cross_project/`.

Use reference mode to inspect the historical OpenSSL/FFmpeg aggregate counts without real running.:

```bash
bash artifact/cross_project/run.sh --reference
bash artifact/cross_project/run.sh openssl OPENSSL_free --reference
```

Reference mode prints the located usages, valid defensive-code snippets, and inferred defensive-pattern counts for the packaged examples. It also writes the corresponding pattern JSON files under `artifact/results/cross_project/reference_patterns/`, prints each JSON path, and writes `expected_output.txt` and `reference_output_paths.md` under `artifact/results/cross_project/`. 


For new projects, add a new key to `config.json:program_paths`, then run the same command shape with the new repo key and seed defensive operation.
