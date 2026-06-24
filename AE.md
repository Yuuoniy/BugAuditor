# BugAuditor Artifact Evaluation
This document provides the steps to evaluate **BugAuditor**. The artifact evaluation (AE) focuses on two core parts:

1. **Minimal Functional Example**
A small example using `clk_put` as the seed defensive operation. It demonstrates the full workflow in two stages:
- **Stage 1**: Locate defensive code and infer defensive patterns using the LLM.
- **Stage 2**: Use the mined patterns to perform bug auditing on comparable functions.

This part is lightweight and suitable for quick functional verification.

1. **Reproduced Reduced-Scale Evaluation**
A scaled-down reproduction of the main experiments from the paper, covering two stages:
- **Defensive Pattern Reasoning**: Infer defensive patterns from Linux kernel code using six seed defensive operations.
- **Bug Auditing**: Audit known missing-defense cases using the inferred patterns.


The full paper-scale experiments are computationally expensive (large-scale AST queries, Joern analysis, and many LLM calls). Therefore, the AE provides reduced-scale versions that preserve the core workflow, data, and results.
The reduced-scale versions keep LLM costs very low. Using a model such as DeepSeek-V4-Flash can bring the total cost to less than one dollar.

We also provide additional extension experiments (defensive operation extensibility and cross-project generalizability on OpenSSL/FFmpeg). These demonstrate broader capabilities of BugAuditor but are not required for the core artifact evaluation.

## Outline
- [BugAuditor Artifact Evaluation](#bugauditor-artifact-evaluation)
  - [Outline](#outline)
  - [Setup](#setup)
  - [Minimal Functional Example](#minimal-functional-example)
    - [Step 1: Locate Code and Reason Patterns](#step-1-locate-code-and-reason-patterns)
    - [Step 2: Bug Auditing](#step-2-bug-auditing)
  - [Reproduced Reduced-Scale Evaluation](#reproduced-reduced-scale-evaluation)
    - [Defensive Pattern Reasoning](#defensive-pattern-reasoning)
    - [Bug Auditing](#bug-auditing)
  - [Extension Experiments](#extension-experiments)
    - [1. Extensibility analysis.](#1-extensibility-analysis)
    - [2. Generalizability Study](#2-generalizability-study)
  - [Data for Paper Tables and Figures](#data-for-paper-tables-and-figures)


## Setup

Follow [INSTALL.md](INSTALL.md) to build the Docker image, prepare `source/linux`, and set the LLM endpoint in `config.json`.


## Minimal Functional Example

This example uses `clk_put` as the seed defensive operation. It runs two commands with default settings: 10 examples for pattern reasoning, a fixed 10-function comparable sample for bug auditing, and 8 workers.

### Step 1: Locate Code and Reason Patterns

**Intro.** This step locates Linux code snippets that use the seed defensive operation `clk_put`, selects 10 defensive code snippets, and performs defensive pattern reasoning for a quick functional test.

**Execution.**

```bash
bash artifact/minimal/run_pattern_reasoning.sh
```


**Output.** 

The key outputs in `artifact/results/minimal/` are:

| File Name                          | Description                        |
| ---------------------------------- | ---------------------------------- |
| `defensive_code_snippets.json`     | Collected defensive code snippets. |
| `inferred_defensive_patterns.json` | Inferred defensive patterns.       |


The file `defensive_code_snippets.json` records detailed information for each defensive code snippet. An example entry is shown below:

```json
{
    "function": "{func_code}",
    "func_name": "berlin2q_clock_setup",
    "var": "clk",
    "defensive_op": "clk_put",
    ...
}
```
The file `inferred_defensive_patterns.json` contains the corresponding inferred defensive patterns. An example entry is shown below:
```json
{
    "func_name": "berlin2q_clock_setup",
     ...
    "llm_output": {
        "security_sensitive_behaviors": "When of_clk_get_by_name acquires a clock reference for clk, it creates a reference leak risk because the clock reference must be released after use to avoid resource exhaustion.",
        "defensive_behaviors": "The clk_put is executed after ...",
        "analysis": "...",
    }
}
```


**Execution Time.** 

```text
bash artifact/minimal/run_pattern_reasoning.sh  7.54s user 2.91s system 62% cpu 16.638 total
```
**Reference Execution Output.**
```bash
bash artifact/minimal/run_pattern_reasoning.sh --reference
```

The `--reference` flag copies the packaged reference outputs to `artifact/results/minimal/`, enabling you to check the results without real execution.

### Step 2: Bug Auditing

**Intro.** This step audits comparable functions using one mined pattern from Step 1. The pattern is derived from the source function `berlin2q_clock_setup`, which contains the security-sensitive operation `of_clk_get_by_name` and the corresponding defensive operation `clk_put`.

The script automatically generates a weggli query to locate similar functions and then audits a fixed sample of 10 functions. It detects buggy functions such as `lpc32xx_clk_init` and `nmdk_timer_of_init`.

**Execution.**

```bash
bash artifact/minimal/run_bug_auditing.sh
```

**Input.** The pattern is read from `artifact/results/minimal/inferred_defensive_patterns.json`.

**Output.** The key results are written to `artifact/results/minimal/`:

| File                        | Description                                            |
| --------------------------- | ------------------------------------------------------ |
| `bug_auditing_results.csv`  | LLM verdicts for the sampled functions.                |
| `bug_auditing_clk_put.json` | Full live-run LLM audit output.                        |
| `bug_reports_clk_put.json`  | Generated bug reports with vulnerability explanations. |

Reference versions of the compact result files are in `artifact/minimal/reference/`. For example, the corresponding entry in `bug_reports_clk_put.json` explains why `lpc32xx_clk_init` is reported:
```json
{
    "buggy_function": "lpc32xx_clk_init",
    "buggy_function_path": "drivers/clk/nxp/clk-lpc32xx.c",
    "pattern_source_func": "berlin2q_clock_setup",
    "security_sensitive_operation": "of_clk_get_by_name",
    ...
    "bug_explanation": "The function acquires clock references via of_clk_get_by_name for clk_32k and clk_osc. On subsequent error paths (invalid rate for clk_32k, missing base, regmap failure), the function returns without releasing these acquired clock references, causing a resource leak. .."
},
```
**Execution Time.**

```text
bash artifact/minimal/run_bug_auditing.sh  8.44s user 2.29s system 103% cpu 10.406 total
```
**Reference Execution Output.**
```bash
bash artifact/minimal/run_bug_auditing.sh --reference
```

The `--reference` command copies the packaged 10-function reference result without real execution.

## Reproduced Reduced-Scale Evaluation

### Defensive Pattern Reasoning

**Intro.** This stage reproduces the defensive pattern reasoning process on the six seed defensive operations: `kfree`, `of_node_put`, `clk_put`, `null-ptr-check`, `negative-check`, and `err-ptr-check`.
For easier evaluation, the default run collects up to 200 defensive-code examples per seed for pattern reasoning.

**Run.**

```bash
bash artifact/r_pattern_reasoning/run.sh
```

The default settings are already in the script: up to 200 code snippets per seed and 8 workers. You can override them with two optional arguments:

```bash
bash artifact/r_pattern_reasoning/run.sh <per_seed_sample_size> <workers>
```

**Result.** The main results are written to the directory **`artifact/results/r_pattern_reasoning/`**.

Packaged reference files with the same names are provided in **`artifact/r_pattern_reasoning/reference/`** for comparison:

| File Name                       | Description                                                       |
| ------------------------------- | ----------------------------------------------------------------- |
| `defensive_code_samples.csv`    | Defensive-code examples selected for each seed.                   |
| `inferred_patterns.csv`         | Reference inferred defensive patterns for the selected examples.  |
| `pattern_reasoning_summary.csv` | Per-seed counts of selected defensive code and inferred patterns. |

To facilitate result checking, this run prioritizes the collection of defensive code related to the top security-sensitive operations listed in Table 18. 
By running this script, you can verify whether the inferred patterns cover these important cases. This demonstrates that BugAuditor can effectively mine diverse defensive patterns.

To quickly check whether the inferred patterns cover the top security-sensitive operations from Table 18, please run:
```bash
# Due to the inherent instability of LLMs, you may expect near 100% coverage (or very minor variations) across different runs.
python3 artifact/r_pattern_reasoning/check_table18_coverage.py
```



**Expected cost.** Based on our testing, the default sample is estimated at **1.366M total tokens**, and **1,107.862 seconds** of LLM time.
The overall script runtime is 39 mins. The actual runtime depends on the machine (especially the number of CPU cores).

**Reference Execution Output.**
For a quick packaged-output check:

```bash
bash artifact/r_pattern_reasoning/run.sh --reference
```

### Bug Auditing

**Intro.** To facilitate testing, we provide a set of pre-inferred defensive patterns related to bug detection. These patterns were either directly derived from the seed defensive operations or from their corresponding wrappers.
The benchmark includes 20 bug candidates for validation. We only provide a subset of detected bugs as some bugs are still being processed. 


**Input files:**
- `defensive_patterns.csv` — pre-inferred defensive patterns
- `detected_bug_reports.json` — 20 detected benchmark bugs used for the overlap check

**Run.**
```bash
bash artifact/r_bug_auditing/run.sh
```


The default settings are in the script: audit up to 10 comparable functions per pattern and use 8 workers. You can override them with two optional arguments:

```bash
bash artifact/r_bug_auditing/run.sh <per_pattern_audit_limit> <workers>
```

The per-pattern limit must be at least 10.
The results should detect most known bugs in the benchmark, with minor variation possible because the audit uses an LLM. This may also catch new bugs beyond the benchamrk.

For a quick packaged-output check without LLM calls:

```bash

bash artifact/r_bug_auditing/run.sh --reference
```

**Result.** The results are saved in the `artifact/results/r_bug_auditing/` directory. The key outputs are:

| File                       | Description                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------- |
| `bug_reports.json`         | Bug reports for provided cases.                                                     |
| `exact_audit_results.json` | Raw live LLM audit results for all selected candidates. Produced by live runs only. |
| `bug_auditing_results.csv` | Overall audit verdicts for selected candidates.                                     |
| `detected_bug_overlap.csv` | Overlap between  benchmark bugs and generated reports.                              |

Example report: 
```json
  "items": [
    {
      "case_id": "P01",
      "buggy_function": "ksmbd_crypt_message",
      ...
      "bug_explanation": "The function calls aead_request_alloc() to allocate a request, but on error paths (e.g., when ksmbd_init_sg fails or kzalloc fails) it uses kfree(req) instead of aead_request_free(req). This is a resource leak because aead_request_alloc returns a structure that must be freed with aead_request_free, not kfree. ..."
    },
```

**Execution time.** The packaged reference live run took about 185 seconds and used about 0.33M tokens.


**Execution time.** A few mins and token cost.

## Extension Experiments

### 1. Extensibility analysis.

**Intro.** This experiment corresponds to the paper's Section 7.1 extensibility analysis. Given function-call seed defensive operations such as `kfree`, `of_node_put`, `clk_put`, and `kref_put`, BugAuditor extends them to wrapper defensive operations, then mines defensive patterns for those extended operations. 

**Execution.**

```bash
bash artifact/defensive_op_extension/run.sh
```

**Results.** The command writes the Table 11 reference data and compact extension summaries to `artifact/results/defensive_op_extension/`. The expected Table 11 total is 7,943 wrapper defensive operations and 735 inferred patterns.

### 2. Generalizability Study


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
For new projects, add a new key to `config.json:program_paths`, then run the same command shape with the new repo key and seed defensive operation.

Outputs are written under `output/security_sensitive_data/<repo>/cross_project_live/`.At the end, it prints the located usage count, valid defensive-code context count, reasoning input count, inferred pattern count, and the pattern JSON path. It also writes `live_summary.csv` and `live_output_paths.md` to `artifact/results/cross_project/`.

Use reference mode to inspect the historical OpenSSL/FFmpeg aggregate counts without real running.:

```bash
bash artifact/cross_project/run.sh --reference
bash artifact/cross_project/run.sh openssl OPENSSL_free --reference
```

Reference mode prints the located usages, valid defensive-code snippets, and inferred defensive-pattern counts for the packaged examples. It also writes the corresponding pattern JSON files under `artifact/results/cross_project/reference_patterns/`, prints each JSON path, and writes `expected_output.txt` and `reference_output_paths.md` under `artifact/results/cross_project/`. 



## Data for Paper Tables and Figures

**Intro.** The directory `artifact/paper_tables/` contains compact source data and scripts needed to support selected paper results. 
One can **run the scripts on the provided source data** to automatically regenerate main tables and figure. The key input files are located under `artifact/paper_tables/data/`:


**Execution.**

```bash
bash artifact/paper_tables/run.sh
```

**Results.** The command prints Table 9 and Table 11 and writes generated markdown/LaTeX tables plus `figure8_long_tail.svg` to `artifact/results/paper_tables/`. Reference generated outputs are in `artifact/paper_tables/reference/`.
