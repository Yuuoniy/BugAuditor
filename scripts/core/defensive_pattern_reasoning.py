import argparse
import csv
import json
import os
import sys

from defensive_code_locating import DefensiveCodeLocator
from reasoning_engine import DefensivePatternReasoningRunner
import runtime_paths as rt
from tqdm import tqdm


def load_sample_functions(path):
    names = []
    with open(path, "r", newline="") as f:
        if path.endswith(".csv"):
            reader = csv.DictReader(f)
            if reader.fieldnames and "func_name" in reader.fieldnames:
                for row in reader:
                    name = (row.get("func_name") or "").strip()
                    if name:
                        names.append(name)
            else:
                f.seek(0)
                for row in csv.reader(f):
                    if row and row[0].strip() and row[0].strip() != "func_name":
                        names.append(row[0].strip())
        else:
            for line in f:
                name = line.strip().split(",", 1)[0].strip()
                if name and not name.startswith("#"):
                    names.append(name)
    return names


def main():
    parser = argparse.ArgumentParser(
        description="Defensive pattern reasoning runner. Auto-runs defensive code locating if contexts are missing."
    )
    parser.add_argument("defensive_op", help="defensive operation name, e.g., kfree or clk_put (used as seed when batching)")
    parser.add_argument("repo", nargs="?", default="linux", help="repo name key from config.json (default: linux)")
    parser.add_argument("--no-llm", action="store_true", help="disable LLM reporting step")
    parser.add_argument("--llm-dry-run", action="store_true", help="skip LLM API calls but persist prompts")
    parser.add_argument("--llm-model", help="override LLM model id (default from config or env)")
    parser.add_argument("--workers", type=int, default=32, help="parallel workers for dominator/context analysis (default auto)")
    parser.add_argument("--timeout", type=int, default=60, help="per-context analysis timeout in seconds (default 300)")
    parser.add_argument("--step", choices=["both", "dominator", "llm"], default="both", help="choose pipeline stage: dominator (stage-2 only), llm (reuse saved llm_inputs), or both (default)")
    parser.add_argument("--batch-manifest", help="optional path to a wrapper-operation manifest JSON")
    parser.add_argument("--single", action="store_true", help="run only the given defensive operation and ignore expanded manifests")
    parser.add_argument("--llm-suffix", default="", help="optional suffix for LLM output filenames")
    parser.add_argument("--incremental", action="store_true", help="save/resume analysis progress (skip already analyzed contexts)")
    parser.add_argument("--limit", type=int, default=0, help="limit number of contexts to process (0=unlimited, e.g., 1000 for testing)")
    parser.add_argument("--sample-functions-file", help="optional newline or CSV file listing func_name values to keep from the located contexts")
    parser.add_argument("--skip-completed", action="store_true", help="skip defensive operations that already have output files (spec/*.json)")
    parser.add_argument("--include-fptr", action="store_true", help="include sequences with function-pointer calls (default: filtered)")
    parser.add_argument("--force-recompute", action="store_true", help="ignore existing raw sequence cache and recompute")
    parser.add_argument(
        "--output-subdir",
        default="",
        help="write reasoning outputs under <security_sensitive_data_path>/<repo>/<output_subdir>/",
    )
    args = parser.parse_args()

    seed_defensive_op = args.defensive_op
    repo = args.repo

    llm_suffix = args.llm_suffix

    config = rt.load_config()
    security_sensitive_data_path = config["security_sensitive_data_path"]
    black_list = config["black_list"]

    default_manifest = os.path.join(security_sensitive_data_path, repo, "contexts", f"{seed_defensive_op}_expanded.json")
    manifest_path = args.batch_manifest
    if not args.single and not manifest_path and os.path.exists(default_manifest):
        manifest_path = default_manifest

    defensive_ops_to_run = [seed_defensive_op]
    if manifest_path and os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r") as f:
                data = json.load(f)
                defensive_ops_from_manifest = data.get("defensive_ops") or data.get("secops") or []
                if defensive_ops_from_manifest:
                    defensive_ops_to_run = defensive_ops_from_manifest
                    print(f"[batch] loaded {len(defensive_ops_to_run)} defensive ops from {manifest_path}")
        except Exception as e:
            sys.exit(f"Failed to read batch manifest {manifest_path}: {e}")

    output_repo_dir = None
    if args.output_subdir:
        output_repo_dir = os.path.join(security_sensitive_data_path, repo, args.output_subdir)
        os.makedirs(output_repo_dir, exist_ok=True)
        print(f"[out] output_repo_dir={output_repo_dir}")

    for defensive_op in tqdm(defensive_ops_to_run, desc="Stage-2 defensive ops", unit="op"):
        # Check if already completed
        if args.skip_completed:
            base_dir = output_repo_dir or os.path.join(security_sensitive_data_path, repo)
            spec_file = os.path.join(base_dir, "spec", f"{defensive_op}.json")
            raw_file = os.path.join(base_dir, "raw", f"{defensive_op}.json")
            if os.path.exists(spec_file) and os.path.exists(raw_file):
                print(f"[skip] {defensive_op} already completed (found {spec_file})")
                continue

        contexts_dir = os.path.join(security_sensitive_data_path, repo, "contexts")
        contexts_file = os.path.join(contexts_dir, f"{defensive_op}.json")

        contexts = []
        if args.step != "llm":
            if not os.path.exists(contexts_file):
                locator = DefensiveCodeLocator(defensive_op, repo)
                contexts_file = locator.pipeline()

            if not contexts_file or not os.path.exists(contexts_file):
                print(f"[warn] No contexts for defensive_op={defensive_op} repo={repo}; skipping")
                continue

            with open(contexts_file, "r") as f:
                contexts = json.load(f)

        if args.sample_functions_file and args.step != "llm":
            sample_names = load_sample_functions(args.sample_functions_file)
            by_func = {}
            for context in contexts:
                by_func.setdefault(context.get("func_name"), context)
            original_count = len(contexts)
            contexts = [by_func[name] for name in sample_names if name in by_func]
            missing = [name for name in sample_names if name not in by_func]
            print(f"[sample] selected {len(contexts)} contexts from {original_count} located contexts using {args.sample_functions_file}")
            if missing:
                print(f"[sample] missing functions not found in located contexts: {missing}")

        # Apply limit if specified
        if args.limit > 0:
            original_count = len(contexts)
            contexts = contexts[:args.limit]
            print(f"[limit] reduced contexts from {original_count} to {len(contexts)}")

        llm_enabled = not args.no_llm
        effective_step = args.step
        runner = DefensivePatternReasoningRunner(defensive_op, repo, black_list, security_sensitive_data_path, output_repo_dir=output_repo_dir)
        runner.run(
            contexts,
            llm_enabled=llm_enabled,
            llm_model=args.llm_model,
            llm_dry_run=args.llm_dry_run,
            parallel_workers=args.workers,
            analysis_timeout=args.timeout,
            step=effective_step,
            prompt_version=2,
            llm_suffix=llm_suffix,
            exclude_func_ptr=not args.include_fptr,
            reuse_raw=not args.force_recompute,
            # incremental=args.incremental,
        )

        if output_repo_dir:
            print(f"Stage-2 done for {defensive_op}. Outputs under {output_repo_dir}/(raw|detail|spec)/{defensive_op}.json")
        else:
            print(f"Stage-2 done for {defensive_op}. Outputs under {security_sensitive_data_path}/{repo}/(raw|detail|spec)/{defensive_op}.json")

    print(f"Processed defensive operations (seed first): {defensive_ops_to_run}")


if __name__ == "__main__":
    main()
