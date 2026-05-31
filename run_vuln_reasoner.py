import argparse
import glob
import json
import os
import sys

from defensive_code_locate import DefensiveCodeLocator
from vuln_op_reasoner import VulnOpReasonerRunner
from run_pipeline import load_config
from tqdm import tqdm


def main():
    parser = argparse.ArgumentParser(
        description="Stage-2 VulnOpReasoner runner. Auto-runs defensive locate if contexts are missing."
    )
    parser.add_argument("secop", help="secop name, e.g., memset or nla_put (used as seed when batching)")
    parser.add_argument("repo", nargs="?", default="linux", help="repo name key from config.json (default: linux)")
    parser.add_argument("--no-llm", action="store_true", help="disable LLM reporting step")
    parser.add_argument("--llm-dry-run", action="store_true", help="skip LLM API calls but persist prompts")
    parser.add_argument("--llm-model", help="override LLM model id (default from config or env)")
    parser.add_argument("--workers", type=int, default=32, help="parallel workers for dominator/context analysis (default auto)")
    parser.add_argument("--timeout", type=int, default=60, help="per-context analysis timeout in seconds (default 300)")
    parser.add_argument("--step", choices=["both", "dominator", "llm"], default="both", help="choose pipeline stage: dominator (stage-2 only), llm (reuse saved llm_inputs), or both (default)")
    parser.add_argument("--batch-manifest", help="optional path to a manifest JSON; defaults to contexts/<seed>_expanded.json if present")
    parser.add_argument("--prompt-version", type=int, choices=[1, 2], default=2, help="LLM prompt version: 1=full function code, 2=code slice with dominator hints (default)")
    parser.add_argument("--llm-suffix", default="", help="optional suffix for LLM output filenames (e.g., _fullcode)")
    parser.add_argument("--fullcode", action="store_true", help="convenience flag: use prompt version 1 and append '_fullcode' to outputs")
    parser.add_argument("--incremental", action="store_true", help="save/resume analysis progress (skip already analyzed contexts)")
    parser.add_argument("--limit", type=int, default=0, help="limit number of contexts to process (0=unlimited, e.g., 1000 for testing)")
    parser.add_argument("--skip-completed", action="store_true", help="skip secops that already have output files (spec/*.json)")
    parser.add_argument("--include-fptr", action="store_true", help="include sequences with function-pointer calls (default: filtered)")
    parser.add_argument("--force-recompute", action="store_true", help="ignore existing raw outputs and recompute sequences")
    parser.add_argument(
        "--output-subdir",
        default="",
        help="write dominator outputs under <vuln_data_path>/<repo>/<output_subdir>/ (separate raw/detail/spec/llm_inputs)",
    )
    args = parser.parse_args()

    seed_secop = args.secop
    repo = args.repo

    prompt_version = args.prompt_version
    llm_suffix = args.llm_suffix
    if args.fullcode:
        prompt_version = 1
        if not llm_suffix:
            llm_suffix = "_fullcode"

    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    black_list = config["black_list"]

    # Build secop list: default to batch using contexts/<seed>_expanded.json if exists
    default_manifest = os.path.join(vuln_data_path, repo, "contexts", f"{seed_secop}_expanded.json")
    manifest_path = args.batch_manifest or default_manifest

    secops_to_run = [seed_secop]
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r") as f:
                data = json.load(f)
                secops_from_manifest = data.get("secops") or []
                if secops_from_manifest:
                    secops_to_run = secops_from_manifest
                    print(f"[batch] loaded {len(secops_to_run)} secops from {manifest_path}")
        except Exception as e:
            sys.exit(f"Failed to read batch manifest {manifest_path}: {e}")
    else:
        print(f"[batch] manifest not found, falling back to single secop: {seed_secop}")

    def llm_output_paths(secop_name):
        base_dir = output_repo_dir or os.path.join(vuln_data_path, repo)
        llm_dir = os.path.join(base_dir, "llm_reports")
        if llm_suffix:
            candidates = [
                os.path.join(llm_dir, f"{secop_name}{llm_suffix}.parsed.json"),
                os.path.join(llm_dir, f"{secop_name}{llm_suffix}.json"),
                os.path.join(llm_dir, f"{secop_name}{llm_suffix}.dialog.json"),
            ]
            return [p for p in candidates if os.path.exists(p)]
        matches = glob.glob(os.path.join(llm_dir, f"{secop_name}*.parsed.json"))
        if not matches:
            matches = glob.glob(os.path.join(llm_dir, f"{secop_name}*.json"))
        return sorted(matches)

    def llm_outputs_exist(secop_name):
        return bool(llm_output_paths(secop_name))

    run_llm_requested = args.step in ("both", "llm") and not args.no_llm

    output_repo_dir = None
    if args.output_subdir:
        output_repo_dir = os.path.join(vuln_data_path, repo, args.output_subdir)
        os.makedirs(output_repo_dir, exist_ok=True)
        print(f"[out] output_repo_dir={output_repo_dir}")

    for secop in tqdm(secops_to_run, desc="Stage-2 secops", unit="secop"):
        # Check if already completed
        if args.skip_completed:
            base_dir = output_repo_dir or os.path.join(vuln_data_path, repo)
            spec_file = os.path.join(base_dir, "spec", f"{secop}.json")
            raw_file = os.path.join(base_dir, "raw", f"{secop}.json")
            if os.path.exists(spec_file) and os.path.exists(raw_file):
                print(f"[skip] {secop} already completed (found {spec_file})")
                continue

        llm_outputs_already = False
        if run_llm_requested and llm_outputs_exist(secop):
            llm_outputs_already = True
            if args.step == "llm":
                existing = ", ".join(llm_output_paths(secop))
                print(f"[skip] {secop} LLM outputs already exist; skipping llm stage ({existing})")
                continue
        
        contexts_dir = os.path.join(vuln_data_path, repo, "contexts")
        contexts_file = os.path.join(contexts_dir, f"{secop}.json")

        contexts = []
        if args.step != "llm":
            if not os.path.exists(contexts_file):
                locator = DefensiveCodeLocator(secop, repo)
                contexts_file = locator.pipeline()

            if not contexts_file or not os.path.exists(contexts_file):
                print(f"[warn] No contexts for secop={secop} repo={repo}; skipping")
                continue

            with open(contexts_file, "r") as f:
                contexts = json.load(f)

        # Apply limit if specified
        if args.limit > 0:
            original_count = len(contexts)
            contexts = contexts[:args.limit]
            print(f"[limit] reduced contexts from {original_count} to {len(contexts)}")

        llm_enabled = not args.no_llm
        if llm_outputs_already and args.step != "llm":
            llm_enabled = False
            print(f"[skip] {secop} LLM outputs already exist; running dominator only")
        effective_step = args.step
        runner = VulnOpReasonerRunner(secop, repo, black_list, vuln_data_path, output_repo_dir=output_repo_dir)
        runner.run(
            contexts,
            llm_enabled=llm_enabled,
            llm_model=args.llm_model,
            llm_dry_run=args.llm_dry_run,
            parallel_workers=args.workers,
            analysis_timeout=args.timeout,
            step=effective_step,
            prompt_version=prompt_version,
            llm_suffix=llm_suffix,
            exclude_func_ptr=not args.include_fptr,
            reuse_raw=not args.force_recompute,
            # incremental=args.incremental,
        )

        if output_repo_dir:
            print(f"Stage-2 done for {secop}. Outputs under {output_repo_dir}/(raw|detail|spec)/{secop}.json")
        else:
            print(f"Stage-2 done for {secop}. Outputs under {vuln_data_path}/{repo}/(raw|detail|spec)/{secop}.json")

    print(f"Processed secops (seed first): {secops_to_run}")


if __name__ == "__main__":
    main()
