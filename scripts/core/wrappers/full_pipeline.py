import os
import json
import logging
import sys
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from tqdm import tqdm
from defensive_code_locating import DefensiveCodeLocator
from reasoning_engine import DefensivePatternReasoningRunner
import runtime_paths as rt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_config():
    return rt.load_config()


def combine_spec_files(output_dir: str, defensive_ops: list, base_defensive_op: str, repo_name: str) -> None:
    combined_specs = []
    spec_dir = os.path.join(os.path.dirname(output_dir), "spec")

    for defensive_op in defensive_ops:
        spec_file = os.path.join(spec_dir, f"{defensive_op}.json")
        if os.path.exists(spec_file):
            try:
                with open(spec_file, 'r') as f:
                    specs = json.load(f)
                    logger.info(f"Reading {spec_file}: found {len(specs)} specs")
                    combined_specs.extend(specs)
            except Exception as e:
                logger.error(f"Error reading spec file {spec_file}: {e}")
                continue
        else:
            logger.warning(f"Spec file not found: {spec_file}")

    combined_specs.sort(key=lambda x: x['count'], reverse=True)
    logger.info(f"Total combined specs: {len(combined_specs)}")
    combined_file = os.path.join(output_dir, f"{repo_name}_{base_defensive_op}.json")
    with open(combined_file, 'w') as f:
        json.dump(combined_specs, f, indent=4)
    logger.info(f"Combined specs saved to {combined_file}")


def process_defensive_op(seed_defensive_op: str, repo_name: str):
    config = load_config()
    security_sensitive_data_path = config["security_sensitive_data_path"]
    defensive_op_data_path = config["defensive_op_data_path"]
    black_list = config["black_list"]

    repo_dir = os.path.join(security_sensitive_data_path, repo_name)
    output_dir = os.path.join(repo_dir, "spec")
    spec_all_dir = os.path.join(repo_dir, "spec_all")

    defensive_op_file = os.path.join(defensive_op_data_path, f"{repo_name}_{seed_defensive_op}_extend_5.txt")
    if not os.path.exists(defensive_op_file):
        logger.error(f"Defensive operation file not found: {defensive_op_file}")
        return

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(spec_all_dir, exist_ok=True)

    processed_defensive_ops = {
        os.path.splitext(filename)[0]
        for filename in os.listdir(output_dir)
        if filename.endswith('.json')
    }

    defensive_ops = []
    with open(defensive_op_file, 'r') as file:
        for line in file:
            func_name, freq = line.strip().split(': ')
            defensive_ops.append(func_name)

    logger.info(f"Found {len(defensive_ops)} defensive operations to process")

    for defensive_op in tqdm(defensive_ops, desc="Processing defensive ops", unit="op"):
        # Stage 1: locate defensive code contexts
        locator = DefensiveCodeLocator(defensive_op, repo_name)
        contexts_file = locator.pipeline()
        if not contexts_file:
            continue

        # Stage 2: defensive pattern reasoning consumes saved contexts
        with open(contexts_file, 'r') as f:
            contexts = json.load(f)
        reasoner = DefensivePatternReasoningRunner(defensive_op, repo_name, black_list, security_sensitive_data_path)
        reasoner.run(contexts)

    combine_spec_files(spec_all_dir, defensive_ops, seed_defensive_op, repo_name)
    logger.info("Analysis completed")


def test_combine_spec_files():
    seed_defensive_op = "free"
    repo_name = "openssl"

    config = load_config()
    security_sensitive_data_path = config["security_sensitive_data_path"]
    defensive_op_data_path = config["defensive_op_data_path"]

    repo_dir = os.path.join(security_sensitive_data_path, repo_name)
    spec_dir = os.path.join(repo_dir, "spec")
    output_dir = os.path.join(repo_dir, "spec_all")

    os.makedirs(spec_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    defensive_op_file = os.path.join(defensive_op_data_path, f"{repo_name}_{seed_defensive_op}_extend_5.txt")

    defensive_ops = []
    with open(defensive_op_file, 'r') as file:
        for line in file:
            func_name = line.strip().split(': ')[0]
            defensive_ops.append(func_name)

    combine_spec_files(output_dir, defensive_ops, seed_defensive_op, repo_name)


def process_single_defensive_op(seed_defensive_op: str, repo_name: str):
    config = load_config()
    security_sensitive_data_path = config["security_sensitive_data_path"]
    black_list = config["black_list"]

    repo_dir = os.path.join(security_sensitive_data_path, repo_name)
    output_dir = os.path.join(repo_dir, "spec")
    spec_all_dir = os.path.join(repo_dir, "spec_all")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(spec_all_dir, exist_ok=True)

    logger.info(f"Processing single defensive operation: {seed_defensive_op}")

    try:
        locator = DefensiveCodeLocator(seed_defensive_op, repo_name)
        contexts_file = locator.pipeline()
        if contexts_file:
            with open(contexts_file, 'r') as f:
                contexts = json.load(f)
            reasoner = DefensivePatternReasoningRunner(seed_defensive_op, repo_name, black_list, security_sensitive_data_path)
            reasoner.run(contexts)
            combine_spec_files(spec_all_dir, [seed_defensive_op], seed_defensive_op, repo_name)
        logger.info("Analysis completed")
    except Exception as e:
        logger.error(f"Error processing defensive operation {seed_defensive_op}: {e}")
        raise


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scripts/core/wrappers/full_pipeline.py <seed_defensive_op> [repo_name] [--single] | --test")
        sys.exit(1)

    if sys.argv[1] == "--test":
        test_combine_spec_files()
        return

    seed_defensive_op = sys.argv[1]
    repo_name = sys.argv[2] if len(sys.argv) > 2 else 'linux'

    if len(sys.argv) > 3 and sys.argv[3] == "--single":
        process_single_defensive_op(seed_defensive_op, repo_name)
    else:
        process_defensive_op(seed_defensive_op, repo_name)


if __name__ == '__main__':
    main()
