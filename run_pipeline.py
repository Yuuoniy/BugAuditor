import os
import json
import logging
from tqdm import tqdm
from defensive_code_locate import DefensiveCodeLocator
from vuln_op_reasoner import VulnOpReasonerRunner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)


def combine_spec_files(output_dir: str, secops: list, base_secop: str, repo_name: str) -> None:
    combined_specs = []
    spec_dir = os.path.join(os.path.dirname(output_dir), "spec")

    for secop in secops:
        spec_file = os.path.join(spec_dir, f"{secop}.json")
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
    combined_file = os.path.join(output_dir, f"{repo_name}_{base_secop}.json")
    with open(combined_file, 'w') as f:
        json.dump(combined_specs, f, indent=4)
    logger.info(f"Combined specs saved to {combined_file}")


def process_secop(seed_sec_op: str, repo_name: str):
    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    secop_data_path = config["secop_data_path"]
    black_list = config["black_list"]

    repo_dir = os.path.join(vuln_data_path, repo_name)
    output_dir = os.path.join(repo_dir, "spec")
    spec_all_dir = os.path.join(repo_dir, "spec_all")

    secop_file = os.path.join(secop_data_path, f"{repo_name}_{seed_sec_op}_extend_5.txt")
    if not os.path.exists(secop_file):
        logger.error(f"Secop file not found: {secop_file}")
        return

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(spec_all_dir, exist_ok=True)

    processed_secops = {
        os.path.splitext(filename)[0]
        for filename in os.listdir(output_dir)
        if filename.endswith('.json')
    }

    secops = []
    with open(secop_file, 'r') as file:
        for line in file:
            func_name, freq = line.strip().split(': ')
            secops.append(func_name)

    logger.info(f"Found {len(secops)} secops to process")

    for secop in tqdm(secops, desc="Processing secops", unit="secop"):
        # Stage 1: locate defensive code contexts
        locator = DefensiveCodeLocator(secop, repo_name)
        contexts_file = locator.pipeline()
        if not contexts_file:
            continue

        # Stage 2: vuln-op reasoning consumes saved contexts
        with open(contexts_file, 'r') as f:
            contexts = json.load(f)
        reasoner = VulnOpReasonerRunner(secop, repo_name, black_list, vuln_data_path)
        reasoner.run(contexts)

    combine_spec_files(spec_all_dir, secops, seed_sec_op, repo_name)
    logger.info("Analysis completed")


def test_combine_spec_files():
    seed_sec_op = "free"
    repo_name = "openssl"

    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    secop_data_path = config["secop_data_path"]

    repo_dir = os.path.join(vuln_data_path, repo_name)
    spec_dir = os.path.join(repo_dir, "spec")
    output_dir = os.path.join(repo_dir, "spec_all")

    os.makedirs(spec_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    secop_file = os.path.join(secop_data_path, f"{repo_name}_{seed_sec_op}_extend_5.txt")

    secops = []
    with open(secop_file, 'r') as file:
        for line in file:
            func_name = line.strip().split(': ')[0]
            secops.append(func_name)

    combine_spec_files(output_dir, secops, seed_sec_op, repo_name)


def process_single_secop(seed_sec_op: str, repo_name: str):
    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    black_list = config["black_list"]

    repo_dir = os.path.join(vuln_data_path, repo_name)
    output_dir = os.path.join(repo_dir, "spec")
    spec_all_dir = os.path.join(repo_dir, "spec_all")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(spec_all_dir, exist_ok=True)

    logger.info(f"Processing single secop: {seed_sec_op}")

    try:
        locator = DefensiveCodeLocator(seed_sec_op, repo_name)
        contexts_file = locator.pipeline()
        if contexts_file:
            with open(contexts_file, 'r') as f:
                contexts = json.load(f)
            reasoner = VulnOpReasonerRunner(seed_sec_op, repo_name, black_list, vuln_data_path)
            reasoner.run(contexts)
            combine_spec_files(spec_all_dir, [seed_sec_op], seed_sec_op, repo_name)
        logger.info("Analysis completed")
    except Exception as e:
        logger.error(f"Error processing secop {seed_sec_op}: {e}")
        raise


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python run_pipeline.py <seed_sec_op> [repo_name] [--single] | --test")
        sys.exit(1)

    if sys.argv[1] == "--test":
        test_combine_spec_files()
        return

    seed_sec_op = sys.argv[1]
    repo_name = sys.argv[2] if len(sys.argv) > 2 else 'linux'

    if len(sys.argv) > 3 and sys.argv[3] == "--single":
        process_single_secop(seed_sec_op, repo_name)
    else:
        process_secop(seed_sec_op, repo_name)


if __name__ == '__main__':
    main()
