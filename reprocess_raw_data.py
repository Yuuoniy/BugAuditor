#!/usr/bin/env python3
"""
Script to reprocess existing raw data files and regenerate spec files
using the improved find_representative_subsequences logic that excludes secop.
"""

import os
import json
import argparse
import sys
from run_pipeline import load_config
from vuln_op_reasoner import VulnOpReasonerRunner, CHECK_SECOPS


def reprocess_raw_data(secop: str, repo: str = "linux"):
    """Reprocess raw data for a given secop and regenerate spec file."""
    
    # Load config
    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    black_list = config["black_list"]
    
    # Paths
    repo_dir = os.path.join(vuln_data_path, repo)
    raw_dir = os.path.join(repo_dir, 'raw')
    spec_dir = os.path.join(repo_dir, 'spec')
    
    raw_file = os.path.join(raw_dir, f'{secop}.json')
    spec_file = os.path.join(spec_dir, f'{secop}.json')
    
    # Check if raw file exists
    if not os.path.exists(raw_file):
        print(f"Error: Raw file not found: {raw_file}")
        return False
    
    print(f"Reading raw data from: {raw_file}")
    with open(raw_file, 'r') as f:
        var_path_list = json.load(f)
    
    print(f"Loaded {len(var_path_list)} sequences from raw file")
    
    # Create VulnOpReasonerRunner instance to use its find_representative_subsequences method
    runner = VulnOpReasonerRunner(secop, repo, black_list, vuln_data_path)
    
    # Recompute representative subsequences (excluding secop)
    print(f"Recomputing representative subsequences (excluding secop: {secop})...")
    target_path_list = runner.find_representative_subsequences(var_path_list)
    
    print(f"Found {len(target_path_list)} representative subsequences")
    
    # Ensure spec directory exists
    os.makedirs(spec_dir, exist_ok=True)
    
    # Save new spec file
    spec_data = [{
        'secop': secop,
        'func': str(x['subsequence']),
        'count': x['count'],
        'func_name': x.get('functions', [])
    } for x in target_path_list]
    
    print(f"Writing spec file to: {spec_file}")
    with open(spec_file, 'w') as f:
        json.dump(spec_data, f, indent=4)
    
    print(f"Successfully regenerated spec file with {len(spec_data)} entries")
    
    # Print some statistics
    if spec_data:
        print(f"\nTop 5 subsequences by count:")
        for i, item in enumerate(spec_data[:5], 1):
            print(f"  {i}. {item['func']} (count: {item['count']})")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Reprocess raw data files and regenerate spec files with improved logic"
    )
    parser.add_argument("secop", help="secop name (e.g., kfree)")
    parser.add_argument("repo", nargs="?", default="linux", help="repo name (default: linux)")
    
    args = parser.parse_args()
    
    success = reprocess_raw_data(args.secop, args.repo)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

