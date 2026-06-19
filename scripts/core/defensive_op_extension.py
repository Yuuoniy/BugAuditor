from __future__ import annotations
import os
import subprocess
import json
from collections import Counter
from typing import List, Dict, Set
from pathlib import Path
import logging
import argparse
import runtime_paths as rt

class DefensiveOpExtender:
    def __init__(self, defensive_op, data_path, weggli_path, source_dir, iterations, repo_name):
        self.seed_defensive_op = defensive_op
        self.defensive_op = defensive_op
        self.data_path = str(data_path)
        self.weggli_path = str(weggli_path)
        self.source_dir = str(source_dir)
        self.extended_defensive_ops = []
        self.func_counter = {}

        # ensure output dirs exist
        os.makedirs(self.data_path, exist_ok=True)
        weggli_dir = os.path.join(self.data_path, 'weggli')
        os.makedirs(weggli_dir, exist_ok=True)

        self.weggli_file = os.path.join(weggli_dir, f'{defensive_op}_weggli.json')
        self.parsed_file = os.path.join(self.data_path, f'{repo_name}_{defensive_op}_extend_{iterations}.txt')
        if os.path.exists(self.parsed_file):
            os.remove(self.parsed_file)
        self.keywords = ['free', 'put']
        self.is_seed_written = False

    def workflow(self, iterations=1):
        current_defensive_ops = [self.defensive_op]
        for _ in range(iterations):
            next_defensive_ops = []
            for defensive_op in current_defensive_ops:
                print("Extending defensive operation:", defensive_op)
                self.defensive_op = defensive_op
                self.parse_weggli_results_extend_defensive_op()
                self.func_counter = self.parse_and_count_funcs()
                self.dump_results()
                next_defensive_ops.extend(self.func_counter.keys())
            self.extended_defensive_ops.extend(next_defensive_ops)
            current_defensive_ops = next_defensive_ops
        self.extended_defensive_ops.insert(0, self.seed_defensive_op)
        return self.extended_defensive_ops

    def dump_results(self):
        with open(self.parsed_file, 'a') as file:
            if not self.is_seed_written:
                file.write(f"{self.defensive_op}: 0\n")
                self.is_seed_written = True

            for func, count in self.func_counter.items():
                file.write(f"{func}: {count}\n")
        print('Log to file done:', self.parsed_file)
        return self.func_counter

    def parse_weggli_results_extend_defensive_op(self):
        query = f'_ $func(_){{{self.defensive_op}();}}'
        cmd = f"{self.weggli_path} '{query}' {self.source_dir} -s {self.weggli_file}"
        print(cmd)
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        res = result.stdout.read().decode().split('\n')[0]
        return len(res) > 0

    def parse_and_count_funcs(self):
        with open(self.weggli_file, 'r') as file:
            data = json.load(file)

        func_counter = Counter()

        for file_set in data:
            for file_entry in file_set:
                for match_group in file_entry['matches']:
                    for match in match_group['vars']:
                        if match['var'] == '$func':
                            if any(keyword in match['val'] for keyword in self.keywords):
                                if 'output' in match['val']:
                                    continue
                                func_counter[match['val']] += 1

        func_counter = dict(sorted(func_counter.items(), key=lambda item: item[1], reverse=True))
        return func_counter


def main():
    parser = argparse.ArgumentParser(description='Defensive operation extender')
    parser.add_argument('defensive_op', help='defensive operation to analyze')
    parser.add_argument('repo_name', help='Target program to analyze (e.g., linux, qemu, xen)')
    args = parser.parse_args()

    config = rt.load_config()

    if args.repo_name not in config['program_paths']:
        print(f"Error: Unknown program name '{args.repo_name}'")
        print(f"Available programs: {list(config['program_paths'].keys())}")
        exit(1)

    CONFIG = {
        'defensive_op': args.defensive_op,
        'data_path': Path(config['defensive_op_data_path']),
        'weggli_path': Path(config['weggli_path']),
        'source_dir': Path(config['program_paths'][args.repo_name]),
        'iterations': config['iterations'],
        'repo_name': args.repo_name
    }

    extender = DefensiveOpExtender(**CONFIG)
    extended_defensive_ops = extender.workflow(CONFIG['iterations'])
    print(f'Found {len(extended_defensive_ops)} unique defensive operations:')
    print('Original defensive operation:', extended_defensive_ops[0])
    print('Extended defensive operations:', extended_defensive_ops[1:])


if __name__ == '__main__':
    main()
