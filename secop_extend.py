from __future__ import annotations
import os
import subprocess
import json
from collections import Counter
from typing import List, Dict, Set
from pathlib import Path
import logging
import argparse

class SecOpExtender:
    def __init__(self, secop, data_path, weggli_path, source_dir, iterations, repo_name):
        self.secop = secop
        self.data_path = str(data_path)
        self.weggli_path = str(weggli_path)
        self.source_dir = str(source_dir)
        self.extended_secops = []
        self.func_counter = {}

        # ensure output dirs exist
        os.makedirs(self.data_path, exist_ok=True)
        weggli_dir = os.path.join(self.data_path, 'weggli')
        os.makedirs(weggli_dir, exist_ok=True)

        self.weggli_file = os.path.join(weggli_dir, f'{secop}_weggli.json')
        self.parsed_file = os.path.join(self.data_path, f'{repo_name}_{secop}_extend_{iterations}.txt')
        if os.path.exists(self.parsed_file):
            os.remove(self.parsed_file)
        self.keywords = ['free', 'put']
        self.is_secop_written = False

    def workflow(self, iterations=1):
        current_secops = [self.secop]
        for _ in range(iterations):
            next_secops = []
            for secop in current_secops:
                print("Extending secop:", secop)
                self.secop = secop
                self.parse_weggli_results_extend_secop()
                self.func_counter = self.parse_and_count_funcs()
                self.dump_results()
                next_secops.extend(self.func_counter.keys())
            self.extended_secops.extend(next_secops)
            current_secops = next_secops
        self.extended_secops.insert(0, self.secop)
        return self.extended_secops

    def dump_results(self):
        with open(self.parsed_file, 'a') as file:
            if not self.is_secop_written:
                file.write(f"{self.secop}: 0\n")
                self.is_secop_written = True

            for func, count in self.func_counter.items():
                file.write(f"{func}: {count}\n")
        print('Log to file done:', self.parsed_file)
        return self.func_counter

    def parse_weggli_results_extend_secop(self):
        query = f'_ $func(_){{{self.secop}();}}'
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
    parser = argparse.ArgumentParser(description='Security Operation Extender')
    parser.add_argument('secop', help='Security operation to analyze')
    parser.add_argument('repo_name', help='Target program to analyze (e.g., linux, qemu, xen)')
    args = parser.parse_args()

    config_path = Path(__file__).parent / 'config.json'
    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {config_path}")
        exit(1)

    if args.repo_name not in config['program_paths']:
        print(f"Error: Unknown program name '{args.repo_name}'")
        print(f"Available programs: {list(config['program_paths'].keys())}")
        exit(1)

    CONFIG = {
        'secop': args.secop,
        'data_path': Path(config['secop_data_path']),
        'weggli_path': Path(config['weggli_path']),
        'source_dir': Path(config['program_paths'][args.repo_name]),
        'iterations': config['iterations'],
        'repo_name': args.repo_name
    }

    extender = SecOpExtender(**CONFIG)
    extended_secops = extender.workflow(CONFIG['iterations'])
    print(f'Found {len(extended_secops)} unique security operations:')
    print('Original security operation:', extended_secops[0])
    print('Extended security operations:', extended_secops[1:])


if __name__ == '__main__':
    main()
