import os
import json
import subprocess
import shutil
import networkx as nx
import re

# Prefer pygraphviz; fall back to pydot if unavailable
try:
    from networkx.drawing.nx_agraph import read_dot as nx_read_dot
except ImportError:  # pragma: no cover
    from networkx.drawing.nx_pydot import read_dot as nx_read_dot

class BuildFuncCFG:
    def __init__(self, repo_name, func_name, func_code):
        self.repo_name = repo_name
        self.func_name = func_name
        self.func_code = self._clean_func_code(func_code)
        # get the joern data path from the repo-level config.json
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_path = os.path.join(repo_root, 'config.json')
        if not os.path.exists(config_path):
            config_path = os.path.join(repo_root, 'configs', 'config.json')
        with open(config_path, "r") as f:
            config = json.load(f)
        self.joern_data_path = config["joern_data_path"]
        
        
        
    def workflow(self):
        # call joern to build the cfg
        # process the generated files
        # catch the exception
        try:
            # Reuse existing CFG if already built
            existing_cfg = os.path.join(self.joern_data_path, "cfg", f"{self.func_name}.dot")
            if os.path.exists(existing_cfg) and os.path.getsize(existing_cfg) > 0:
                print(f"Reusing existing CFG: {existing_cfg}")
                return existing_cfg

            ok = self.call_joern()
            if not ok:
                return None
            ok = self.process_generated_files()
            cfg_path = os.path.join(self.joern_data_path, "cfg", f"{self.func_name}.dot")
            if (not ok) or (not os.path.exists(cfg_path)):
                print(f"CFG file not found after joern-export: {cfg_path}")
                return None
            # the path to the cfg file is cfg-outdir/func_name.dot
            return cfg_path
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def call_joern(self):
        if not os.path.exists(self.joern_data_path):
            os.makedirs(self.joern_data_path)
        with open(os.path.join(self.joern_data_path, f"{self.func_name}.c"), "w") as f:
            f.write(self.func_code)
        
        # save the function code to the subdir of the joern data path, subdir name is source
        source_dir = os.path.join(self.joern_data_path, "source")
        if not os.path.exists(source_dir):
            os.makedirs(source_dir)
        with open(os.path.join(source_dir, f"{self.func_name}.c"), "w") as f:
            f.write(self.func_code)
        
        # call joern to build the cfg and export the cfg, subdir name is cfg , then subdir is the function name
        cfg_dir = os.path.join(self.joern_data_path, "cfg", self.func_name)
        cfg_root = os.path.join(self.joern_data_path, "cfg")
        if not os.path.exists(cfg_root):
            os.makedirs(cfg_root, exist_ok=True)
        # joern-export bails if target exists; ensure removal and let joern-export create it
        if os.path.exists(cfg_dir):
            shutil.rmtree(cfg_dir, ignore_errors=True)

        bin_path = os.path.join(self.joern_data_path, f"{self.func_name}.bin")

        # always regenerate .bin to match current code snippet
        try:
            subprocess.run(
                ["joern-parse", f"{self.joern_data_path}/{self.func_name}.c", "-o", bin_path],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"joern-parse failed: {e.stderr}")
            return False

        # use subprocess.run to call the joern-export command
        try:
            cmd = ["joern-export", "--repr", "cfg", bin_path, "--out", cfg_dir]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if result.stderr:
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"joern-export failed: {e.stderr}")
            return False
        return True

    
    
    def process_generated_files(self):
        cfg_dir = os.path.join(self.joern_data_path, "cfg", self.func_name)
        if not os.path.isdir(cfg_dir):
            return False
        dot_files = [x for x in os.listdir(cfg_dir) if x.endswith('.dot')]
        if not dot_files:
            return False
        for dot_file in dot_files:
            self.process_dot_file_one(cfg_dir, dot_file)
        # after processing, expect ../<func>.dot
        return os.path.exists(os.path.join(self.joern_data_path, "cfg", f"{self.func_name}.dot"))
        
          
    def process_dot_file_one(self, cfg_dir, dot_file):
        dot_path = os.path.join(cfg_dir, dot_file)
        if not os.path.exists(dot_path):
            return

        G = nx_read_dot(dot_path)
        if G.name not in [self.func_name]:
            try:
                os.remove(dot_path)
            except FileNotFoundError:
                pass
        else:
            target_path = os.path.join(self.joern_data_path, "cfg", f"{G.name}.dot")
            try:
                shutil.move(dot_path, target_path)
            except FileNotFoundError:
                pass

    def _clean_func_code(self, code: str) -> str:
        # Remove Linux __init annotation and similar attributes that can confuse joern
        cleaned = re.sub(r"\b__init\b", "", code)
        # Optional: strip attribute sections like __attribute__((...)) if they remain on same line
        cleaned = re.sub(r"__attribute__\s*\(\([^)]*\)\)", "", cleaned)
        return cleaned
    
    
if __name__ == "__main__":
    # get the repo name, func name, func code from the command line
    repo_name = 'linux'
    func_name = ''
    func_code = ''
    build_func_cfg = BuildFuncCFG(repo_name, func_name, func_code)
    build_func_cfg.workflow()
