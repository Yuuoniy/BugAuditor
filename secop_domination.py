import os
import json
import pdb
from src.utils.BuildFuncCFG import BuildFuncCFG
import networkx as nx
from src.utils.CFGAnalyzer import CFGAnalyzer
from icecream import ic

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CHECK_SECOPS = {"null-ptr-check", "negative-check", "err-ptr-check"}

# Dominator analysis mode per secop:
# - pre: only pre-dominator (default)
# - post: only post-dominator
# - both: analyze both and merge results
SECOP_DOMINANCE_MODE = {
    "memset": "both",
}
DEFAULT_DOMINANCE_MODE = "pre"


class SecOpDominateAnalyzer:
    def __init__(self, secop, repo_name, func_name, func_code, var_name=None):
        self.secop = secop
        self.repo_name = repo_name
        self.func_name = func_name
        self.func_code = func_code
        self.var_name = var_name
        self.cfg_path = None
        self.CFG = None
        self.funcs_cfg = ['METHOD_RETURN', 'METHOD', 'RETURN']
        self.methods = CFGAnalyzer.get_func_call(func_code)
        self.funcs_cfg.extend([f"{x}" for x in self.methods])
        self.dominate_funcs = None
        self.post_dominate_funcs = None

        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        self.black_list = config["black_list"]

    def workflow(self):
        self.export_cfg()
        if self.CFG is None:
            return None
        self.locate_secop_stmt()
        mode = self._get_dominate_mode()
        pre_funcs = []
        post_funcs = []

        if mode in ("pre", "both"):
            self.find_pre_dominate_stmt_for_secop()
            pre_funcs = self.dominate_funcs or []

        if mode in ("post", "both"):
            self.find_post_dominate_stmt_for_secop()
            post_funcs = self.post_dominate_funcs or []

        if mode == "post":
            self.dominate_funcs = post_funcs
            return self.dominate_funcs

        if mode == "both":
            merged = list(set(pre_funcs + post_funcs))
            self.dominate_funcs = merged
            return self.dominate_funcs

        return self.dominate_funcs

    def export_cfg(self):
        build_func_cfg = BuildFuncCFG(self.repo_name, self.func_name, self.func_code)
        self.cfg_path = build_func_cfg.workflow()
        if self.cfg_path is None:
            return None
        if not os.path.exists(self.cfg_path):
            ic(f"CFG file not found: {self.cfg_path}")
            return None

        self.CFG = nx.drawing.nx_agraph.read_dot(self.cfg_path)

    def locate_secop_stmt(self):
        self.secop_node_id, source_code = CFGAnalyzer.assignement_node_id_by_label(self.CFG, self.secop)
        if self.secop_node_id is None:
            self.secop_node_id, source_code = CFGAnalyzer.callsite_node_id_by_label(self.CFG, self.secop)
        if self.secop_node_id is None and self._is_check_secop():
            self.secop_node_id = self._find_check_node()

    def find_pre_dominate_stmt_for_secop(self):
        start_node = CFGAnalyzer.node_id_by_label(self.CFG, 'METHOD')
        end_node = self.secop_node_id
        if start_node is None or end_node is None:
            ic(f"start_node or end_node is None: {start_node}, {end_node},{self.func_name}")
            return None

        function_call_nodes = []
        for path in nx.all_simple_paths(self.CFG, start_node, end_node):
            for node in path:
                label = self.CFG.nodes[node]['label']
                if label.startswith('('):
                    try:
                        parts = label[1:].split(',')
                        if not parts or not parts[0]:
                            continue
                        func_name = parts[0]
                        if func_name in self.funcs_cfg:
                            function_call_nodes.append(func_name)
                    except (IndexError, ValueError) as e:
                        ic(f"Error parsing label '{label}': {e}")
                        continue
        self.dominate_funcs = [label for label in function_call_nodes if label not in self.black_list]
        self.dominate_funcs = list(set(self.dominate_funcs))

    def find_post_dominate_stmt_for_secop(self):
        start_node = self.secop_node_id
        end_node = CFGAnalyzer.node_id_by_label(self.CFG, 'METHOD_RETURN')
        if start_node is None or end_node is None:
            ic(f"start_node or end_node is None: {start_node}, {end_node}")
            return None

        function_call_nodes = []
        for path in nx.all_simple_paths(self.CFG, start_node, end_node):
            for node in path:
                label = self.CFG.nodes[node]['label']
                if label.startswith('('):
                    try:
                        parts = label[1:].split(',')
                        if not parts or not parts[0]:
                            continue
                        func_name = parts[0]
                        if func_name in self.funcs_cfg:
                            function_call_nodes.append(func_name)
                    except (IndexError, ValueError) as e:
                        ic(f"Error parsing label '{label}': {e}")
                        continue
        post_funcs = [label for label in function_call_nodes if label not in self.black_list]
        self.post_dominate_funcs = list(set(post_funcs))
        return self.post_dominate_funcs

    def _is_check_secop(self):
        return self.secop in CHECK_SECOPS

    def _get_dominate_mode(self):
        mode = SECOP_DOMINANCE_MODE.get(self.secop, DEFAULT_DOMINANCE_MODE)
        if mode not in ("pre", "post", "both"):
            ic(f"Unknown dominance mode '{mode}' for secop={self.secop}, fallback=pre")
            return DEFAULT_DOMINANCE_MODE
        return mode

    def _find_check_node(self):
        if self.CFG is None or not self.var_name:
            return None
        labels = nx.get_node_attributes(self.CFG, "label")
        var = self.var_name
        candidates = []
        is_err_candidates = []
        ptr_err_candidates = []
        for node_id, label in labels.items():
            text = label
            if var not in text:
                continue
            if self.secop == "err-ptr-check":
                compact = text.replace(' ', '')
                v = var.replace(' ', '')
                is_err_patterns = [
                    f"IS_ERR({v})",
                    f"IS_ERR_OR_NULL({v})",
                    f"IS_ERR_VALUE({v})",
                ]
                if any(pat in compact for pat in is_err_patterns):
                    is_err_candidates.append(node_id)
                    continue
                if f"PTR_ERR({v})" in compact:
                    ptr_err_candidates.append(node_id)
                    continue
            if self._match_check_label(text, var):
                candidates.append(node_id)
        if is_err_candidates:
            return is_err_candidates[0]
        if ptr_err_candidates:
            return ptr_err_candidates[0]
        if candidates:
            return candidates[0]
        return None

    def _match_check_label(self, label: str, var: str) -> bool:
        low = label.replace(' ', '')
        v = var.replace(' ', '')
        if self.secop == "null-ptr-check":
            patterns = [
                f"{v}==NULL", f"{v}!=NULL", f"{v}==0", f"{v}!=0", f"!{v}", f"{v}==nullptr"
            ]
        elif self.secop == "negative-check":
            patterns = [f"{v}<0", f"{v}<=0"]
        elif self.secop == "err-ptr-check":
            patterns = [
                f"IS_ERR({v})",
                f"IS_ERR_OR_NULL({v})",
                f"IS_ERR_VALUE({v})",
                f"PTR_ERR({v})",
            ]
        else:
            return False
        return any(pat in low for pat in patterns)
