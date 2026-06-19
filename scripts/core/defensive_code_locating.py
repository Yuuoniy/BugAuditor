import re
import sys
import argparse
from tqdm import tqdm
import subprocess
import json
import os
import concurrent.futures
from collections import defaultdict

import runtime_paths as rt

BASE_DIR = str(rt.REPO_ROOT)
UTILS_DIR = str(rt.SRC_UTILS_DIR)
if UTILS_DIR not in sys.path:
    sys.path.append(UTILS_DIR)

import tree_sitter_helper
import weggli_helper


class DefensiveCodeLocator:
    def __init__(self, defensive_op, repo_name):
        self.defensive_op = defensive_op
        self.repo_name = repo_name

        config = rt.load_config()

        if repo_name not in config["program_paths"]:
            raise ValueError(f"Repository {repo_name} not found. Available repos: {list(config['program_paths'].keys())}")

        self.source_dir = config["program_paths"][repo_name]
        self.weggli_path = config["weggli_path"]
        self.data_path = config["security_sensitive_data_path"]

        os.makedirs(self.data_path, exist_ok=True)

        weggli_dir = os.path.join(self.data_path, "weggli_usage")
        os.makedirs(weggli_dir, exist_ok=True)
        self.weggli_file = os.path.join(weggli_dir, f'{defensive_op}.json')
        self.black_list = config["black_list"]
        self._macro_like_re = re.compile(r"^[A-Z0-9_]+$")
        self._alloc_name_re = re.compile(
            r"(?:\b|_)(kmalloc|kzalloc|kcalloc|kvmalloc|kvzalloc|kvcalloc|vmalloc|vzalloc|krealloc|"
            r"kmem_cache_alloc|kmem_cache_zalloc|kmem_cache_alloc_trace|kmemdup|kmemdup_nul|"
            r"kstrdup|kstrndup|kvasprintf|kasprintf|alloc_skb|__alloc_skb|alloc_pages|alloc_page|"
            r"get_free_pages|get_zeroed_page|dma_alloc|devm_kmalloc|devm_kzalloc|devm_kcalloc|"
            r"devm_kmemdup|memdup_user|memdup_user_nul)(?:\b|_)",
            re.IGNORECASE,
        )
        self._iterator_macros = {
            "list_for_each_entry",
            "list_for_each_entry_safe",
            "list_for_each_entry_reverse",
            "hlist_for_each_entry",
            "hlist_for_each_entry_safe",
            "hlist_for_each_entry_continue",
            "hlist_for_each_entry_continue_rcu",
            "xa_for_each",
            "xa_for_each_marked",
            "idr_for_each_entry",
            "radix_tree_for_each_slot",
            "rb_for_each_entry",
            "rb_for_each_entry_safe",
        }

    def test_for_one_ctx_func(self, ctx_func):
        hasUsage = self.get_security_usage_context()
        if not hasUsage:
            return

        defensive_contexts = self.parse_defensive_op_usage()
        context = [x for x in defensive_contexts if x['func_name'] == ctx_func][0]

        var_op_list = self.analyze_context(context['func_name'], context['function'], context['var'])
        print(var_op_list)

    def remove_irrelvant_ctx(self, func_calls):
        keywords = ['uninit', 'put', 'unregister', 'remove', 'destroy', 'free', 'exit', 'cleanup', 'fini', 'close', 'release', 'disable', 'disconnect','del','delete','teardown','deactivate','unbind','detach','stop','complete','unload','deinit','done','unmap','finidev','clear','finidev','finish','cancel','clean','dequeue','depopulate']
        def has_keyword(func_name):
            subwords = func_name.split('_')
            return any(subword in keywords for subword in subwords)
        return [x for x in func_calls if not has_keyword(x['func_name'])]

    def _annotate_locals(self, func_calls):
        annotated = []
        for ctx in func_calls:
            func_code = ctx.get('function', '')
            var_name = ctx.get('var', '')
            origin, reason = self._classify_var_origin(func_code, var_name)
            is_local = origin != "external"
            ctx_with_flag = dict(ctx)
            ctx_with_flag['is_local_var'] = is_local
            ctx_with_flag['var_origin'] = origin
            ctx_with_flag['var_origin_reason'] = reason
            annotated.append(ctx_with_flag)
        return annotated

    def _is_local_var(self, func_code: str, var_name: str) -> bool:
        """Return True if var_name is local (not clearly originating from external)."""
        origin, _ = self._classify_var_origin(func_code, var_name)
        return origin != "external"

    def _classify_var_origin(self, func_code: str, var_name: str):
        """Classify var_name origin: local / external / unknown."""
        try:
            tree = tree_sitter_helper.parser.parse(bytes(func_code, "utf8"))
            params = self._collect_param_names(tree, func_code)
            locals_set = self._collect_local_declarations(tree, func_code)
            assignments = self._collect_assignments(tree, func_code)
            iter_vars = self._collect_iterator_vars(tree, func_code)

            external_vars = set(params)
            external_vars.update(iter_vars)

            # Propagate external origin through assignments
            changed = True
            while changed:
                changed = False
                for item in assignments:
                    lhs_ident = item.get("lhs_ident")
                    if not lhs_ident or lhs_ident in external_vars:
                        continue
                    rhs = item.get("rhs_node")
                    if self._expr_depends_on_external(rhs, func_code, params, external_vars, locals_set):
                        external_vars.add(lhs_ident)
                        changed = True

            norm_var = self._normalize_expr(var_name)
            var_ident = self._extract_base_identifier(var_name) or var_name

            # Member access needs assignment evidence to be local
            if "->" in var_name or "." in var_name:
                member_assign = self._find_assignment(assignments, norm_var)
                if member_assign:
                    rhs = member_assign.get("rhs_node")
                    if self._expr_depends_on_external(rhs, func_code, params, external_vars, locals_set):
                        return "external", "member_assigned_from_external"
                    return "local", "member_assigned_locally"
                base_ident = self._extract_base_identifier(var_name)
                if base_ident and (base_ident in params or base_ident in external_vars or base_ident in iter_vars):
                    return "external", f"derived_from_external:{base_ident}"
                return "unknown", "member_access_without_local_assignment"

            if var_ident in params or var_name in params:
                return "external", "function_parameter"
            if var_ident in iter_vars or var_name in iter_vars:
                return "external", "iterator_variable"

            base_ident = self._extract_base_identifier(var_name)
            if base_ident and base_ident in external_vars:
                return "external", f"derived_from_external:{base_ident}"

            if var_ident in external_vars or var_name in external_vars:
                return "external", "external_assignment"

            if var_ident in locals_set or var_name in locals_set:
                if self._has_assignment_to_var(assignments, norm_var, var_ident):
                    return "local", "local_assignment"
                return "unknown", "local_decl_without_assignment"

            return "unknown", "no_local_declaration"

        except Exception:
            return "unknown", "parse_error"

    def _is_function_parameter(self, tree, func_code, var_name):
        """Check if var_name is a function parameter."""
        # Find all parameter_declaration nodes
        param_decls = tree_sitter_helper.find_node_by_type(tree, "parameter_declaration")
        
        for param_decl in param_decls:
            # Try to extract parameter name from declarator
            declarator = param_decl.child_by_field_name("declarator")
            if declarator:
                param_name = self._extract_identifier_from_declarator(declarator, func_code)
                if param_name == var_name:
                    return True
        
        return False
    
    def _extract_identifier_from_declarator(self, node, func_code):
        """Extract the identifier name from a declarator node (handles pointers, arrays, etc.)."""
        if node.type == "identifier":
            return tree_sitter_helper.get_node_content(node, func_code).strip()
        
        # For pointer_declarator, array_declarator, etc., find the nested identifier
        for child in node.children:
            if child.type == "identifier":
                return tree_sitter_helper.get_node_content(child, func_code).strip()
            result = self._extract_identifier_from_declarator(child, func_code)
            if result:
                return result
        
        return None

    def _collect_param_names(self, tree, func_code):
        params = set()
        param_decls = tree_sitter_helper.find_node_by_type(tree, "parameter_declaration")
        for param_decl in param_decls:
            declarator = param_decl.child_by_field_name("declarator")
            if not declarator:
                continue
            name = self._extract_identifier_from_declarator(declarator, func_code)
            if name:
                params.add(name)
        return params

    def _collect_local_declarations(self, tree, func_code):
        locals_set = set()
        decls = tree_sitter_helper.find_node_by_type(tree, "declaration")
        for decl in decls:
            declarator = decl.child_by_field_name("declarator")
            if declarator:
                name = self._extract_identifier_from_declarator(declarator, func_code)
                if name:
                    locals_set.add(name)
            init_decls = tree_sitter_helper.find_node_by_type(decl, "init_declarator")
            for init in init_decls:
                name = self._extract_identifier_from_declarator(init.child_by_field_name("declarator"), func_code)
                if name:
                    locals_set.add(name)
        return locals_set

    def _collect_assignments(self, tree, func_code):
        assignments = []
        assign_nodes = tree_sitter_helper.find_node_by_type(tree, "assignment_expression")
        for assign in assign_nodes:
            left = assign.child_by_field_name("left")
            right = assign.child_by_field_name("right")
            if not left:
                continue
            lhs_text = tree_sitter_helper.get_node_content(left, func_code).strip()
            lhs_ident = None
            if left.type == "identifier":
                lhs_ident = tree_sitter_helper.get_node_content(left, func_code).strip()
            assignments.append({
                "lhs_text": self._normalize_expr(lhs_text),
                "lhs_ident": lhs_ident,
                "rhs_node": right,
            })

        init_nodes = tree_sitter_helper.find_node_by_type(tree, "init_declarator")
        for init in init_nodes:
            declarator = init.child_by_field_name("declarator")
            value = init.child_by_field_name("value")
            if not declarator or not value:
                continue
            lhs_ident = self._extract_identifier_from_declarator(declarator, func_code)
            lhs_text = tree_sitter_helper.get_node_content(declarator, func_code).strip()
            assignments.append({
                "lhs_text": self._normalize_expr(lhs_text),
                "lhs_ident": lhs_ident,
                "rhs_node": value,
            })
        return assignments

    def _collect_iterator_vars(self, tree, func_code):
        iter_vars = set()
        calls = tree_sitter_helper.find_node_by_type(tree, "call_expression")
        for call in calls:
            func_node = call.child_by_field_name("function")
            if not func_node:
                continue
            func_name = tree_sitter_helper.get_node_content(func_node, func_code).strip()
            if func_name not in self._iterator_macros:
                continue
            args = call.child_by_field_name("arguments")
            if not args:
                continue
            first_arg = None
            for child in args.children:
                if child.type in ("(", ")", ","):
                    continue
                if child.is_named:
                    first_arg = child
                    break
            if not first_arg:
                continue
            arg_name = self._extract_identifier_from_expression(first_arg, func_code)
            if arg_name:
                iter_vars.add(arg_name)
        return iter_vars

    def _has_assignment_to_var(self, assignments, norm_var, var_ident=None):
        for item in assignments:
            if item.get("lhs_text") == norm_var:
                return True
            if var_ident and item.get("lhs_ident") == var_ident:
                return True
        return False

    def _find_assignment(self, assignments, norm_var):
        for item in assignments:
            if item.get("lhs_text") == norm_var:
                return item
        return None

    def _normalize_expr(self, text):
        return re.sub(r"\s+", "", text or "")

    def _extract_base_identifier(self, text):
        if not text:
            return None
        text = text.strip()
        text = text.lstrip("*&(")
        base = re.split(r"->|\.|\[", text, maxsplit=1)[0]
        base = base.strip()
        base = base.lstrip("*&(")
        return base or None

    def _extract_identifier_from_expression(self, node, func_code):
        if not node:
            return None
        if node.type == "identifier":
            return tree_sitter_helper.get_node_content(node, func_code).strip()
        if node.type in ("field_expression", "subscript_expression", "pointer_expression", "parenthesized_expression", "cast_expression", "unary_expression"):
            for child in node.children:
                if child.type == "identifier":
                    return tree_sitter_helper.get_node_content(child, func_code).strip()
        return None

    def _expr_depends_on_external(self, node, func_code, params, external_vars, locals_set):
        if not node:
            return False

        node_type = node.type

        if node_type == "identifier":
            name = tree_sitter_helper.get_node_content(node, func_code).strip()
            if name in params or name in external_vars:
                return True
            if name not in locals_set and not self._macro_like_re.match(name):
                return True
            return False

        if node_type == "field_expression":
            base = node.child_by_field_name("argument")
            if base and self._expr_depends_on_external(base, func_code, params, external_vars, locals_set):
                return True
            return False

        if node_type == "subscript_expression":
            base = node.child_by_field_name("argument") or node.child_by_field_name("array")
            if base and self._expr_depends_on_external(base, func_code, params, external_vars, locals_set):
                return True
            return False

        if node_type == "call_expression":
            func_node = node.child_by_field_name("function")
            func_name = tree_sitter_helper.get_node_content(func_node, func_code).strip() if func_node else ""
            if self._is_conversion_macro(func_name):
                return True
            if self._is_data_retrieval_function(func_name):
                return True
            if self._is_allocation_function(func_name):
                return False
            return False

        if node_type in ("unary_expression", "cast_expression", "parenthesized_expression", "pointer_expression"):
            arg = node.child_by_field_name("argument") or node.child_by_field_name("operand")
            return self._expr_depends_on_external(arg, func_code, params, external_vars, locals_set)

        if node_type in ("binary_expression", "conditional_expression"):
            for child in node.children:
                if child.is_named and self._expr_depends_on_external(child, func_code, params, external_vars, locals_set):
                    return True
            return False

        for child in node.children:
            if child.is_named and self._expr_depends_on_external(child, func_code, params, external_vars, locals_set):
                return True
        return False

    def _is_conversion_macro(self, func_name):
        """Check if function name is a type conversion macro/function (explicit list)."""
        # Explicit list of known container/conversion macros
        conversion_macros = {
            'container_of', 
            'list_entry', 'hlist_entry',
            'list_first_entry', 'list_last_entry',
            'list_next_entry', 'list_prev_entry',
            'to_delayed_work','list_for_each_entry_safe'
        }
        
        if func_name in conversion_macros:
            return True
        
        # Pattern: to_* and *_to_* are typically conversion functions
        if func_name.startswith('to_') or '_to_' in func_name:
            return True
        
        return False

    def _is_allocation_function(self, func_name):
        if not func_name:
            return False
        if self._alloc_name_re.search(func_name):
            return True
        if "alloc" in func_name or "dup" in func_name:
            return True
        return False

    def _is_data_retrieval_function(self, func_name):
        """Check if function name is a known data retrieval function (explicit list only)."""
        # Only include functions we are certain about from examples
        known_retrieval_funcs = {
            # XArray functions
            'xa_erase', 'xa_load',
            # Tree navigation
            'ext_tree_next',
            'net_shaper_hierarchy',
            # Driver data retrieval
            'dev_get_drvdata', 'platform_get_drvdata', 'pci_get_drvdata',
            'i2c_get_clientdata', 'usb_get_intfdata', 'usb_get_dev',
            'netdev_priv', 'dev_get_platdata', 'device_get_match_data',
            # # OF helpers
            # 'of_get_property', 'of_parse_phandle', 'of_find_node_by_path',
            # 'of_find_node_by_name', 'of_find_node_by_type', 'of_find_compatible_node',
        }
        if func_name in known_retrieval_funcs:
            return True
        if func_name.endswith('_get_drvdata') or func_name.endswith('_get_clientdata') or func_name.endswith('_get_intfdata'):
            return True
        if func_name.startswith('dev_get_') or func_name.startswith('of_get_') or func_name.startswith('of_find_'):
            return True
        return False

    def get_nums_vulnerable_ctx(self):
        hasUsage = self.get_security_usage_context()
        if not hasUsage:
            return 0

        defensive_contexts = self.remove_irrelvant_ctx(self.parse_defensive_op_usage())
        return len(defensive_contexts)

    def pipeline(self):
        """Locate defensive-code contexts and persist defensive pattern reasoning inputs.

        Output: security_sensitive_data/<repo>/contexts/<defensive_op>.json
        Schema: list of {"function": <code>, "func_name": <str>, "var": <str>}
        """
        hasUsage = self.get_security_usage_context()
        if not hasUsage:
            return None

        defensive_contexts = self.remove_irrelvant_ctx(self.parse_defensive_op_usage())
        defensive_contexts = self._annotate_locals(defensive_contexts)
        defensive_contexts = [c for c in defensive_contexts if c.get('is_local_var')]
        if len(defensive_contexts) == 0:
            return None

        repo_dir = os.path.join(self.data_path, self.repo_name)
        contexts_dir = os.path.join(repo_dir, 'contexts')
        os.makedirs(contexts_dir, exist_ok=True)
        
        contexts_file = os.path.join(contexts_dir, f'{self.defensive_op}.json')

        with open(contexts_file, 'w') as f:
            json.dump(defensive_contexts, f, indent=4)

        print(
            f"[stage-1] defensive_code_snippets={len(defensive_contexts)} "
            f"path={contexts_file}"
        )
        return contexts_file

    def parse_defensive_op_usage(self):
        with open(self.weggli_file, 'r') as file:
            data = json.load(file)

        result = []
        for file_set in data:
            for file_entry in file_set:
                for match_group in file_entry['matches']:
                    function_name = match_group.get('function', '')
                    func_name = None
                    var_name = None
                    for match in match_group['vars']:
                        if match['var'] == '$func':
                            func_name = match['val']
                        elif match['var'] == '$var':
                            var_name = match['val']

                    if func_name and var_name:
                        result.append({
                            'function': function_name,
                            'func_name': func_name,
                            'var': var_name,
                            'defensive_op': self.defensive_op
                        })

        return result

    def get_security_usage_context(self):
        queries = self._build_queries()
        aggregated = []
        any_hit = False

        for idx, query in enumerate(queries):
            tmp_out = f"{self.weggli_file}.tmp{idx}"
            cmd = f"{self.weggli_path} '{query}' {self.source_dir} -l -s {tmp_out}"
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            res = result.stdout.read().decode().split('\n')[0]
            if len(res) > 0:
                any_hit = True

            if os.path.exists(tmp_out):
                try:
                    with open(tmp_out, 'r') as f:
                        data = json.load(f)
                    aggregated.extend(data)
                except Exception:
                    pass
                finally:
                    os.remove(tmp_out)

        if aggregated:
            with open(self.weggli_file, 'w') as f:
                json.dump(aggregated, f)

        return any_hit

    def _build_queries(self):
        """Construct one or more weggli queries for the given defensive operation.

        Some defensive operations are checks (no direct call). Map well-known checks to
        multiple patterns to capture stylistic variants. Otherwise default
        to a single function-call pattern.
        """
        check_queries = {
            'null-ptr-check': [
                'if(!$var) return _;',
                'if($var==NULL) return _;',
            ],
            'negative-check': [
                'if($var<0) return _;',
                'if($var<=0) return _;'
            ],
            'err-ptr-check': [
                'if(IS_ERR($var)) return _;',
            ]
        }

        if self.defensive_op in check_queries:
            return [f"_ $func(_){{{expr}}}" for expr in check_queries[self.defensive_op]]

        return [f"_ $func(_){{{self.defensive_op}($var);}}"]

    # Stage-1 stops here; defensive pattern reasoning consumes saved contexts.


def _process_one(defensive_op, repo_name):
    analyzer = DefensiveCodeLocator(defensive_op, repo_name)
    return analyzer.pipeline()


def main():
    parser = argparse.ArgumentParser(description="Run the Stage-1 defensive code locator.")
    parser.add_argument("seed_defensive_op", help="seed defensive operation name")
    parser.add_argument("repo", nargs="?", default="linux", help="repo name key from config.json (default: linux)")
    parser.add_argument("--single", action="store_true", help="force single defensive operation (do not expand via extend file)")
    parser.add_argument("--workers", type=int, default=4, help="max parallel defensive operation jobs (default: 4)")
    args = parser.parse_args()

    seed_defensive_op = args.seed_defensive_op
    repo_name = args.repo
    single_flag = args.single

    config = rt.load_config()
    defensive_op_data_path = config.get("defensive_op_data_path", "")

    defensive_op_file = os.path.join(defensive_op_data_path, f"{repo_name}_{seed_defensive_op}_extend_5.txt")
    defensive_ops_to_run = [seed_defensive_op]
    if (not single_flag) and os.path.exists(defensive_op_file):
        seen = set()
        defensive_ops_to_run = []
        for candidate in [seed_defensive_op]:
            if candidate not in seen:
                seen.add(candidate)
                defensive_ops_to_run.append(candidate)

        with open(defensive_op_file, 'r') as file:
            for line in file:
                func_name, freq = line.strip().split(': ')
                if func_name in seen:
                    continue
                seen.add(func_name)
                defensive_ops_to_run.append(func_name)

    max_workers = min(args.workers, max(1, len(defensive_ops_to_run)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_one, defensive_op, repo_name): defensive_op for defensive_op in defensive_ops_to_run}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Stage-1 defensive ops", unit="op"):
            defensive_op = futures[future]
            try:
                future.result()
            except Exception as exc:
                print(f"defensive_op {defensive_op} generated an exception: {exc}")

    data_path = config["security_sensitive_data_path"]
    repo_dir = os.path.join(data_path, repo_name)
    contexts_dir = os.path.join(repo_dir, 'contexts')
    os.makedirs(contexts_dir, exist_ok=True)
    if (not single_flag) and len(defensive_ops_to_run) > 1:
        manifest_file = os.path.join(contexts_dir, f"{seed_defensive_op}_expanded.json")
        with open(manifest_file, 'w') as f:
            json.dump({
                "seed_defensive_op": seed_defensive_op,
                "defensive_ops": defensive_ops_to_run
            }, f, indent=4)
        print(f"[stage-1] defensive_op_manifest={manifest_file}")


if __name__ == '__main__':
    main()
