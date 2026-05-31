import os
import sys
import json
import re
import multiprocessing as mp
import threading
from collections import defaultdict
from icecream import ic
ic.configureOutput(includeContext=False)
from tqdm import tqdm


try:
    from run_pipeline import load_config
except Exception:
    load_config = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR = os.path.join(BASE_DIR, "src", "utils")
if UTILS_DIR not in sys.path:
    sys.path.append(UTILS_DIR)

import tree_sitter_helper
import weggli_helper
from secop_domination import SecOpDominateAnalyzer
from llm_reasoner import LLMReasoner

CHECK_SECOPS = {"null-ptr-check", "negative-check", "err-ptr-check"}


def _sequence_has_func_ptr(seq):
    for item in seq or []:
        if not isinstance(item, dict):
            continue
        func = item.get("func") or ""
        if "->" in func:
            return True
    return False


class VulnOpReasoner:
    def __init__(self, secop, func_name, func_code, var_name, repo_name) -> None:
        self.secop = secop
        self.func_name = func_name
        self.func_code = func_code
        self.var_name = var_name
        self.repo_name = repo_name

        self.all_func_calls = None
        self.func_calls_related_to_var = None
        self.var_op_list = None

        self.data_dependent_funcs = None
        self.control_dominate_funcs = None
        self.critical_funcs = None
        self.secop_stmt = None

    def workflow(self, mode='cfg', timeout_sec=None):
        if self.check_if_var_is_arg():
            return []

        self.extract_var_op()
        self.extract_func_names()
        try:
            self.joern_workflow(timeout_sec=timeout_sec)
        except Exception as e:
            import traceback
            error_msg = f"joern_workflow failed: {type(e).__name__}: {e}"
            ic(error_msg)
            # Log full traceback for debugging
            if "index out of range" in str(e).lower():
                ic(f"Traceback: {traceback.format_exc()}")
            return []
        if self.control_dominate_funcs is None:
            return []

        self.critical_funcs = [item for item in self.data_dependent_funcs if item['func'] in self.control_dominate_funcs]
        return self.critical_funcs

    def joern_workflow(self, timeout_sec=None):
        """Run joern workflow with optional timeout protection (threading-based, works in threads)."""
        try:
            secop_dominate_analyzer = SecOpDominateAnalyzer(self.secop, self.repo_name, self.func_name, self.func_code, self.var_name)
            
            # Apply timeout if specified - use threading-based approach (signal won't work in worker threads)
            if timeout_sec and timeout_sec > 0:
                result = [None]
                exception = [None]
                
                def _run_analyzer():
                    try:
                        result[0] = secop_dominate_analyzer.workflow()
                    except Exception as e:
                        exception[0] = e
                
                thread = threading.Thread(target=_run_analyzer, daemon=True)
                thread.start()
                thread.join(timeout=timeout_sec)
                
                if thread.is_alive():
                    # Thread is still running - timeout occurred
                    ic(f"joern workflow timeout ({timeout_sec}s) for {self.func_name}")
                    self.control_dominate_funcs = None
                elif exception[0]:
                    # Thread finished but with exception
                    raise exception[0]
                else:
                    # Thread finished successfully
                    self.control_dominate_funcs = result[0]
            else:
                self.control_dominate_funcs = secop_dominate_analyzer.workflow()
        except Exception as e:
            import traceback
            error_msg = f"joern workflow error: {type(e).__name__}: {e}"
            ic(error_msg)
            # Log full traceback for debugging
            if "index out of range" in str(e).lower():
                ic(f"Traceback: {traceback.format_exc()}")
            self.control_dominate_funcs = None
        if self.control_dominate_funcs is None:
            return

    def check_if_var_is_arg(self):
        try:
            tree = tree_sitter_helper.parser.parse(bytes(self.func_code, "utf8"))
            func_decl_nodes = tree_sitter_helper.find_node_by_type(tree, "function_declarator")
            if not func_decl_nodes:
                return False
            func_decl = func_decl_nodes[0]
            params_nodes = tree_sitter_helper.find_node_by_type(func_decl, "parameter_list")
            if not params_nodes:
                return False
            params = params_nodes[0]
            idents = tree_sitter_helper.find_node_by_type(params, "identifier")
            args = [tree_sitter_helper.get_node_content(x, self.func_code) for x in idents]
            return self.var_name in args
        except Exception:
            return False

    def extract_func_names(self):
        func_items = []
        for stmt in self.func_calls_related_to_var:
            if not stmt.endswith(';'):
                stmt += ';'
            func_name_in_call = "<stmt>"
            try:
                tree = tree_sitter_helper.parser.parse(bytes(stmt, "utf8"))
                call_nodes = tree_sitter_helper.find_node_by_type(tree, "call_expression")
                if call_nodes:
                    call = call_nodes[0]
                    func_name_in_call = tree_sitter_helper.get_node_content(
                        call.child_by_field_name("function"), stmt
                    )
                elif self._is_check_secop():
                    # Label check statements so downstream keeps them
                    func_name_in_call = f"{self.secop}_check"
            except Exception as e:
                ic(stmt)
                ic(e)
            func_items.append({"func": func_name_in_call, "stmt": stmt.strip()})

        seen = set()
        unique_items = []
        for item in func_items:
            key = (item["func"], item["stmt"])
            if key in seen:
                continue
            seen.add(key)
            unique_items.append(item)
        self.data_dependent_funcs = unique_items

    def extract_var_op(self):
        self.all_func_calls = self._extract_var_related_slices(self.func_code, self.var_name)
        self.func_calls_related_to_var = self.all_func_calls
        self.secop_stmt = self._find_secop_stmt(self.func_code, self.var_name)

    def _extract_var_related_slices(self, func_code: str, var_name: str):
        slices = []
        tree = tree_sitter_helper.parser.parse(bytes(func_code, "utf8"))

        # collect statements that mention the crit
        # ical variable, not limited to calls
        stmt_types = [
            "expression_statement",
            "declaration",
            "return_statement",
            # "if_statement",
            # "for_statement",
            # "while_statement",
            # "do_statement",
            # "switch_statement",
        ]
        stmt_nodes = []
        for t in stmt_types:
            stmt_nodes.extend(tree_sitter_helper.find_node_by_type(tree, t))

        positioned = []
        for stmt_node in stmt_nodes:
            stmt_content = tree_sitter_helper.get_node_content(stmt_node, func_code)
            if not self.dependency_on_critical_variable(stmt_content, var_name):
                continue
            normalized = " ".join(stmt_content.split())
            if not normalized.endswith(';'):
                normalized += ';'
            positioned.append((stmt_node.start_byte, normalized))

        # also capture guard/check statements for check-type secops (e.g., null-ptr-check)
        if self._is_check_secop():
            positioned.extend(self._extract_check_slices(tree, func_code, var_name, with_pos=True))

        # sort by source order
        positioned.sort(key=lambda x: x[0])

        # deduplicate while preserving order
        deduped = []
        seen = set()
        for _, stmt in positioned:
            if stmt in seen:
                continue
            seen.add(stmt)
            deduped.append(stmt)
        return deduped

    def _find_secop_stmt(self, func_code: str, var_name: str):
        tree = tree_sitter_helper.parser.parse(bytes(func_code, "utf8"))

        # For call-based secops, grab the statement containing the secop call on var
        call_nodes = tree_sitter_helper.find_node_by_type(tree, "call_expression")
        for call in call_nodes:
            func_node = call.child_by_field_name("function")
            if not func_node:
                continue
            func_name = tree_sitter_helper.get_node_content(func_node, func_code)
            if func_name != self.secop:
                continue
            stmt_node = call
            while stmt_node and stmt_node.type not in ("expression_statement", "declaration"):
                stmt_node = stmt_node.parent
            stmt_content = tree_sitter_helper.get_node_content(stmt_node, func_code) if stmt_node else tree_sitter_helper.get_node_content(call, func_code)
            if not self.dependency_on_critical_variable(stmt_content, var_name):
                continue
            normalized = " ".join(stmt_content.split())
            if not normalized.endswith(';'):
                normalized += ';'
            return normalized

        # For check-style secops, reuse check slice extraction
        if self._is_check_secop():
            checks = self._extract_check_slices(tree, func_code, var_name)
            if checks:
                return checks[0]
        return None

    def _slice_with_header(self, func_name: str, func_code: str, statements):
        """Return code slice spanning header through last relevant statement.

        - Always include function header (start of signature).
        - Bound body from first to last matched statement when possible.
        - If no statements found, return full function.
        """
        if not func_code:
            return ""

        # locate header start near function name
        name_pos = func_code.find(func_name) if func_name else -1
        if name_pos == -1:
            header_start = 0
        else:
            header_start = func_code.rfind("\n", 0, name_pos)
            header_start = 0 if header_start == -1 else header_start + 1

        spans = []
        for item in statements or []:
            stmt = item.get("stmt", "") if isinstance(item, dict) else str(item)
            if not stmt:
                continue
            idx = func_code.find(stmt)
            if idx == -1:
                continue
            spans.append((idx, idx + len(stmt)))

        if not spans:
            return func_code[header_start:]

        start = min(s for s, _ in spans)
        end = max(e for _, e in spans)
        start = min(header_start, start)
        return func_code[start:end]

    def _is_check_secop(self):
        return self.secop in CHECK_SECOPS

    def _extract_check_slices(self, tree, func_code: str, var_name: str, with_pos: bool = False):
        check_stmts = []
        if_nodes = tree_sitter_helper.find_node_by_type(tree, "if_statement")
        for if_node in if_nodes:
            cond = if_node.child_by_field_name("condition")
            if not cond:
                continue
            cond_text = tree_sitter_helper.get_node_content(cond, func_code)
            if not self._matches_check_condition(cond_text, var_name):
                continue
            stmt_text = tree_sitter_helper.get_node_content(if_node, func_code)
            normalized = " ".join(stmt_text.split())
            # keep braces intact; ensure we terminate for downstream parsing
            if not normalized.endswith(';') and not normalized.endswith('}'):
                normalized += ';'
            if with_pos:
                check_stmts.append((if_node.start_byte, normalized))
            else:
                check_stmts.append(normalized)
        return check_stmts

    def _matches_check_condition(self, cond_text: str, var_name: str) -> bool:
        text = " ".join(cond_text.split())
        if self.secop == "null-ptr-check":
            patterns = [
                rf"!\s*{re.escape(var_name)}",
                rf"{re.escape(var_name)}\s*==\s*NULL",
                rf"{re.escape(var_name)}\s*==\s*0",
                rf"{re.escape(var_name)}\s*!=\s*NULL",
                rf"{re.escape(var_name)}\s*!=\s*0",
                rf"{re.escape(var_name)}\s*==\s*nullptr",
            ]
        elif self.secop == "negative-check":
            patterns = [
                rf"{re.escape(var_name)}\s*<\s*0",
                rf"{re.escape(var_name)}\s*<=\s*0",
            ]
        elif self.secop == "err-ptr-check":
            patterns = [
                rf"\bIS_ERR\s*\(\s*{re.escape(var_name)}\s*\)",
                rf"\bIS_ERR_OR_NULL\s*\(\s*{re.escape(var_name)}\s*\)",
                rf"\bIS_ERR_VALUE\s*\(\s*{re.escape(var_name)}\s*\)",
                rf"\bPTR_ERR\s*\(\s*{re.escape(var_name)}\s*\)",
            ]
        else:
            return False

        for pat in patterns:
            if re.search(pat, text):
                return True
        return False

    def dependency_on_critical_variable(self, slice, critical_var):
        if not slice.endswith(';'):
            slice += ';'
        tree = tree_sitter_helper.parser.parse(bytes(slice, "utf8"))
        idents = tree_sitter_helper.find_node_by_type(tree, "identifier")
        ident_codes = [tree_sitter_helper.get_node_content(x, slice) for x in idents]

        field_exprs = tree_sitter_helper.find_node_by_type(tree, "field_expression")
        field_exprs = [tree_sitter_helper.get_node_content(x, slice) for x in field_exprs]

        for ident in ident_codes:
            if critical_var == ident:
                return True
        for field_expr in field_exprs:
            if critical_var in field_expr:
                return True
        return False


def _process_single_context(args):
    """Worker function for multiprocessing: process a single context.
    
    Args:
        args: tuple of (secop, context, repo_name, black_list, analysis_timeout)
    
    Returns:
        tuple: (success, result_dict) where result_dict contains var_op_list, llm_cand, func_name, etc.
    """
    secop, context, repo_name, black_list, analysis_timeout = args
    
    try:
        reasoner = VulnOpReasoner(secop, context['func_name'], context['function'], context['var'], repo_name)
        var_op_list = reasoner.workflow(timeout_sec=analysis_timeout)
        
        if not var_op_list:
            return (True, None)
        
        # Filter blacklisted functions and ALL_CAPS
        var_op_list = [x for x in var_op_list if not any(black in x["func"] for black in black_list)]
        var_op_list = [x for x in var_op_list if not re.match(r'^[A-Z_]+$', x["func"])]
        
        # Deduplicate
        filtered = []
        seen = set()
        for item in var_op_list:
            key = (item["func"], item["stmt"])
            if key in seen:
                continue
            seen.add(key)
            filtered.append(item)
        
        # Add secop statement if available
        if reasoner.secop_stmt:
            secop_func_label = secop if secop not in CHECK_SECOPS else f"{secop}_check"
            key = (secop_func_label, reasoner.secop_stmt)
            if key not in seen:
                filtered.append({"func": secop_func_label, "stmt": reasoner.secop_stmt})
        
        # Build result
        result = {
            'var_op_list': filtered,
            'func_name': context['func_name'],
            'var': context['var'],
            'function': context.get('function', ''),
        }
        
        return (True, result)
        
    except Exception as e:
        import traceback
        error_msg = f"[Error] {context.get('func_name', '?')}: {type(e).__name__}: {e}"
        if "index out of range" in str(e).lower():
            error_msg += f"\nTraceback: {traceback.format_exc()}"
        return (False, {'error': error_msg, 'func_name': context.get('func_name', '?')})


class VulnOpReasonerRunner:
    """Stage-2 runner: consume contexts and produce specs."""

    def __init__(self, secop, repo_name, black_list, data_path, output_repo_dir=None):
        self.secop = secop
        self.repo_name = repo_name
        self.black_list = black_list
        self.data_path = data_path
        self.output_repo_dir = output_repo_dir

    def _input_repo_dir(self):
        return os.path.join(self.data_path, self.repo_name)

    def _output_repo_dir(self):
        return self.output_repo_dir or self._input_repo_dir()

    def run(self, contexts, llm_enabled=True, llm_model=None, llm_dry_run=False, parallel_workers=None, analysis_timeout=60, step="both", prompt_version=2, llm_suffix="", exclude_func_ptr=True, reuse_raw=True):
        total_ctx = len(contexts)
        contexts = [c for c in contexts if c.get('is_local_var')]
        local_ctx = len(contexts)
        skipped = total_ctx - local_ctx
        print(f"[VulnOpReasonerRunner] contexts total={total_ctx}, local_only={local_ctx}, skipped_non_local={skipped}")

        step = (step or "both").lower()
        run_dominator = step in ("both", "dominator")
        run_llm = llm_enabled and step in ("both", "llm")

        # Initialize LLM reasoner (no API calls unless run_llm=True).
        llm_reasoner = LLMReasoner(
            self.secop,
            self.repo_name,
            self.data_path,
            output_repo_dir=self._output_repo_dir(),
        )

        # If only LLM stage requested, load existing llm_inputs and run reporting
        if not run_dominator and run_llm:
            llm_reasoner.analyze_from_saved_inputs(
                llm_model=llm_model,
                llm_dry_run=llm_dry_run,
                prompt_version=prompt_version,
                llm_suffix=llm_suffix
            )
            return []

        if not run_dominator:
            # nothing to do
            return []

        var_path_list = []
        func_context_map = {}  # Map func_name -> context for LLM candidate generation
        
        # Check if raw data already exists and can be reused
        input_repo_dir = self._input_repo_dir()
        output_repo_dir = self._output_repo_dir()

        raw_dir = os.path.join(output_repo_dir, 'raw')
        raw_seq_file = os.path.join(raw_dir, f'{self.secop}.json')
        
        if reuse_raw and os.path.exists(raw_seq_file):
            print(f"[Stage-2] Found existing raw data at {raw_seq_file}, loading...")
            try:
                with open(raw_seq_file, 'r') as f:
                    var_path_list = json.load(f)
                print(f"[Stage-2] Loaded {len(var_path_list)} sequences from existing raw file")
                if exclude_func_ptr:
                    before = len(var_path_list)
                    var_path_list = [x for x in var_path_list if not _sequence_has_func_ptr(x[0])]
                    filtered = before - len(var_path_list)
                    if filtered:
                        print(f"[Stage-2] Filtered {filtered} sequences containing function-pointer calls")
                
                # Build func_context_map from contexts for LLM candidate generation
                # If contexts are provided, use them; otherwise try to load from contexts file
                if contexts:
                    for context in contexts:
                        func_name = context.get('func_name')
                        if func_name:
                            func_context_map[func_name] = context
                else:
                    # Try to load contexts from file for LLM candidate generation
                    contexts_dir = os.path.join(input_repo_dir, 'contexts')
                    contexts_file = os.path.join(contexts_dir, f'{self.secop}.json')
                    if os.path.exists(contexts_file):
                        try:
                            with open(contexts_file, 'r') as f:
                                loaded_contexts = json.load(f)
                            for context in loaded_contexts:
                                func_name = context.get('func_name')
                                if func_name:
                                    func_context_map[func_name] = context
                            print(f"[Stage-2] Loaded {len(func_context_map)} contexts for LLM candidate generation")
                        except Exception as e:
                            print(f"[Stage-2] Failed to load contexts: {e}, LLM candidates may be limited")
            except Exception as e:
                print(f"[Stage-2] Failed to load raw data: {e}, will recompute...")
                var_path_list = []
                func_context_map = {}
        
        # If raw data doesn't exist or loading failed, process contexts
        if not var_path_list:
            # Handle empty contexts early
            if not contexts:
                print(f"[Stage-2] No contexts to process for {self.secop}")
                target_path_list = self.find_representative_subsequences(var_path_list)
                self._persist_outputs(var_path_list, target_path_list)
                return target_path_list
            
            # Determine number of workers
            num_workers = parallel_workers or max(1, mp.cpu_count() - 1)
            num_workers = min(num_workers, len(contexts))  # Don't spawn more workers than contexts
            num_workers = max(1, num_workers)  # Ensure at least 1 worker
            
            print(f"[Stage-2] Processing {len(contexts)} contexts with {num_workers} workers (timeout={analysis_timeout}s per context)")
            
            # Build func_context_map for later use
            for context in contexts:
                func_name = context.get('func_name')
                if func_name:
                    func_context_map[func_name] = context
            
            # Prepare arguments for worker function
            work_args = [
                (self.secop, context, self.repo_name, self.black_list, analysis_timeout)
                for context in contexts
            ]
            
            # Process contexts (sequential fallback when num_workers <= 1)
            error_count = 0
            success_count = 0
            fptr_skip_count = 0

            if num_workers <= 1:
                pbar = tqdm(total=len(contexts), desc="Stage-2 dominator", unit="ctx", ncols=100)
                try:
                    for args in work_args:
                        success, result = _process_single_context(args)
                        if success and result is not None:
                            var_op_list = result['var_op_list']
                            func_name = result['func_name']
                            if exclude_func_ptr and _sequence_has_func_ptr(var_op_list):
                                fptr_skip_count += 1
                            else:
                                var_path_list.append((var_op_list, func_name))
                                success_count += 1
                            pbar.set_postfix_str(f"✓{success_count} ✗{error_count} fptr={fptr_skip_count}", refresh=False)
                        elif not success:
                            error_count += 1
                            pbar.write(result.get('error', 'Unknown error'))
                            pbar.set_postfix_str(f"✓{success_count} ✗{error_count} fptr={fptr_skip_count}", refresh=False)
                        pbar.update(1)
                finally:
                    pbar.close()
            else:
                with mp.Pool(processes=num_workers) as pool:
                    # Use imap_unordered for better performance and progress tracking
                    pbar = tqdm(total=len(contexts), desc="Stage-2 dominator", unit="ctx", ncols=100)
                    
                    try:
                        for success, result in pool.imap_unordered(_process_single_context, work_args):
                            if success and result is not None:
                                var_op_list = result['var_op_list']
                                func_name = result['func_name']
                                if exclude_func_ptr and _sequence_has_func_ptr(var_op_list):
                                    fptr_skip_count += 1
                                else:
                                    var_path_list.append((var_op_list, func_name))
                                    success_count += 1
                                
                                pbar.set_postfix_str(f"✓{success_count} ✗{error_count} fptr={fptr_skip_count}", refresh=False)
                                
                            elif not success:
                                error_count += 1
                                pbar.write(result.get('error', 'Unknown error'))
                                pbar.set_postfix_str(f"✓{success_count} ✗{error_count} fptr={fptr_skip_count}", refresh=False)
                            
                            pbar.update(1)
                            
                    finally:
                        pbar.close()
            
            print(f"[Stage-2] Completed: {success_count} succeeded, {error_count} failed, {fptr_skip_count} filtered")
            
            # Persist raw data
            self._persist_outputs(var_path_list, [])

        # Find representative subsequences
        target_path_list = self.find_representative_subsequences(var_path_list)
        
        # Persist outputs (detail and spec files)
        self._persist_outputs(var_path_list, target_path_list)

        # Generate LLM candidates based on representative subsequences
        # NOTE: even for dominator-only runs, we still persist llm_inputs for later reuse.
        llm_candidates = self._build_llm_candidates_from_subsequences(
            target_path_list, var_path_list, func_context_map, prompt_version
        )
        
        if llm_candidates:
            llm_reasoner.persist_llm_inputs(llm_candidates)
            if run_llm:
                llm_reasoner.run_llm_reporting(
                    llm_candidates,
                    llm_model=llm_model,
                    llm_dry_run=llm_dry_run,
                    prompt_version=prompt_version,
                    llm_suffix=llm_suffix
                )
        
        return target_path_list

    def _slice_with_header_static(self, func_name: str, func_code: str, statements):
        """Return code slice spanning header through last relevant statement."""
        if not func_code:
            return ""

        name_pos = func_code.find(func_name) if func_name else -1
        if name_pos == -1:
            header_start = 0
        else:
            header_start = func_code.rfind("\n", 0, name_pos)
            header_start = 0 if header_start == -1 else header_start + 1

        spans = []
        for item in statements or []:
            stmt = item.get("stmt", "") if isinstance(item, dict) else str(item)
            if not stmt:
                continue
            idx = func_code.find(stmt)
            if idx == -1:
                continue
            spans.append((idx, idx + len(stmt)))

        if not spans:
            return func_code[header_start:]

        start = min(s for s, _ in spans)
        end = max(e for _, e in spans)
        start = min(header_start, start)
        return func_code[start:end]

    def _build_llm_candidates_from_subsequences(self, target_path_list, var_path_list, func_context_map, prompt_version):
        """Build LLM candidates from representative subsequences.
        
        For each representative subsequence, select a representative function
        and build an LLM candidate based on that subsequence.
        """
        llm_candidates = []
        
        # Build a mapping from func_name to (var_op_list, func_name) for quick lookup
        var_path_dict = {func_name: var_op_list for var_op_list, func_name in var_path_list}
        
        # Determine secop labels to exclude (same as in find_representative_subsequences)
        secop_labels_to_exclude = {self.secop}
        if self.secop in CHECK_SECOPS:
            secop_labels_to_exclude.add(f"{self.secop}_check")
        
        for subseq_info in target_path_list:
            subsequence = subseq_info['subsequence']
            func_names = subseq_info.get('functions', [])
            
            if not subsequence or not func_names:
                continue
            
            # Filter out secop from subsequence for LLM candidate
            filtered_subsequence = [item for item in subsequence if item not in secop_labels_to_exclude]
            if not filtered_subsequence:
                continue
            
            # Select a representative function (use the first one)
            # TODO: Could improve by selecting based on some criteria
            representative_func_name = func_names[0]
            
            # Get the var_op_list for this function
            var_op_list = var_path_dict.get(representative_func_name, [])
            if not var_op_list:
                continue
            
            # Filter var_op_list to match the subsequence (excluding secop for subsequence matching)
            # But keep secop in var_statements for LLM to see the complete sequence
            filtered_var_op_list = [
                item for item in var_op_list
                if item.get("func") not in secop_labels_to_exclude
            ]
            if not filtered_var_op_list:
                continue
            
            # Get function context
            context = func_context_map.get(representative_func_name)
            if not context:
                continue
            
            func_code = context.get('function', '')
            var_name = context.get('var', '')
            var_origin = context.get("var_origin", "unknown")
            var_origin_reason = context.get("var_origin_reason", "")
            
            # For LLM input, we need the complete var_statements including secop
            # So use the original var_op_list (which includes secop) instead of filtered
            # Build var_statements: include all statements that are in subsequence OR secop
            subsequence_funcs = set(filtered_subsequence)
            
            var_statements_for_llm = []
            for item in var_op_list:
                func_name_in_stmt = item.get("func", "")
                # Include if: (1) in subsequence, or (2) is secop
                if func_name_in_stmt in subsequence_funcs or func_name_in_stmt in secop_labels_to_exclude:
                    var_statements_for_llm.append(item)
            
            # If no secop found, try to add it from the original var_op_list
            # (it should be there, but double-check)
            has_secop = any(item.get("func") in secop_labels_to_exclude for item in var_statements_for_llm)
            if not has_secop:
                # Look for secop in original var_op_list and add it
                for item in var_op_list:
                    if item.get("func") in secop_labels_to_exclude:
                        var_statements_for_llm.append(item)
                        break
            
            # Build code slice using the complete statements (including secop)
            code_slice = self._slice_with_header_static(
                representative_func_name,
                func_code,
                var_statements_for_llm
            )
            
            llm_cand = {
                "func_name": representative_func_name,
                "var": var_name,
                "var_statements": var_statements_for_llm,  # Include secop for complete sequence
                "function": func_code,
                "code_slice": code_slice,
                "subsequence": filtered_subsequence,  # Subsequence excludes secop (for grouping)
                "count": subseq_info.get('count', 0),
                "all_functions": func_names,  # Include all functions for this subsequence
                "var_origin": var_origin,
                "var_origin_reason": var_origin_reason,
            }
            llm_candidates.append(llm_cand)
        
        print(f"[LLM] Generated {len(llm_candidates)} LLM candidates from {len(target_path_list)} representative subsequences")
        return llm_candidates

    def _persist_outputs(self, var_path_list, target_path_list):
        # Ensure subsequences used for merge/spec exclude secop
        secop_labels_to_exclude = {self.secop}
        if self.secop in CHECK_SECOPS:
            secop_labels_to_exclude.add(f"{self.secop}_check")

        def _has_secop_in_subseq(items):
            for item in items or []:
                subseq = item.get("subsequence") if isinstance(item, dict) else None
                if not subseq:
                    continue
                if any(func in secop_labels_to_exclude for func in subseq):
                    return True
            return False

        if (not target_path_list) or _has_secop_in_subseq(target_path_list):
            target_path_list = self.find_representative_subsequences(var_path_list)

        repo_dir = self._output_repo_dir()
        detail_dir = os.path.join(repo_dir, 'detail')
        raw_dir = os.path.join(repo_dir, 'raw')
        spec_dir = os.path.join(repo_dir, 'spec')
        os.makedirs(detail_dir, exist_ok=True)
        os.makedirs(raw_dir, exist_ok=True)
        os.makedirs(spec_dir, exist_ok=True)

        detail_seq_file = os.path.join(detail_dir, f'{self.secop}.json')
        raw_seq_file = os.path.join(raw_dir, f'{self.secop}.json')

        with open(detail_seq_file, 'w') as file:
            json.dump(target_path_list, file, indent=4)
        with open(raw_seq_file, 'w') as file:
            json.dump(var_path_list, file, indent=4)
        
        # Persist spec file
        if target_path_list:
            spec_file = os.path.join(spec_dir, f'{self.secop}.json')
            with open(spec_file, 'w') as file:
                json.dump([{
                    'secop': self.secop,
                    'func': str(x['subsequence']),
                    'count': x['count'],
                    'func_name': x.get('functions', [])
                } for x in target_path_list], file, indent=4)

    def find_representative_subsequences(self, sequences):
        subseq_info = defaultdict(lambda: {'count': 0, 'functions': set()})
        # keep only non-empty sequences
        sequences = [x for x in sequences if len(x[0]) > 0]
        
        # Determine secop labels to exclude
        secop_labels_to_exclude = {self.secop}
        if self.secop in CHECK_SECOPS:
            secop_labels_to_exclude.add(f"{self.secop}_check")
        
        # project dict items to function-name lists for inclusion tests
        # Filter out secop-related functions from sequences
        projected = []
        for seq, func_name in sequences:
            filtered_funcs = [item["func"] for item in seq if item["func"] not in secop_labels_to_exclude]
            if filtered_funcs:  # Only include if there are functions left after filtering
                projected.append((filtered_funcs, func_name))
        
        projected.sort(key=lambda x: len(x[0]))

        for seq_names, func_name in projected:
            found_representative = False
            for other_seq_names, _ in projected:
                if set(other_seq_names).issubset(seq_names):
                    subseq_info[tuple(other_seq_names)]['functions'].add(func_name)
                    found_representative = True
                    break
            if not found_representative:
                subseq_info[tuple(seq_names)]['functions'].add(func_name)

        for subseq, info in subseq_info.items():
            subseq_info[subseq]['count'] = len(info['functions'])

        result = [{'subsequence': list(subseq), 'count': info['count'], 'functions': list(info['functions'])} for subseq, info in subseq_info.items()]
        return sorted(result, key=lambda x: x['count'], reverse=True)
