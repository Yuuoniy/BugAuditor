"""LLM-based defensive pattern reasoning module."""

import os
import sys
import json
import re
import ast
from datetime import datetime
from icecream import ic
import runtime_paths as rt

load_config = rt.load_config

from prompt_builder import (
    build_requests_from_llm_inputs,
    execute_llm_requests,
    DEFAULT_MODEL,
    normalize_api_base,
)


class DefensivePatternReasoningLLM:
    """Handles LLM-based defensive pattern analysis and reporting."""

    def __init__(self, defensive_op, repo_name, data_path, output_repo_dir=None):
        self.defensive_op = defensive_op
        self.repo_name = repo_name
        self.data_path = data_path
        self.output_repo_dir = output_repo_dir

    @staticmethod
    def _parse_response_json(response: str):
        """Extract JSON object from an LLM response (tolerate ```json fences)."""
        if not response:
            return None

        text = response.strip()
        fence = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.S)
        if fence:
            text = fence.group(1)
        else:
            brace = re.search(r"\{.*\}", text, flags=re.S)
            if brace:
                text = brace.group(0)
        try:
            return json.loads(text)
        except Exception:
            try:
                # tolerate single-quoted or trailing-comma structures
                return ast.literal_eval(text)
            except Exception:
                return None

    @staticmethod
    def _model_suffix(model: str) -> str:
        if not model:
            return ""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_")
        return f"_model_{safe}" if safe else ""

    def _load_llm_config(self, override_model=None):
        """Load LLM configuration from environment or config file."""
        api_base = os.environ.get("OPENAI_API_BASE", "https://api.openai.com")
        api_key = os.environ.get("OPENAI_API_KEY", "")
        model = override_model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL)

        try:
            cfg = load_config()
            api_base = cfg.get("openai_api_base") or api_base
            cfg_api_key = cfg.get("openai_api_key")
            api_key = api_key if cfg_api_key in (None, "", "YOUR_KEY") else cfg_api_key
            model = override_model or cfg.get("openai_model") or model
        except Exception as e:
            ic(f"load_config failed: {e}")

        api_base = normalize_api_base(api_base)
        return api_base, api_key, model

    @staticmethod
    def _timestamp_suffix() -> str:
        return datetime.now().strftime("_ts%Y%m%d_%H%M%S")

    def _repo_dir(self) -> str:
        return self.output_repo_dir or os.path.join(self.data_path, self.repo_name)

    def load_llm_inputs(self):
        """Load previously saved LLM input candidates."""
        repo_dir = self._repo_dir()
        llm_dir = os.path.join(repo_dir, 'llm_inputs')
        llm_file = os.path.join(llm_dir, f'{self.defensive_op}.json')
        
        if not os.path.exists(llm_file):
            return []
        
        try:
            with open(llm_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            ic(f"failed to load llm_inputs: {llm_file} err={e}")
            return []

    def persist_llm_inputs(self, llm_candidates):
        """Save LLM input candidates for later analysis."""
        repo_dir = self._repo_dir()
        llm_dir = os.path.join(repo_dir, 'llm_inputs')
        os.makedirs(llm_dir, exist_ok=True)
        
        llm_file = os.path.join(llm_dir, f'{self.defensive_op}.json')
        with open(llm_file, 'w') as f:
            json.dump(llm_candidates, f, indent=2)
        
        print(f"[LLM] saved inputs to {llm_file}")

    def persist_llm_outputs(self, llm_outputs, suffix=""):
        """Persist LLM analysis outputs in multiple formats."""
        if not llm_outputs:
            return
        
        repo_dir = self._repo_dir()
        llm_dir = os.path.join(repo_dir, 'llm_reports')
        os.makedirs(llm_dir, exist_ok=True)
        
        suffix = suffix or ""
        llm_file = os.path.join(llm_dir, f'{self.defensive_op}{suffix}.json')
        
        # Save raw outputs
        with open(llm_file, 'w') as f:
            json.dump(llm_outputs, f, indent=2)

        # Save dialog format (prompt + response pairs)
        dialog_file = os.path.join(llm_dir, f"{self.defensive_op}{suffix}.dialog.json")
        dialog_entries = []

        # Save parsed/structured format
        structured = []
        for item in llm_outputs:
            parsed = self._parse_response_json(item.get("response"))
            security_sensitive_behaviors = None
            defensive_behaviors = None
            # Fallback to old format for backward compatibility
            analysis = None
            critical_calls = None
            
            if parsed:
                # New format: security_sensitive_behaviors and defensive_behaviors
                security_sensitive_behaviors = (
                    parsed.get("security_sensitive_behaviors")
                    or parsed.get("security-sensitive behaviors")
                )
                defensive_behaviors = (
                    parsed.get("defensive_behaviors")
                    or parsed.get("defensive behaviors")
                )
                
                # Old format fallback
                analysis = (
                    parsed.get("analysis")
                    or parsed.get("pattern")
                    or parsed.get("semantic pattern")
                    or parsed.get("semantic_pattern")
                )
                critical_calls = (
                    parsed.get("critical_calls")
                    or parsed.get("synax details")
                    or parsed.get("syntax details")
                )
            
            dialog_entries.append({
                "func_name": item.get("func_name"),
                "var": item.get("var"),
                "model": item.get("model"),
                "prompt": item.get("prompt"),
                "response": item.get("response"),
            })
            
            structured.append({
                "func_name": item.get("func_name"),
                "var": item.get("var"),
                "model": item.get("model"),
                "llm_output": {
                    "security_sensitive_behaviors": security_sensitive_behaviors,
                    "defensive_behaviors": defensive_behaviors,
                    # Keep old fields for backward compatibility
                    "analysis": analysis or security_sensitive_behaviors or item.get("response"),
                    "critical_calls": critical_calls,
                },
                "llm_input": {
                    "var_statements": item.get("var_statements"),
                    "code_slice": item.get("code_slice"),
                    "function": item.get("function"),
                    "var_origin": item.get("var_origin"),
                    "var_origin_reason": item.get("var_origin_reason"),
                },
            })

        parsed_file = os.path.join(llm_dir, f"{self.defensive_op}{suffix}.parsed.json")
        with open(parsed_file, "w") as f:
            json.dump(structured, f, indent=2)

        with open(dialog_file, "w") as f:
            json.dump(dialog_entries, f, indent=2)

        print(f"[LLM] saved outputs: raw={llm_file}, parsed={parsed_file}, dialog={dialog_file}")

    def run_llm_reporting(self, llm_candidates, llm_model=None, llm_dry_run=False, 
                         prompt_version=2, llm_suffix=""):
        """Execute LLM analysis on candidates and persist results."""
        if not llm_candidates:
            ic("No LLM candidates to analyze")
            return []
        
        # Build requests from candidates
        requests = build_requests_from_llm_inputs(self.defensive_op, llm_candidates)
        if not requests:
            ic("No LLM requests to run")
            return []
        
        # Load configuration
        api_base, api_key, model = self._load_llm_config(override_model=llm_model)
        if llm_suffix:
            if model and "_model_" not in llm_suffix:
                llm_suffix = f"{llm_suffix}{self._model_suffix(model)}"
        else:
            llm_suffix = self._model_suffix(model)
        if "_ts" not in llm_suffix:
            llm_suffix = f"{llm_suffix}{self._timestamp_suffix()}" if llm_suffix else self._timestamp_suffix()
        ic(f"LLM planned={len(requests)} base={api_base} model={model} dry_run={llm_dry_run}")
        
        # Execute requests
        outputs = execute_llm_requests(
            self.defensive_op, 
            requests, 
            api_base, 
            api_key, 
            model, 
            dry_run=llm_dry_run, 
            prompt_version=prompt_version
        )
        
        # Persist outputs
        self.persist_llm_outputs(outputs, suffix=llm_suffix)
        
        return outputs

    def analyze_from_saved_inputs(self, llm_model=None, llm_dry_run=False, 
                                  prompt_version=2, llm_suffix=""):
        """Load saved LLM inputs and run analysis."""
        llm_inputs = self.load_llm_inputs()
        
        if not llm_inputs:
            ic("No llm_inputs found; run dominator stage first")
            return []
        
        return self.run_llm_reporting(
            llm_inputs,
            llm_model=llm_model,
            llm_dry_run=llm_dry_run,
            prompt_version=prompt_version,
            llm_suffix=llm_suffix
        )
