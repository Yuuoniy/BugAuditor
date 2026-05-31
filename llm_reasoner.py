"""LLM-based vulnerability pattern reasoning module."""

import os
import sys
import json
import re
import ast
from datetime import datetime
from icecream import ic

def load_config():
    """Load config.json without importing run_pipeline (avoids circular imports)."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "r") as f:
        return json.load(f)

from llm_dominate_report import (
    build_requests_from_llm_inputs,
    execute_llm_requests,
    DEFAULT_MODEL,
    normalize_api_base,
)


class LLMReasoner:
    """Handles LLM-based vulnerability pattern analysis and reporting."""

    def __init__(self, secop, repo_name, data_path, output_repo_dir=None):
        self.secop = secop
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

    @staticmethod
    def _load_model_config_from_yaml(model: str):
        """Best-effort load of per-model base_url/api_key from scripts/utils/openai_config.yaml."""
        try:
            import yaml
        except Exception:
            return None, None

        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "utils", "openai_config.yaml")
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            return None, None

        models = cfg.get("models") or {}
        if not isinstance(models, dict) or not models:
            return None, None

        if model in models:
            return model, models[model]

        # case-insensitive fallback for convenience
        for key in models:
            if isinstance(key, str) and key.lower() == (model or "").lower():
                return key, models[key]

        return None, None

    def _load_llm_config(self, override_model=None):
        """Load LLM configuration from environment or config file."""
        api_base = os.environ.get("OPENAI_API_BASE", "https://api.openai.com")
        api_key = os.environ.get("OPENAI_API_KEY", "")
        model = override_model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL)

        try:
            cfg = load_config()
            api_base = cfg.get("openai_api_base") or api_base
            api_key = cfg.get("openai_api_key") or api_key
            model = override_model or cfg.get("openai_model") or model
        except Exception as e:
            ic(f"load_config failed: {e}")

        # Prefer per-model config (same source used by wrapper in llm_dominate_report)
        resolved_model, model_cfg = self._load_model_config_from_yaml(model)
        if model_cfg:
            api_base = model_cfg.get("base_url") or api_base
            api_key = model_cfg.get("api_key") or api_key
            model = resolved_model or model

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
        llm_file = os.path.join(llm_dir, f'{self.secop}.json')
        
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
        
        llm_file = os.path.join(llm_dir, f'{self.secop}.json')
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
        llm_file = os.path.join(llm_dir, f'{self.secop}{suffix}.json')
        
        # Save raw outputs
        with open(llm_file, 'w') as f:
            json.dump(llm_outputs, f, indent=2)

        # Save dialog format (prompt + response pairs)
        dialog_file = os.path.join(llm_dir, f"{self.secop}{suffix}.dialog.json")
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

        parsed_file = os.path.join(llm_dir, f"{self.secop}{suffix}.parsed.json")
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
        requests = build_requests_from_llm_inputs(self.secop, llm_candidates)
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
            self.secop, 
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
