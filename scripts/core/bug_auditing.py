#!/usr/bin/env python3
"""
Bug auditing:
1) Use LLM to translate security-sensitive behaviors into weggli queries (key code locator).
2) Run weggli to collect candidate functions.
3) For each candidate, ask LLM to judge whether defensive handling is consistent with a given pattern.

Designed to work with existing config.json (weggli_path, program_paths, openai settings).
"""

import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import runtime_paths as rt
from prompt_builder import DEFAULT_MODEL, call_openai, normalize_api_base
from tqdm import tqdm

load_config = rt.load_config


def _strip_json_block(text: str) -> str:
    """Extract JSON object/array from plain text or fenced blocks."""
    if not text:
        return ""
    text = text.strip()
    fence = re.search(r"```json\s*(\{.*?\}|\[.*?\])\s*```", text, flags=re.S)
    if fence:
        return fence.group(1)
    # fallback: first {...} or [...]
    brace = re.search(r"(\{.*\}|\[.*\])", text, flags=re.S)
    return brace.group(1) if brace else text


def _safe_json_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _get_encoding(model_name: str):
    try:
        import tiktoken
        try:
            return tiktoken.encoding_for_model(model_name)
        except Exception:
            return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return None


def _count_tokens(text: str, encoding) -> int:
    if not text:
        return 0
    if encoding:
        return len(encoding.encode(text))
    return len(text.split())


def _extract_usage(resp) -> Optional[Dict[str, int]]:
    if resp is None:
        return None
    usage = getattr(resp, "usage", None)
    if usage is None:
        return None
    if isinstance(usage, dict):
        return {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
        }
    return {
        "prompt_tokens": getattr(usage, "prompt_tokens", None),
        "completion_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


_C_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "do",
    "goto",
    "case",
    "default",
    "break",
    "continue",
    "struct",
    "enum",
    "union",
    "typedef",
    "static",
}


def _extract_callee_names(code: str, func_name: Optional[str] = None, max_items: int = 5) -> List[str]:
    if not code:
        return []
    names: List[str] = []
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        if name in _C_KEYWORDS:
            continue
        if func_name and name == func_name:
            continue
        if name not in names:
            names.append(name)
        if len(names) >= max_items:
            break
    return names


def _extract_key_calls_from_behaviors(behaviors: List[str], max_items: int = 5) -> List[str]:
    names: List[str] = []
    if not behaviors:
        return names

    behavior_patterns = [
        re.compile(r"\bWhen\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    ]
    for behavior in behaviors:
        for pattern in behavior_patterns:
            for match in pattern.finditer(behavior or ""):
                name = match.group(1)
                if name in _C_KEYWORDS or name in names:
                    continue
                names.append(name)
                if len(names) >= max_items:
                    return names
    return names


def _normalize_verdict(parsed: Any) -> Any:
    if not isinstance(parsed, dict):
        return parsed
    parsed = _normalize_confidence(parsed)
    verdict = parsed.get("verdict")
    consistent = parsed.get("consistent")
    if isinstance(verdict, str):
        key = verdict.strip().lower()
        if key in ("consistent", "inconsistent", "uncertain"):
            parsed["verdict"] = key
            if key == "consistent":
                parsed["consistent"] = True
            elif key == "inconsistent":
                parsed["consistent"] = False
            else:
                parsed["consistent"] = None
            return parsed
    if isinstance(consistent, str):
        key = consistent.strip().lower()
        if key in ("true", "false"):
            consistent = key == "true"
            parsed["consistent"] = consistent
        elif key in ("uncertain", "unknown"):
            parsed["consistent"] = None
            parsed["verdict"] = "uncertain"
            return parsed
    if consistent is True:
        parsed["verdict"] = "consistent"
    elif consistent is False:
        parsed["verdict"] = "inconsistent"
    else:
        parsed["verdict"] = "uncertain"
    return parsed


def _normalize_confidence(parsed: Any) -> Any:
    if not isinstance(parsed, dict):
        return parsed
    confidence = parsed.get("confidence")
    if confidence is None:
        return parsed
    value: Optional[float] = None
    if isinstance(confidence, (int, float)):
        value = float(confidence)
    elif isinstance(confidence, str):
        text = confidence.strip().lower()
        if text.endswith("%"):
            text = text[:-1].strip()
            try:
                value = float(text) / 100.0
            except ValueError:
                value = None
        elif text in ("low", "medium", "high"):
            value = {"low": 0.2, "medium": 0.5, "high": 0.8}[text]
        else:
            try:
                value = float(text)
            except ValueError:
                value = None
    if value is None:
        parsed.pop("confidence", None)
        return parsed
    if value > 1.0 and value <= 100.0:
        value = value / 100.0
    if value < 0.0:
        value = 0.0
    if value > 1.0:
        value = 1.0
    parsed["confidence"] = value
    return parsed


def _normalize_requested_functions(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    invalid_exact = {
        "cleanup_function_name_if_any",
        "cleanup_function_if_any",
        "cleanup_function_name",
        "cleanup_function",
        "cleanup_function_name_if_needed",
        "cleanup_function_if_needed",
        "remove",
        "exit",
        "uninit",
        "cleanup",
    }
    normalized = []
    for val in values:
        if not val:
            continue
        cleaned = str(val).strip()
        if cleaned.endswith("()"):
            cleaned = cleaned[:-2]
        upper = cleaned.upper()
        if upper in ("CALLER", "CALLERS"):
            cleaned = "CALLER_OF:SELF"
        elif upper in ("CALLEE", "CALLEES"):
            cleaned = "CALLEE_OF:SELF"
        if cleaned in invalid_exact:
            continue
        if "function_name" in cleaned:
            continue
        normalized.append(cleaned)
    return normalized

def _normalize_pattern_verdict(parsed: Any) -> Any:
    if not isinstance(parsed, dict):
        return parsed
    verdict = parsed.get("verdict")
    if isinstance(verdict, str):
        key = verdict.strip().lower()
        if key in ("valid", "invalid", "uncertain"):
            parsed["verdict"] = key
            return parsed
        if key in ("consistent", "inconsistent"):
            parsed["verdict"] = "valid" if key == "consistent" else "invalid"
            return parsed
    consistent = parsed.get("consistent")
    if consistent is True:
        parsed["verdict"] = "valid"
    elif consistent is False:
        parsed["verdict"] = "invalid"
    else:
        parsed["verdict"] = "uncertain"
    return parsed



def _normalize_behavior_list(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    normalized = []
    for val in values:
        if not val:
            continue
        cleaned = re.sub(r"\s+", " ", str(val).strip())
        if cleaned:
            normalized.append(cleaned)
    return normalized


def _pattern_signature(sec_behaviors: Any, def_behaviors: Any) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    sec = tuple(_normalize_behavior_list(sec_behaviors))
    defi = tuple(_normalize_behavior_list(def_behaviors))
    return (sec, defi)


def _build_pattern_frequency_map(entries: List[Dict[str, Any]]) -> Dict[Tuple[Tuple[str, ...], Tuple[str, ...]], int]:
    freq: Dict[Tuple[Tuple[str, ...], Tuple[str, ...]], int] = {}
    for entry in entries:
        llm_out = entry.get("llm_output", {}) or {}
        sec_behaviors = llm_out.get("security_sensitive_behaviors") or []
        def_behaviors = llm_out.get("defensive_behaviors") or []
        if not sec_behaviors and llm_out.get("analysis"):
            sec_behaviors = [llm_out["analysis"]]
        if not def_behaviors and llm_out.get("analysis"):
            def_behaviors = [llm_out["analysis"]]
        if not (sec_behaviors and def_behaviors):
            continue
        sig = _pattern_signature(sec_behaviors, def_behaviors)
        freq[sig] = freq.get(sig, 0) + 1
    return freq


def _load_patterns_csv_frequency_map(patterns_csv: str, defensive_op: str) -> Dict[Tuple[Tuple[str, ...], Tuple[str, ...]], int]:
    freq: Dict[Tuple[Tuple[str, ...], Tuple[str, ...]], int] = {}
    if not patterns_csv or not defensive_op or not os.path.exists(patterns_csv):
        return freq
    try:
        csv.field_size_limit(10**7)
    except Exception:
        try:
            csv.field_size_limit(2**31 - 1)
        except Exception:
            pass
    with open(patterns_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_defensive_op = row.get("defensive_op") or row.get("secop")
            if row_defensive_op != defensive_op:
                continue
            sec_text = row.get("security_sensitive_behaviors") or ""
            def_text = row.get("defensive_behaviors") or ""
            sig = _pattern_signature(sec_text, def_text)
            try:
                freq_val = int(row.get("frequency") or 0)
            except ValueError:
                freq_val = 0
            if sig in freq:
                freq[sig] = max(freq[sig], freq_val)
            else:
                freq[sig] = freq_val
    return freq




def _build_queries_from_key_calls(key_calls: List[str]) -> List[str]:
    queries = []
    seen = set()
    for call in key_calls or []:
        name = call.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        queries.append(f"_ $func(_){{{name}(_);}}")
    return queries


def _select_single_query(queries_meta: Dict[str, Any]) -> Dict[str, Any]:
    queries = queries_meta.get("queries") or []
    key_calls = queries_meta.get("key_calls") or []
    behaviors = queries_meta.get("security_sensitive_behaviors") or []
    behavior_text = " ".join(str(b) for b in behaviors if b).lower()

    chosen_call = None
    matched = False
    if isinstance(key_calls, list) and key_calls and behavior_text:
        for call in key_calls:
            if call and call.lower() in behavior_text:
                chosen_call = call
                matched = True
                break
        if not chosen_call:
            tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", behavior_text))
            for call in key_calls:
                if call in tokens:
                    chosen_call = call
                    matched = True
                    break

    if not chosen_call and isinstance(key_calls, list) and key_calls:
        chosen_call = key_calls[0]

    if chosen_call:
        chosen = f"_ $func(_){{{chosen_call}(_);}}"
    else:
        chosen = queries[0] if isinstance(queries, list) and queries else None
        if chosen:
            matched = True

    queries_meta["query"] = chosen
    queries_meta["queries"] = [chosen] if chosen else []
    queries_meta["key_calls"] = [chosen_call] if chosen_call else []
    queries_meta["query_match"] = matched
    return queries_meta


def _load_summary_key_calls(summary_path: str, defensive_op: str) -> List[str]:
    if not summary_path or not os.path.exists(summary_path) or not defensive_op:
        return []
    with open(summary_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Defensive operation") != defensive_op:
                continue
            raw = row.get("Security-sensitive APIs (top30)") or ""
            return [x.strip() for x in raw.split(";") if x.strip()]
    return []


def _load_candidate_funcs(path: str) -> set:
    funcs = set()
    if not path:
        return funcs
    candidate_path = Path(path)
    if not candidate_path.exists():
        raise FileNotFoundError(f"candidate functions file not found: {path}")

    if candidate_path.suffix.lower() == ".csv":
        with candidate_path.open(newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fn = row.get("function") or row.get("func_name") or row.get("candidate_function")
                if fn:
                    funcs.add(fn.strip())
        return {fn for fn in funcs if fn}

    with candidate_path.open() as f:
        return {line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")}


def _load_exclude_funcs_from_patterns(patterns_path: str, defensive_op: str) -> set:
    funcs = set()
    if not patterns_path or not os.path.exists(patterns_path) or not defensive_op:
        return funcs

    try:
        csv.field_size_limit(10**7)
    except Exception:
        try:
            csv.field_size_limit(2**31 - 1)
        except Exception:
            pass

    if patterns_path.endswith(".jsonl"):
        with open(patterns_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                rec_defensive_op = rec.get("defensive_op") or rec.get("secop")
                if rec_defensive_op != defensive_op:
                    continue
                funcs.update(rec.get("functions") or [])
        return funcs

    with open(patterns_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_defensive_op = row.get("defensive_op") or row.get("secop")
            if row_defensive_op != defensive_op:
                continue
            raw = row.get("all_functions") or row.get("functions_sample") or ""
            if not raw:
                continue
            try:
                vals = json.loads(raw)
            except Exception:
                vals = [x.strip() for x in re.split(r"[;,]", raw) if x.strip()]
            funcs.update(vals)
    return funcs


def _load_related_funcs_from_llm_inputs(path: str) -> set:
    funcs = set()
    if not path or not os.path.exists(path):
        return funcs
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        return funcs
    if not isinstance(data, list):
        return funcs
    for item in data:
        if not isinstance(item, dict):
            continue
        funcs.update(item.get("all_functions") or [])
        fn = item.get("func_name")
        if fn:
            funcs.add(fn)
    return funcs


def _load_related_funcs_from_llm_reports(path: str) -> set:
    funcs = set()
    if not path or not os.path.exists(path):
        return funcs
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        return funcs
    if not isinstance(data, list):
        return funcs
    for item in data:
        if not isinstance(item, dict):
            continue
        fn = item.get("func_name")
        if fn:
            funcs.add(fn)
        llm_input = item.get("llm_input") or {}
        funcs.update(llm_input.get("all_functions") or [])
    return funcs


@dataclass
class DefensivePattern:
    security_sensitive_behaviors: List[str] = field(default_factory=list)
    defensive_behaviors: List[str] = field(default_factory=list)
    name: str = ""
    source_func: str = ""
    source_defensive_op: str = ""
    source_code: str = ""
    frequency: int = 0

    @staticmethod
    def _load_from_llm_outputs(defensive_op: str, repo: str, func_name: Optional[str], index: Optional[int], parsed_path: Optional[str] = None) -> "DefensivePattern":
        cfg = load_config()
        security_sensitive_data_path = cfg["security_sensitive_data_path"]
        if parsed_path:
            path = parsed_path
            if not os.path.exists(path):
                raise SystemExit(f"LLM parsed file not found: {path}")
        else:
            path = os.path.join(security_sensitive_data_path, repo, "llm_reports", f"{defensive_op}.parsed.json")
            
            # If standard file not found, try to find timestamped version
            if not os.path.exists(path):
                import glob
                pattern = os.path.join(security_sensitive_data_path, repo, "llm_reports", f"{defensive_op}_ts*.parsed.json")
                candidates = sorted(glob.glob(pattern), reverse=True)  # newest first
                if candidates:
                    path = candidates[0]
                    print(f"[info] Using timestamped file: {os.path.basename(path)}")
                else:
                    raise SystemExit(f"LLM parsed file not found: {path} (also tried {defensive_op}_ts*.parsed.json)")

        with open(path, "r") as f:
            data = json.load(f)

        freq_map = _build_pattern_frequency_map(data)

        patterns_csv = str(rt.repo_path("output", "pattern_stats", "patterns.csv"))
        csv_freq_map = _load_patterns_csv_frequency_map(patterns_csv, defensive_op)

        if func_name:
            data = [d for d in data if d.get("func_name") == func_name]
            if not data:
                raise SystemExit(f"Func {func_name} not found in {path}")
        if index is not None:
            if index < 0 or index >= len(data):
                raise SystemExit(f"index {index} out of range (size={len(data)}) for {path}")
            data = [data[index]]

        # pick first with non-empty defensive behaviors; otherwise fall back to any item
        chosen = None
        for d in data:
            llm_out = d.get("llm_output", {}) or {}
            if llm_out.get("defensive_behaviors") or llm_out.get("security_sensitive_behaviors"):
                chosen = d
                break
        if not chosen and data:
            chosen = data[0]
        if not chosen:
            raise SystemExit(f"No entries available in {path}")

        llm_out = chosen.get("llm_output", {}) or {}
        sec_behaviors = llm_out.get("security_sensitive_behaviors") or []
        def_behaviors = llm_out.get("defensive_behaviors") or []
        if isinstance(sec_behaviors, str):
            sec_behaviors = [sec_behaviors]
        if isinstance(def_behaviors, str):
            def_behaviors = [def_behaviors]
        # Fallback: use analysis as a single behavior if specific fields are empty
        if not sec_behaviors and llm_out.get("analysis"):
            sec_behaviors = [llm_out["analysis"]]
        if not def_behaviors and llm_out.get("analysis"):
            def_behaviors = [llm_out["analysis"]]

        llm_input = chosen.get("llm_input", {}) or {}
        source_code = llm_input.get("function") or llm_input.get("code_slice") or ""
        sig = _pattern_signature(sec_behaviors, def_behaviors)
        freq = csv_freq_map.get(sig, freq_map.get(sig, 0))

        return DefensivePattern(
            security_sensitive_behaviors=sec_behaviors,
            defensive_behaviors=def_behaviors,
            name=f"{defensive_op}:{chosen.get('func_name','')}",
            source_func=chosen.get("func_name", ""),
            source_defensive_op=defensive_op,
            source_code=source_code,
            frequency=freq,
        )

    @staticmethod
    def load_all_from_llm(defensive_op: str, repo: str, parsed_path: Optional[str] = None) -> List["DefensivePattern"]:
        """Load all valid patterns from llm_reports."""
        cfg = load_config()
        security_sensitive_data_path = cfg["security_sensitive_data_path"]
        if parsed_path:
            path = parsed_path
            if not os.path.exists(path):
                raise SystemExit(f"LLM parsed file not found: {path}")
        else:
            path = os.path.join(security_sensitive_data_path, repo, "llm_reports", f"{defensive_op}.parsed.json")
            
            # If standard file not found, try to find timestamped version
            if not os.path.exists(path):
                import glob
                pattern = os.path.join(security_sensitive_data_path, repo, "llm_reports", f"{defensive_op}_ts*.parsed.json")
                candidates = sorted(glob.glob(pattern), reverse=True)  # newest first
                if candidates:
                    path = candidates[0]
                    print(f"[info] Using timestamped file: {os.path.basename(path)}")
                else:
                    raise SystemExit(f"LLM parsed file not found: {path} (also tried {defensive_op}_ts*.parsed.json)")

        with open(path, "r") as f:
            data = json.load(f)

        freq_map = _build_pattern_frequency_map(data)

        patterns_csv = str(rt.repo_path("output", "pattern_stats", "patterns.csv"))
        csv_freq_map = _load_patterns_csv_frequency_map(patterns_csv, defensive_op)

        patterns = []
        for idx, entry in enumerate(data):
            llm_out = entry.get("llm_output", {}) or {}
            sec_behaviors = llm_out.get("security_sensitive_behaviors") or []
            def_behaviors = llm_out.get("defensive_behaviors") or []
            if isinstance(sec_behaviors, str):
                sec_behaviors = [sec_behaviors]
            if isinstance(def_behaviors, str):
                def_behaviors = [def_behaviors]
            if not sec_behaviors and llm_out.get("analysis"):
                sec_behaviors = [llm_out["analysis"]]
            if not def_behaviors and llm_out.get("analysis"):
                def_behaviors = [llm_out["analysis"]]
            
            if not (sec_behaviors and def_behaviors):
                continue
            
            sig = _pattern_signature(sec_behaviors, def_behaviors)
            llm_input = entry.get("llm_input", {}) or {}
            source_code = llm_input.get("function") or llm_input.get("code_slice") or ""
            freq = csv_freq_map.get(sig, freq_map.get(sig, 0))
            patterns.append(DefensivePattern(
                security_sensitive_behaviors=sec_behaviors,
                defensive_behaviors=def_behaviors,
                name=f"{defensive_op}:{entry.get('func_name','')}:{idx}",
                source_func=entry.get("func_name", ""),
                source_defensive_op=defensive_op,
                source_code=source_code,
                frequency=freq,
            ))
        
        return patterns

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "DefensivePattern":
        if args.pattern_from_llm:
            # Use explicit value or fall back to the selected defensive operation.
            defensive_op_value = getattr(args, '_pattern_from_llm_set', None) or args.pattern_from_llm
            if isinstance(defensive_op_value, bool):
                defensive_op_value = args.defensive_op
            return cls._load_from_llm_outputs(
                defensive_op=defensive_op_value,
                repo=args.repo,
                func_name=args.pattern_func,
                index=args.pattern_index,
                parsed_path=args.pattern_llm_file,
            )

        if args.pattern_file:
            with open(args.pattern_file, "r") as f:
                data = json.load(f)
            return cls(
                security_sensitive_behaviors=data.get("security_sensitive_behaviors", []),
                defensive_behaviors=data.get("defensive_behaviors", []),
                name=data.get("name", args.defensive_op or ""),
                source_func=data.get("source_func", ""),
                source_defensive_op=args.defensive_op or "",
                source_code=data.get("source_code", ""),
            )

        def _split(val: Optional[str]) -> List[str]:
            if not val:
                return []
            # split on semicolon or newline for convenience
            parts = re.split(r"[;\n]+", val)
            return [p.strip() for p in parts if p.strip()]

        return cls(
            security_sensitive_behaviors=_split(args.security_behaviors),
            defensive_behaviors=_split(args.defensive_behaviors),
            name=args.defensive_op or "",
            source_defensive_op=args.defensive_op or "",
        )

    def is_valid(self) -> bool:
        return bool(self.security_sensitive_behaviors and self.defensive_behaviors)


class LLMWeggliTranslator:
    """LLM helper: behaviors -> weggli queries."""

    PROMPT_FILE = rt.PROMPT_DIR / "extract_ast_query_operations.txt"

    def __init__(self, repo_name: str, model: Optional[str] = None):
        cfg = load_config()
        self.model = model or cfg.get("openai_model") or DEFAULT_MODEL
        self.api_base = normalize_api_base(cfg.get("openai_api_base") or os.environ.get("OPENAI_API_BASE", "https://api.openai.com"))
        cfg_api_key = cfg.get("openai_api_key")
        self.api_key = os.environ.get("OPENAI_API_KEY", "") if cfg_api_key in (None, "", "YOUR_KEY") else cfg_api_key
        self.repo_name = repo_name

    def _build_prompt(self, behaviors: List[str]) -> str:
        template = self.PROMPT_FILE.read_text()
        joined = "\n".join(f"- {b}" for b in behaviors)
        return template.format_map({"behaviors": joined})

    def translate_with_meta(self, behaviors: List[str], dry_run: bool = False) -> Dict[str, Any]:
        if not behaviors:
            return {"key_calls": [], "queries": []}

        key_calls: List[str] = _extract_key_calls_from_behaviors(behaviors)
        if not key_calls and not (dry_run or not self.api_key):
            prompt = self._build_prompt(behaviors)
            resp = call_openai(self.api_base, self.api_key, self.model, prompt)
            if resp is None:
                print("[warn] LLM call failed for weggli translation, using empty key_calls")
            else:
                content = resp.choices[0].message.content if resp.choices else ""
                parsed = _safe_json_loads(_strip_json_block(content))
                if isinstance(parsed, dict):
                    kc = parsed.get("key_calls") or []
                    if isinstance(kc, str):
                        key_calls = [kc]
                    elif isinstance(kc, list):
                        key_calls = [c for c in kc if isinstance(c, str) and c.strip()]

        # Build call-site queries from key_calls only
        queries = []
        seen = set()
        for call in key_calls:
            name = call.strip()
            if not name or name in seen:
                continue
            seen.add(name)
            queries.append(f"_ $func(_){{{name}(_);}}")

        return {"key_calls": key_calls, "queries": queries}

    def translate(self, behaviors: List[str], dry_run: bool = False) -> List[str]:
        return self.translate_with_meta(behaviors, dry_run=dry_run).get("queries", [])


class WeggliRunner:
    """Thin wrapper to run weggli queries and parse matches."""

    def __init__(self, repo_name: str):
        cfg = load_config()
        if repo_name not in cfg["program_paths"]:
            raise ValueError(f"Repository {repo_name} not configured")
        self.source_dir = cfg["program_paths"][repo_name]
        self.weggli_path = cfg["weggli_path"]

    def _parse_weggli_json(self, data: Any) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not isinstance(data, list):
            return results
        for file_set in data:
            if not isinstance(file_set, list):
                continue
            for file_entry in file_set:
                file_path = file_entry.get("path") or ""
                for match_group in file_entry.get("matches", []):
                    func_code = match_group.get("function", "")
                    func_name = None
                    var_name = None
                    for match in match_group.get("vars", []):
                        if match.get("var") == "$func":
                            func_name = match.get("val")
                        elif match.get("var") == "$var":
                            var_name = match.get("val")
                    if func_name:
                        results.append(
                            {
                                "func_name": func_name,
                                "var": var_name,
                                "function": func_code,
                                "path": file_path,
                            }
                        )
        return results

    def run_query(self, query: str) -> List[Dict[str, Any]]:
        if not query:
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cmd = [self.weggli_path, query, self.source_dir, "-l", "-s", tmp_path]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or f"weggli failed: {proc.returncode}")
            with open(tmp_path, "r") as f:
                data = json.load(f)
            return self._parse_weggli_json(data)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _extract_function_from_file(self, path: str, func_name: str) -> Optional[str]:
        if not path or not func_name or not os.path.exists(path):
            return None
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", func_name):
            return None
        try:
            with open(path, "r") as f:
                text = f.read()
        except Exception:
            return None
        pattern = re.compile(r"\b" + re.escape(func_name) + r"\s*\(", re.M)
        for match in pattern.finditer(text):
            i = match.start() - 1
            while i >= 0 and text[i].isspace():
                i -= 1
            if i >= 1 and text[i - 1 : i + 1] == "->":
                continue
            if i >= 0 and text[i] == ".":
                continue
            brace_pos = text.find("{", match.end())
            if brace_pos == -1:
                continue
            if ";" in text[match.end() : brace_pos]:
                continue
            depth = 0
            end = None
            for j in range(brace_pos, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break
            if end is None:
                continue
            start = text.rfind("\n", 0, match.start()) + 1
            return text[start:end]
        return None

    def fetch_function_source(self, func_name: str) -> Optional[str]:
        """Fetch function body by name using a loose weggli pattern."""
        if not func_name:
            return None
        # Allow any params/body; `_` in params matches arbitrary arguments.
        query = f"_ {func_name}(_){{}}"
        matches = self.run_query(query)
        if matches:
            return matches[0].get("function")
        return None

    def fetch_function_source_by_path(self, func_name: str, path: Optional[str] = None) -> Optional[str]:
        if not func_name:
            return None
        query = f"_ {func_name}(_){{}}"
        matches = self.run_query(query)
        if not matches:
            if path:
                return self._extract_function_from_file(path, func_name)
            return None
        if path:
            for m in matches:
                if m.get("path") == path:
                    return m.get("function")
        return matches[0].get("function")

    def find_callers(
        self, callee_name: str, max_funcs: int = 3, path_contains: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not callee_name:
            return []
        query = f"_ $func(_){{{callee_name}(_);}}"
        matches = self.run_query(query)
        if path_contains:
            matches = [m for m in matches if path_contains in (m.get("path") or "")]
        return matches[:max_funcs]


class DefensivePatternAuditor:
    AUDIT_PROMPT_FILE = rt.PROMPT_DIR / "bug_detection_inconsistency_auditing.txt"
    PATTERN_PROMPT_FILE = rt.PROMPT_DIR / "defensive_pattern_validation.txt"

    def __init__(self, repo_name: str):
        self.repo_name = repo_name
        self.weggli = WeggliRunner(repo_name)
        self.cfg = load_config()

    def _load_llm_config(self, override_model: Optional[str] = None):
        model = override_model or self.cfg.get("openai_model") or DEFAULT_MODEL
        api_base = normalize_api_base(self.cfg.get("openai_api_base") or os.environ.get("OPENAI_API_BASE", "https://api.openai.com"))
        cfg_api_key = self.cfg.get("openai_api_key")
        api_key = os.environ.get("OPENAI_API_KEY", "") if cfg_api_key in (None, "", "YOUR_KEY") else cfg_api_key
        return api_base, api_key, model

    def generate_weggli_queries(
        self,
        pattern: DefensivePattern,
        llm_model: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        translator = LLMWeggliTranslator(self.repo_name, model=llm_model)
        meta = translator.translate_with_meta(pattern.security_sensitive_behaviors, dry_run=dry_run)
        if not meta.get("key_calls"):
            print("[warn] LLM did not return key_calls; weggli queries are empty")
        meta.update(
            {
                "security_sensitive_behaviors": pattern.security_sensitive_behaviors,
                "reference_func": pattern.source_func,
                "reference_defensive_op": pattern.source_defensive_op,
            }
        )
        return meta

    def locate_candidates(
        self,
        pattern: DefensivePattern,
        llm_model: Optional[str] = None,
        dry_run: bool = False,
        limit: Optional[int] = None,
        queries_meta: Optional[Dict[str, Any]] = None,
        exclude_funcs: Optional[set] = None,
        include_funcs: Optional[set] = None,
        exclude_contains: Optional[List[str]] = None,
        exclude_path_contains: Optional[List[str]] = None,
        exclude_path_regex: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        if queries_meta:
            queries = queries_meta.get("queries", [])
        else:
            translator = LLMWeggliTranslator(self.repo_name, model=llm_model)
            queries = translator.translate(pattern.security_sensitive_behaviors, dry_run=dry_run)
        candidates: List[Dict[str, Any]] = []
        for q in queries:
            try:
                candidates.extend(self.weggli.run_query(q))
            except Exception as e:
                print(f"[warn] weggli query failed and was skipped: {q} :: {e}")

        # dedup by func_name and apply optional text filters
        seen = set()
        deduped = []
        exclude_contains = [s for s in (exclude_contains or []) if s]
        exclude_path_contains = [s for s in (exclude_path_contains or []) if s]
        exclude_path_regex = [s for s in (exclude_path_regex or []) if s]
        for c in candidates:
            fn = c.get("func_name")
            code = c.get("function") or ""
            path = c.get("path") or ""
            if include_funcs and fn not in include_funcs:
                continue
            if exclude_path_contains and path and any(s in path for s in exclude_path_contains):
                continue
            if exclude_path_regex and path:
                if any(re.search(pat, path) for pat in exclude_path_regex):
                    continue
            if exclude_contains and code and any(s in code for s in exclude_contains):
                continue
            if exclude_funcs and fn in exclude_funcs:
                continue
            if fn and fn not in seen:
                seen.add(fn)
                deduped.append(c)
        if limit:
            deduped = deduped[:limit]
        return deduped

    def _build_audit_prompt(
        self, pattern: DefensivePattern, candidate: Dict[str, Any], code: str, extra_context: str = ""
    ) -> str:
        template = self.AUDIT_PROMPT_FILE.read_text()
        extra_context = extra_context or "None"
        return template.format_map(
            {
                "sec_behaviors": "\n- ".join(pattern.security_sensitive_behaviors),
                "def_behaviors": "\n- ".join(pattern.defensive_behaviors),
                "func_name": candidate.get("func_name"),
                "code": code,
                "extra_context": extra_context,
            }
        )

    def _build_pattern_validate_prompt(
        self, pattern: DefensivePattern, code: str, extra_context: str = ""
    ) -> str:
        template = self.PATTERN_PROMPT_FILE.read_text()
        extra_context = extra_context or "None"
        return template.format_map(
            {
                "defensive_operation": pattern.source_defensive_op,
                "sec_behaviors": "\n- ".join(pattern.security_sensitive_behaviors),
                "def_behaviors": "\n- ".join(pattern.defensive_behaviors),
                "func_name": pattern.source_func,
                "code": code or "None",
                "extra_context": extra_context,
            }
        )

    def validate_pattern(
        self,
        pattern: DefensivePattern,
        llm_model: Optional[str] = None,
        dry_run: bool = False,
        timeout: float = 300.0,
    ) -> Dict[str, Any]:
        if dry_run:
            return {"verdict": "uncertain", "reason": "dry_run: LLM call skipped"}

        api_base, api_key, model = self._load_llm_config(override_model=llm_model)
        if not api_key:
            return {"verdict": "uncertain", "reason": "missing API key"}

        code = pattern.source_code or self.weggli.fetch_function_source(pattern.source_func) or ""
        prompt = self._build_pattern_validate_prompt(pattern, code)
        resp = call_openai(api_base, api_key, model, prompt, timeout=timeout)
        if resp is None:
            return {"verdict": "uncertain", "reason": "LLM API call failed"}

        content = resp.choices[0].message.content if resp.choices else ""
        parsed = _normalize_pattern_verdict(_safe_json_loads(_strip_json_block(content)) or {})
        if parsed.get("needs_more_context"):
            requested = _normalize_requested_functions(parsed.get("requested_functions"))
            if not requested:
                requested = ["CALLEE_OF:SELF", "CALLER_OF:SELF"]
            parsed["requested_functions"] = requested
            extra_context = self._collect_extra_context(
                requested,
                candidate={"func_name": pattern.source_func, "path": ""},
                code=code,
            )
            if extra_context:
                followup_prompt = self._build_pattern_validate_prompt(pattern, code, extra_context=extra_context)
                resp2 = call_openai(api_base, api_key, model, followup_prompt, timeout=timeout)
                if resp2 is not None:
                    followup_raw = resp2.choices[0].message.content if resp2.choices else ""
                    followup_parsed = _normalize_pattern_verdict(
                        _safe_json_loads(_strip_json_block(followup_raw)) or {}
                    )
                    if followup_parsed:
                        parsed = followup_parsed
        return parsed

    def _collect_extra_context(
        self,
        func_names: List[str],
        candidate: Optional[Dict[str, Any]] = None,
        code: str = "",
        max_funcs: int = 5,
        max_chars: int = 12000,
    ) -> str:
        chunks: List[str] = []
        seen = set()
        candidate_name = (candidate or {}).get("func_name") or ""
        candidate_path = (candidate or {}).get("path") or ""

        def _add_chunk(label: str, src: Optional[str], key: str):
            if not src or key in seen:
                return
            seen.add(key)
            chunks.append(f"{label}:\n{src}")

        for name in func_names or []:
            if not name:
                continue
            cleaned = name.strip()
            if cleaned.endswith("()"):
                cleaned = cleaned[:-2]
            upper = cleaned.upper()
            if upper in ("CALLER", "CALLERS"):
                cleaned = "CALLER_OF:SELF"
                upper = cleaned.upper()
            elif upper in ("CALLEE", "CALLEES"):
                cleaned = "CALLEE_OF:SELF"
                upper = cleaned.upper()
            if upper.startswith("CALLER_OF:"):
                target = cleaned.split(":", 1)[1].strip()
                if target.endswith("()"):
                    target = target[:-2]
                if target.upper() in ("SELF", "CANDIDATE", "THIS"):
                    target = candidate_name
                if not target:
                    continue
                callers = self.weggli.find_callers(target, max_funcs=max_funcs - len(chunks), path_contains=candidate_path)
                if not callers and candidate_path:
                    callers = self.weggli.find_callers(target, max_funcs=max_funcs - len(chunks))
                for m in callers:
                    func = m.get("func_name") or ""
                    _add_chunk(f"Caller {func}", m.get("function"), f"caller:{func}")
                if len(chunks) >= max_funcs:
                    break
                continue
            if upper.startswith("CALLEE_OF:"):
                target = cleaned.split(":", 1)[1].strip()
                if target.endswith("()"):
                    target = target[:-2]
                if target.upper() in ("SELF", "CANDIDATE", "THIS"):
                    callee_names = _extract_callee_names(code, func_name=candidate_name, max_items=max_funcs)
                    for callee in callee_names:
                        src = self.weggli.fetch_function_source(callee)
                        _add_chunk(f"Callee {callee}", src, f"callee:{callee}")
                        if len(chunks) >= max_funcs:
                            break
                    if len(chunks) >= max_funcs:
                        break
                    continue
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", target):
                    continue
                src = self.weggli.fetch_function_source(target)
                _add_chunk(f"Callee {target}", src, f"callee:{target}")
                if len(chunks) >= max_funcs:
                    break
                continue
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cleaned):
                continue
            src = self.weggli.fetch_function_source(cleaned)
            _add_chunk(f"Function {cleaned}", src, f"func:{cleaned}")
            if len(chunks) >= max_funcs:
                break

        extra = "\n\n".join(chunks)
        if len(extra) > max_chars:
            extra = extra[:max_chars]
        return extra

    def audit(
        self,
        pattern: DefensivePattern,
        candidates: List[Dict[str, Any]],
        llm_model: Optional[str] = None,
        dry_run: bool = False,
        fetch_missing_code: bool = True,
        timeout: float = 300.0,
        workers: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        api_base, api_key, model = self._load_llm_config(override_model=llm_model)
        outputs: List[Dict[str, Any]] = [None] * len(candidates)
        encoding = _get_encoding(model)

        def _compute_tokens(prompt: str, response: str, usage: Optional[Dict[str, int]]):
            if usage and usage.get("prompt_tokens") is not None and usage.get("completion_tokens") is not None:
                prompt_tokens = usage.get("prompt_tokens") or 0
                response_tokens = usage.get("completion_tokens") or 0
                total_tokens = usage.get("total_tokens")
                if total_tokens is None:
                    total_tokens = prompt_tokens + response_tokens
                return prompt_tokens, response_tokens, total_tokens, False
            prompt_tokens = _count_tokens(prompt, encoding)
            response_tokens = _count_tokens(response, encoding)
            return prompt_tokens, response_tokens, prompt_tokens + response_tokens, True

        def _run_one(idx: int, cand: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
            code = cand.get("function") or ""
            if not code and fetch_missing_code:
                code = self.weggli.fetch_function_source(cand.get("func_name", "")) or ""
            prompt = self._build_audit_prompt(pattern, cand, code)

            if dry_run or not api_key:
                prompt_tokens, response_tokens, total_tokens, estimated = _compute_tokens(prompt, "", None)
                return idx, {
                    "func_name": cand.get("func_name"),
                    "reference_func": pattern.source_func,
                    "reference_defensive_op": pattern.source_defensive_op,
                    "pattern_security_behaviors": pattern.security_sensitive_behaviors,
                    "pattern_defensive_behaviors": pattern.defensive_behaviors,
                    "verdict": "uncertain",
                    "consistent": None,
                    "missing_defenses": [],
                    "bug_explanation": "dry_run: LLM call skipped",
                    "needs_more_context": False,
                    "requested_functions": [],
                    "prompt": prompt,
                    "usage": None,
                    "prompt_tokens": prompt_tokens,
                    "response_tokens": response_tokens,
                    "total_tokens": total_tokens,
                    "token_estimated": estimated,
                }

            resp = call_openai(api_base, api_key, model, prompt, timeout=timeout)
            if resp is None:
                prompt_tokens, response_tokens, total_tokens, estimated = _compute_tokens(prompt, "", None)
                # LLM call failed after retries, skip this candidate
                return idx, {
                    "func_name": cand.get("func_name"),
                    "reference_func": pattern.source_func,
                    "reference_defensive_op": pattern.source_defensive_op,
                    "pattern_security_behaviors": pattern.security_sensitive_behaviors,
                    "pattern_defensive_behaviors": pattern.defensive_behaviors,
                    "verdict": "error",
                    "consistent": None,
                    "missing_defenses": [],
                    "bug_explanation": "LLM API call failed after retries",
                    "needs_more_context": False,
                    "requested_functions": [],
                    "prompt": prompt,
                    "error": "API connection failed",
                    "usage": None,
                    "prompt_tokens": prompt_tokens,
                    "response_tokens": response_tokens,
                    "total_tokens": total_tokens,
                    "token_estimated": estimated,
                }
            
            content = resp.choices[0].message.content if resp.choices else ""
            usage = _extract_usage(resp)
            prompt_tokens, response_tokens, total_tokens, estimated = _compute_tokens(prompt, content, usage)
            parsed = _safe_json_loads(_strip_json_block(content))
            parsed = _normalize_verdict(parsed or {})
            followup_raw = None
            followup_parsed = None
            used_followup = False
            followup_prompt = None
            followup_usage = None
            followup_prompt_tokens = 0
            followup_response_tokens = 0
            followup_total_tokens = 0
            followup_estimated = False
            if parsed.get("needs_more_context"):
                requested = _normalize_requested_functions(parsed.get("requested_functions"))
                if not requested:
                    requested = ["CALLEE_OF:SELF", "CALLER_OF:SELF"]
                parsed["requested_functions"] = requested
                extra_context = self._collect_extra_context(requested, candidate=cand, code=code)
                if extra_context:
                    followup_prompt = self._build_audit_prompt(pattern, cand, code, extra_context=extra_context)
                    resp2 = call_openai(api_base, api_key, model, followup_prompt, timeout=timeout)
                    followup_usage = _extract_usage(resp2)
                    followup_raw = resp2.choices[0].message.content if resp2 and resp2.choices else ""
                    (
                        followup_prompt_tokens,
                        followup_response_tokens,
                        followup_total_tokens,
                        followup_estimated,
                    ) = _compute_tokens(followup_prompt, followup_raw or "", followup_usage)
                    followup_parsed = _normalize_verdict(_safe_json_loads(_strip_json_block(followup_raw)) or {})
                    if followup_parsed:
                        parsed = followup_parsed
                        used_followup = True
            return idx, {
                "func_name": cand.get("func_name"),
                "reference_func": pattern.source_func,
                "reference_defensive_op": pattern.source_defensive_op,
                "pattern_security_behaviors": pattern.security_sensitive_behaviors,
                "pattern_defensive_behaviors": pattern.defensive_behaviors,
                "raw_response": content,
                "parsed": parsed,
                "verdict": parsed.get("verdict") if isinstance(parsed, dict) else None,
                "consistent": parsed.get("consistent") if isinstance(parsed, dict) else None,
                "confidence": parsed.get("confidence") if isinstance(parsed, dict) else None,
                "missing_defenses": parsed.get("missing_defenses") if isinstance(parsed, dict) else None,
                "bug_explanation": parsed.get("bug_explanation") if isinstance(parsed, dict) else None,
                "needs_more_context": parsed.get("needs_more_context") if isinstance(parsed, dict) else None,
                "requested_functions": parsed.get("requested_functions") if isinstance(parsed, dict) else None,
                "followup_prompt": followup_prompt,
                "followup_raw_response": followup_raw,
                "followup_parsed": followup_parsed,
                "used_followup": used_followup,
                "prompt": prompt,
                "usage": usage,
                "prompt_tokens": prompt_tokens,
                "response_tokens": response_tokens,
                "total_tokens": total_tokens,
                "token_estimated": estimated,
                "followup_usage": followup_usage,
                "followup_prompt_tokens": followup_prompt_tokens,
                "followup_response_tokens": followup_response_tokens,
                "followup_total_tokens": followup_total_tokens,
                "followup_token_estimated": followup_estimated,
            }

        max_workers = workers or 1
        if max_workers < 1:
            max_workers = 1
        max_workers = min(max_workers, max(1, len(candidates)))
        if max_workers == 1:
            for idx, cand in enumerate(tqdm(candidates, desc="Defensive audit", unit="func")):
                _, item = _run_one(idx, cand)
                outputs[idx] = item
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = [ex.submit(_run_one, idx, cand) for idx, cand in enumerate(candidates)]
                for fut in tqdm(as_completed(futures), total=len(futures), desc="Defensive audit", unit="func"):
                    idx, item = fut.result()
                    outputs[idx] = item
        return outputs


def main():
    parser = argparse.ArgumentParser(description="Audit defensive pattern consistency using LLM + weggli.")
    # Core parameters
    parser.add_argument("--defensive-op", dest="defensive_op", help="defensive operation to audit (e.g., kfree, clk_put)")
    parser.add_argument("--secop", dest="defensive_op", help=argparse.SUPPRESS)
    parser.add_argument("--repo", default="linux", help="repo key from config.json")
    parser.add_argument("--llm-model", help="override LLM model id (e.g., DeepSeek-V3.2)")
    parser.add_argument("--llm-timeout", type=float, default=300.0, help="LLM API timeout in seconds (default: 300)")
    parser.add_argument("--workers", type=int, default=4, help="parallel workers for audit (default: 4)")
    parser.add_argument("--limit", type=int, default=0, help="limit number of candidate functions (for testing)")
    parser.add_argument("--dry-run", action="store_true", help="skip LLM calls (still runs weggli)")
    parser.add_argument("--output", help="optional path to save audit results (JSON)")
    parser.add_argument("--weggli-only", action="store_true", help="only generate/save weggli queries and exit")
    parser.add_argument(
        "--candidate-functions-file",
        help="optional newline or CSV file of candidate function names to audit after candidate locating",
    )
    
    # Pattern selection (advanced)
    parser.add_argument("--pattern-func", help="pick an inferred defensive-pattern entry by func_name")
    parser.add_argument("--pattern-index", type=int, help="pick an inferred defensive-pattern entry by index (0-based)")
    parser.add_argument("--pattern-llm-file", help="explicit parsed inferred-pattern JSON file to load")
    parser.add_argument("--all-patterns", action="store_true", help="iterate all inferred defensive patterns (generates bug reports)")
    parser.add_argument("--limit-per-pattern", type=int, help="limit candidates per pattern when using --all-patterns")
    parser.add_argument("--min-pattern-frequency", type=int, default=0, help="minimum frequency for inferred pattern behaviors")
    parser.add_argument("--require-query-match", action="store_true", help="skip patterns whose behaviors do not match a key call")
    parser.add_argument("--require-defensive-op", dest="require_defensive_op", action="store_true", help="skip patterns whose defensive behaviors do not mention the defensive operation")
    parser.add_argument("--pattern-llm-validate", action="store_true", help="validate patterns with LLM before scanning")
    parser.add_argument("--pattern-llm-strict", action="store_true", help="drop patterns with uncertain LLM validation")
    
    # Disable default behaviors
    parser.add_argument(
        "--no-pattern-from-llm",
        dest="pattern_from_llm",
        action="store_false",
        default=True,
        help="disable automatic inferred-pattern loading",
    )
    parser.add_argument(
        "--no-weggli-from-summary",
        dest="weggli_from_summary",
        action="store_false",
        default=True,
        help="disable using summary CSV, use LLM to translate queries instead",
    )
    parser.add_argument(
        "--no-exclude-pattern-funcs",
        dest="exclude_pattern_funcs",
        action="store_false",
        default=True,
        help="disable excluding pattern reference functions",
    )
    parser.add_argument(
        "--no-exclude-related-funcs",
        dest="exclude_related_funcs",
        action="store_false",
        default=True,
        help="disable excluding functions already used during pattern reasoning",
    )
    args = parser.parse_args()
    if not args.defensive_op:
        parser.error("--defensive-op is required")

    # Multi-pattern mode
    if args.all_patterns:
        if not args.pattern_from_llm:
            raise SystemExit("--all-patterns requires --pattern-from-llm (default enabled)")
        patterns = DefensivePattern.load_all_from_llm(args.defensive_op, args.repo, parsed_path=args.pattern_llm_file)
        if not patterns:
            raise SystemExit(f"No valid inferred defensive patterns found for {args.defensive_op}")
        print(f"[info] Loaded {len(patterns)} patterns for {args.defensive_op}")
    else:
        pattern = DefensivePattern.from_args(args)
        if not pattern.is_valid():
            raise SystemExit("Failed to load pattern. Provide inferred_defensive_patterns.json with --pattern-llm-file, or use --no-pattern-from-llm.")
        patterns = [pattern]

    auditor = DefensivePatternAuditor(args.repo)
    if args.min_pattern_frequency and args.min_pattern_frequency > 0:
        before = len(patterns)
        patterns = [p for p in patterns if p.frequency >= args.min_pattern_frequency]
        print(f"[info] Filtered patterns by frequency >= {args.min_pattern_frequency}: {before} -> {len(patterns)}")

    if args.require_defensive_op and args.defensive_op:
        before = len(patterns)
        defensive_op_pat = re.compile(r"\b" + re.escape(args.defensive_op) + r"\b", re.IGNORECASE)
        patterns = [p for p in patterns if defensive_op_pat.search(" ".join(p.defensive_behaviors))]
        print(f"[info] Filtered patterns by defensive operation mention: {before} -> {len(patterns)}")

    if args.pattern_llm_validate:
        _api_base, api_key, _model = auditor._load_llm_config(override_model=args.llm_model)
        if args.dry_run:
            print("[warn] --pattern-llm-validate skipped due to --dry-run")
        elif not api_key:
            print("[warn] --pattern-llm-validate skipped due to missing API key")
        else:
            invalid = 0
            uncertain = 0
            kept = []
            for pattern in patterns:
                verdict = auditor.validate_pattern(
                    pattern,
                    llm_model=args.llm_model,
                    dry_run=False,
                    timeout=args.llm_timeout,
                ).get("verdict")
                verdict = (verdict or "").lower()
                if verdict == "invalid":
                    invalid += 1
                    continue
                if verdict == "uncertain" and args.pattern_llm_strict:
                    uncertain += 1
                    continue
                kept.append(pattern)
            patterns = kept
            print(f"[info] Pattern validation kept {len(patterns)}, invalid {invalid}, uncertain {uncertain}")

    if not patterns:
        raise SystemExit("No patterns left after filtering")

    limit = args.limit if args.limit > 0 else None
    limit_per_pattern = args.limit_per_pattern if hasattr(args, 'limit_per_pattern') and args.limit_per_pattern else limit
    include_funcs = _load_candidate_funcs(args.candidate_functions_file) if args.candidate_functions_file else set()
    
    # Generate model suffix for filenames
    model_suffix = ""
    if args.llm_model:
        model_tag = args.llm_model.replace("/", "_").replace("-", "_").replace(".", "_").lower()
        model_suffix = f"_{model_tag}"
    
    # Build exclusion set from pattern references and related functions
    exclude_funcs = set()
    defensive_op_for_exclusion = patterns[0].source_defensive_op or args.defensive_op
    if defensive_op_for_exclusion:
        # Exclude functions from llm_reports
        try:
            llm_path = os.path.join(
                auditor.cfg["security_sensitive_data_path"], args.repo, "llm_reports", f"{defensive_op_for_exclusion}.parsed.json"
            )
            if os.path.exists(llm_path):
                with open(llm_path, "r") as f:
                    llm_data = json.load(f)
                exclude_funcs = {d.get("func_name") for d in llm_data if d.get("func_name")}
        except Exception:
            pass
    
    if args.exclude_pattern_funcs:
        patterns_file = str(rt.repo_path("output", "pattern_stats", "patterns.csv"))
        exclude_funcs.update(_load_exclude_funcs_from_patterns(patterns_file, defensive_op_for_exclusion))
    
    if args.exclude_related_funcs:
        if defensive_op_for_exclusion:
            llm_inputs_path = os.path.join(
                auditor.cfg["security_sensitive_data_path"], args.repo, "llm_inputs", f"{defensive_op_for_exclusion}.json"
            )
            llm_reports_path = os.path.join(
                auditor.cfg["security_sensitive_data_path"], args.repo, "llm_reports", f"{defensive_op_for_exclusion}.parsed.json"
            )
            exclude_funcs.update(_load_related_funcs_from_llm_inputs(llm_inputs_path))
            exclude_funcs.update(_load_related_funcs_from_llm_reports(llm_reports_path))

    # Multi-pattern iteration
    all_audit_outputs = []
    summary_rows = []
    seen_candidate_keys = set()
    seen_bug_keys = set()
    
    # Initialize bug reports file for real-time writing
    bug_dir = os.path.join(auditor.cfg["security_sensitive_data_path"], args.repo, "bug_reports")
    os.makedirs(bug_dir, exist_ok=True)
    label = patterns[0].source_defensive_op or args.defensive_op or "pattern"
    suffix = "_all" if args.all_patterns else ""
    bug_path = os.path.join(bug_dir, f"{label}{suffix}{model_suffix}_bugs.json")
    
    # Create or load existing bug reports
    if os.path.exists(bug_path):
        with open(bug_path, "r") as f:
            try:
                existing_bug_data = json.load(f)
                bug_items = existing_bug_data.get("items", [])
                print(f"[info] Loaded {len(bug_items)} existing bugs from {bug_path}")
            except:
                bug_items = []
    else:
        bug_items = []
    
    use_summary = args.weggli_from_summary
    if args.all_patterns and args.weggli_from_summary:
        print("[info] --all-patterns uses per-pattern query selection from summary CSV")

    for pattern_idx, pattern in enumerate(patterns):
        print(f"\n[{pattern_idx+1}/{len(patterns)}] Processing pattern: {pattern.name}")
        
        # Build weggli queries from summary CSV or LLM translation
        if use_summary:
            summary_file = str(rt.repo_path("output", "pattern_stats", "templates", "defensive_op_template_summary.csv"))
            if not os.path.exists(summary_file):
                summary_file = str(rt.repo_path("output", "pattern_stats", "templates", "secop_template_summary.csv"))
            summary_defensive_op = pattern.source_defensive_op or args.defensive_op
            key_calls = _load_summary_key_calls(summary_file, summary_defensive_op)
            if not key_calls:
                key_calls = _extract_key_calls_from_behaviors(pattern.security_sensitive_behaviors)
            if not key_calls:
                print(f"[warn] summary key_calls empty for defensive_op={summary_defensive_op}; falling back to LLM query translation")
                queries_meta = auditor.generate_weggli_queries(pattern, llm_model=args.llm_model, dry_run=args.dry_run)
            else:
                queries_meta = {
                    "key_calls": key_calls,
                    "queries": _build_queries_from_key_calls(key_calls),
                    "security_sensitive_behaviors": pattern.security_sensitive_behaviors,
                    "reference_func": pattern.source_func,
                    "reference_defensive_op": pattern.source_defensive_op,
                }
        else:
            queries_meta = auditor.generate_weggli_queries(pattern, llm_model=args.llm_model, dry_run=args.dry_run)
        
        queries_meta["pattern_name"] = pattern.name
        queries_meta["pattern_index"] = pattern_idx
        queries_meta = _select_single_query(queries_meta)

        out_dir = os.path.join(auditor.cfg["security_sensitive_data_path"], args.repo, "weggli_queries")
        os.makedirs(out_dir, exist_ok=True)
        label = pattern.source_defensive_op or args.defensive_op or "pattern"
        if args.all_patterns:
            weggli_path = os.path.join(out_dir, f"{label}_p{pattern_idx}{model_suffix}.json")
        else:
            weggli_path = os.path.join(out_dir, f"{label}{model_suffix}.json")
        with open(weggli_path, "w") as f:
            json.dump(queries_meta, f, indent=2)
        print(f"Saved weggli queries to {weggli_path}")

        if args.require_query_match and not queries_meta.get("query_match"):
            print(f"[warn] Skipping pattern {pattern.name}: no query match")
            summary_rows.append({
                "pattern_index": pattern_idx,
                "pattern_name": pattern.name,
                "pattern_source_func": pattern.source_func,
                "candidates": 0,
                "consistent_true": 0,
                "consistent_false": 0,
                "consistent_none": 0,
                "needs_more_context": 0,
            })
            continue

        if args.weggli_only:
            continue
        
        pattern_limit = limit_per_pattern if args.all_patterns else limit
        candidates = auditor.locate_candidates(
            pattern,
            llm_model=args.llm_model,
            dry_run=args.dry_run,
            limit=pattern_limit,
            queries_meta=queries_meta,
            exclude_funcs=exclude_funcs or None,
            exclude_contains=None,
            exclude_path_contains=None,
            exclude_path_regex=None,
        )
        located_candidate_count = len(candidates)
        located_candidates = [
            {
                "func_name": cand.get("func_name"),
                "path": cand.get("path"),
            }
            for cand in candidates
            if cand.get("func_name")
        ]
        if include_funcs:
            candidates = [cand for cand in candidates if cand.get("func_name") in include_funcs]
        if args.all_patterns and candidates:
            filtered = []
            for cand in candidates:
                fn = cand.get("func_name")
                path = cand.get("path")
                key = (fn, path)
                if not fn or key in seen_candidate_keys:
                    continue
                seen_candidate_keys.add(key)
                filtered.append(cand)
            candidates = filtered
        outputs = auditor.audit(
            pattern,
            candidates,
            llm_model=args.llm_model,
            dry_run=args.dry_run,
            timeout=args.llm_timeout,
            workers=args.workers,
        )

        token_prompt = 0
        token_response = 0
        token_total = 0
        for out in outputs:
            if not out:
                continue
            token_prompt += (out.get("prompt_tokens") or 0) + (out.get("followup_prompt_tokens") or 0)
            token_response += (out.get("response_tokens") or 0) + (out.get("followup_response_tokens") or 0)
            token_total += (out.get("total_tokens") or 0) + (out.get("followup_total_tokens") or 0)
        
        all_audit_outputs.append({
            "pattern": pattern.__dict__,
            "pattern_index": pattern_idx,
            "located_comparable_functions": located_candidate_count,
            "located_candidates": located_candidates,
            "candidate_functions_file": args.candidate_functions_file or "",
            "candidates": candidates,
            "audit": outputs,
            "token_stats": {
                "prompt_tokens": token_prompt,
                "response_tokens": token_response,
                "total_tokens": token_total,
            },
        })
        
        # Collect bug reports and statistics
        consistent_true = 0
        consistent_false = 0
        consistent_none = 0
        needs_more_context = 0
        
        for cand, out in zip(candidates, outputs):
            parsed = out.get("parsed") or {}
            verdict = (parsed.get("verdict") or "").lower()
            
            if verdict == "consistent":
                consistent_true += 1
            elif verdict == "inconsistent":
                consistent_false += 1
                # Add to bug reports
                bug_key = (cand.get("func_name"), cand.get("path"))
                if bug_key in seen_bug_keys:
                    continue
                seen_bug_keys.add(bug_key)
                bug_items.append({
                    "pattern_index": pattern_idx,
                    "pattern_name": pattern.name,
                    "pattern_source_func": pattern.source_func,
                    "pattern_security_sensitive_behaviors": pattern.security_sensitive_behaviors,
                    "pattern_defensive_behaviors": pattern.defensive_behaviors,
                    "weggli_query": queries_meta.get("query") or (queries_meta["queries"][0] if queries_meta.get("queries") else None),
                    "buggy_function": cand.get("func_name"),
                    "buggy_function_path": cand.get("path"),
                    "missing_defenses": parsed.get("missing_defenses"),
                    "bug_explanation": parsed.get("bug_explanation"),
                })
            elif verdict == "uncertain":
                consistent_none += 1
            
            if parsed.get("needs_more_context"):
                needs_more_context += 1
        
        summary_rows.append({
            "pattern_index": pattern_idx,
            "pattern_name": pattern.name,
            "pattern_source_func": pattern.source_func,
            "candidates": len(candidates),
            "consistent_true": consistent_true,
            "consistent_false": consistent_false,
            "consistent_none": consistent_none,
            "needs_more_context": needs_more_context,
            "prompt_tokens": token_prompt,
            "response_tokens": token_response,
            "total_tokens": token_total,
        })
        
        print(f"  Candidates: {len(candidates)}, Bugs: {consistent_false}, Consistent: {consistent_true}, Uncertain: {consistent_none}")
        
        # Real-time save bug reports after each pattern
        if consistent_false > 0 or pattern_idx == 0:  # Always save after first pattern or when bugs found
            with open(bug_path, "w") as f:
                json.dump({
                    "defensive_op": patterns[0].source_defensive_op or args.defensive_op,
                    "total_patterns_processed": pattern_idx + 1,
                    "total_patterns": len(patterns),
                    "total_bugs": len(bug_items),
                    "items": bug_items,
                }, f, indent=2)
            print(f"  → Saved {len(bug_items)} total bugs to {bug_path}")
        
        if not args.all_patterns:
            break
    
    if args.weggli_only:
        return
    
    # Save audit results
    out_path = args.output
    if not out_path:
        out_dir = os.path.join(auditor.cfg["security_sensitive_data_path"], args.repo, "audit")
        os.makedirs(out_dir, exist_ok=True)
        label = patterns[0].source_defensive_op or args.defensive_op or "pattern"
        suffix = "_all" if args.all_patterns else ""
        out_path = os.path.join(out_dir, f"{label}{suffix}{model_suffix}.json")
    
    with open(out_path, "w") as f:
        if args.all_patterns:
            json.dump({"patterns": all_audit_outputs, "summary": summary_rows}, f, indent=2)
        else:
            json.dump(all_audit_outputs[0], f, indent=2)
    print(f"\nSaved audit results to {out_path}")
    
    # Final save of bug reports (already saved incrementally)
    if bug_items:
        with open(bug_path, "w") as f:
            json.dump({
                "defensive_op": patterns[0].source_defensive_op or args.defensive_op,
                "total_patterns_processed": len(patterns),
                "total_patterns": len(patterns),
                "total_bugs": len(bug_items),
                "items": bug_items,
            }, f, indent=2)
        print(f"✓ Final: Saved {len(bug_items)} bug reports to {bug_path}")
        
        # Also save summary CSV
        if args.all_patterns:
            summary_csv = os.path.join(bug_dir, f"{label}_all{model_suffix}_summary.csv")
            with open(summary_csv, "w") as f:
                f.write("pattern_index,pattern_name,pattern_source_func,candidates,consistent_true,consistent_false,consistent_none,needs_more_context\n")
                for r in summary_rows:
                    f.write(f"{r['pattern_index']},\"{r['pattern_name']}\",{r['pattern_source_func']},{r['candidates']},{r['consistent_true']},{r['consistent_false']},{r['consistent_none']},{r['needs_more_context']}\n")
                total = {
                    "candidates": sum(r["candidates"] for r in summary_rows),
                    "consistent_true": sum(r["consistent_true"] for r in summary_rows),
                    "consistent_false": sum(r["consistent_false"] for r in summary_rows),
                    "consistent_none": sum(r["consistent_none"] for r in summary_rows),
                    "needs_more_context": sum(r["needs_more_context"] for r in summary_rows),
                }
                f.write(f"TOTAL,,,{total['candidates']},{total['consistent_true']},{total['consistent_false']},{total['consistent_none']},{total['needs_more_context']}\n")
            print(f"Saved summary to {summary_csv}")


if __name__ == "__main__":
    main()
