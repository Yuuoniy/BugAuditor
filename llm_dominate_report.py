import argparse
import json
import os
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from openai import OpenAI

from defensive_code_locate import DefensiveCodeLocator
from secop_domination import SecOpDominateAnalyzer
# local config loader to avoid circular imports
def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)


DEFAULT_MODEL = "gpt-4o-mini"
PROMPT_DIR = Path(__file__).parent / "prompts"
DEFAULT_PROMPT_FILE = PROMPT_DIR / "default_prompt.txt"
PROMPT_VERSION_FILES = {
    1: PROMPT_DIR / "full_prompt.txt",
    2: DEFAULT_PROMPT_FILE,
}
_PROMPT_CACHE: Dict[int, str] = {}

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def normalize_api_base(api_base: str) -> str:
    """Ensure OpenAI base URL ends with /v1."""
    base = (api_base or "https://api.openai.com").rstrip("/")
    if not base.endswith("/v1"):
        base = base + "/v1"
    return base


def build_var_statements(secop: str, repo: str, func_name: str, func_code: str, var_name: str):
    """Reuse VulnOpReasoner helpers to extract variable-related statements and dominators."""
    from vuln_op_reasoner import VulnOpReasoner  # local import to avoid circular dependency
    vr = VulnOpReasoner(secop, func_name, func_code, var_name, repo)
    if vr.check_if_var_is_arg():
        return [], []
    vr.extract_var_op()
    vr.extract_func_names()

    dom = SecOpDominateAnalyzer(secop, repo, func_name, func_code)
    dom.workflow()
    pre = dom.dominate_funcs or []
    post = getattr(dom, "post_dominate_funcs", []) or []
    return vr.data_dependent_funcs or [], list(set(pre + post))


def slice_code(func_code: str, statements: List[Dict[str, str]]) -> str:
    """Slice function code from first to last occurrence of provided statements.
    If none found, return whole function.
    """
    if not statements:
        return func_code

    spans = []
    for item in statements:
        stmt = item.get("stmt", "")
        if not stmt:
            continue
        idx = func_code.find(stmt)
        if idx == -1:
            continue
        spans.append((idx, idx + len(stmt)))

    if not spans:
        return func_code

    start = min(s for s, _ in spans)
    end = max(e for _, e in spans)
    return func_code[start:end]


def _load_prompt_template(version: int = 2) -> str:
    if version in _PROMPT_CACHE:
        return _PROMPT_CACHE[version]

    path = PROMPT_VERSION_FILES.get(version, DEFAULT_PROMPT_FILE)
    _PROMPT_CACHE[version] = path.read_text()
    return _PROMPT_CACHE[version]


def build_prompt(secop: str, func_name: str, var_name: str, code_slice: str,
                 var_statements: List[Dict[str, str]], function_code: str,
                 prompt_version: int = 2, var_origin: str = "unknown",
                 var_origin_reason: str = "") -> str:
    stmt_lines = "\n".join([f"- func: {it['func']} | stmt: {it['stmt']}" for it in var_statements])
    template = _load_prompt_template(prompt_version)
    return template.format_map({
        "secop": secop,
        "func_name": func_name,
        "var_name": var_name,
        "stmt_lines": stmt_lines,
        "code_slice": code_slice,
        "function_code": function_code or code_slice,
        "var_origin": var_origin or "unknown",
        "var_origin_reason": var_origin_reason or "",
    })


def call_openai(api_base: str, api_key: str, model: str, prompt: str, timeout: float = 300.0, max_retries: int = 3, skip_on_error: bool = True) -> Optional[Dict[str, Any]]:
    """Call OpenAI API with configurable timeout and retry logic for SSL/network errors.
    
    Args:
        api_base: API base URL
        api_key: API key
        model: Model name
        prompt: User prompt
        timeout: Connection and read timeout in seconds (default: 300s)
        max_retries: Maximum retry attempts for transient errors (default: 3)
        skip_on_error: If True, return None on failure; if False, raise exception (default: True)
    
    Returns:
        OpenAI API response, or None if skip_on_error=True and all retries fail
    
    Raises:
        Exception: If skip_on_error=False and all retries fail
    """
    import time
    import httpx
    from openai import APIConnectionError, APIError
    
    client = OpenAI(
        base_url=normalize_api_base(api_base), 
        api_key=api_key,
        timeout=timeout,
        max_retries=0,  # Disable built-in retries, we handle manually
    )
    
    last_error = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a concise security analyst."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
            )
            return resp
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadTimeout, APIConnectionError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                print(f"[warn] LLM API connection error (attempt {attempt+1}/{max_retries}): {type(e).__name__}")
                print(f"[warn] Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                print(f"[error] LLM API failed after {max_retries} attempts: {type(e).__name__}")
                if skip_on_error:
                    print(f"[error] Skipping this request and continuing...")
                    return None
                else:
                    raise
        except (APIError, Exception) as e:
            # Non-retryable errors (API errors, invalid response, etc.)
            print(f"[error] Non-retryable LLM error: {type(e).__name__}: {e}")
            if skip_on_error:
                print(f"[error] Skipping this request and continuing...")
                return None
            else:
                raise
    
    # Should not reach here, but just in case
    if skip_on_error:
        return None
    raise last_error if last_error else RuntimeError("LLM call failed")


def dedup_candidates(candidates: List[Dict[str, Any]]):
    """No-op: keep all candidates."""
    return candidates or []


def build_requests_from_llm_inputs(secop: str, llm_inputs: List[Dict[str, Any]]):
    """Prepare LLM request payloads from precomputed candidates (runner-produced)."""
    requests = []
    for cand in llm_inputs:
        var_statements = cand.get("var_statements", []) or []
        func_code = cand.get("function", "")
        code_slice = cand.get("code_slice") or slice_code(func_code, var_statements)
        var_seq = tuple(item.get("func", "") for item in var_statements)
        requests.append({
            "func_name": cand.get("func_name", ""),
            "var": cand.get("var", ""),
            "var_statements": var_statements,
            "code_slice": code_slice,
            "model": cand.get("model"),
            "function": func_code,
            "var_seq": var_seq,
            "var_origin": cand.get("var_origin", "unknown"),
            "var_origin_reason": cand.get("var_origin_reason", ""),
        })
    deduped = dedup_candidates(requests)
    logger.info(f"LLM requests planned: {len(deduped)} (dedup from {len(requests)})")
    return deduped


def execute_llm_requests(secop: str, prepared: List[Dict[str, Any]], api_base: str, api_key: str, model: str, dry_run: bool = False, workers: int = None, prompt_version: int = 2):
    """Run LLM requests with progress bar; if dry_run or missing key, skip remote call."""
    outputs = []
    if not prepared:
        return outputs

    if not api_key:
        logger.warning("api_key not provided; skipping LLM calls (dry-run)")
        dry_run = True

    norm_base = normalize_api_base(api_base)
    if workers is None:
        # DeepSeek endpoints are more likely to throttle/flake with concurrency;
        # prefer reliability over throughput by default.
        if (model or "").lower().startswith("deepseek"):
            workers = 1
        else:
            workers = min(4, max(1, len(prepared)))

    def _run_one(cand):
        effective_model = model or cand.get("model") or DEFAULT_MODEL
        prompt = build_prompt(
            secop,
            cand["func_name"],
            cand["var"],
            cand["code_slice"],
            cand["var_statements"],
            cand.get("function", ""),
            prompt_version,
            cand.get("var_origin", "unknown"),
            cand.get("var_origin_reason", ""),
        )

        if dry_run:
            return {
                "func_name": cand["func_name"],
                "var": cand["var"],
                "var_statements": cand["var_statements"],
                "code_slice": cand["code_slice"],
                "var_origin": cand.get("var_origin"),
                "var_origin_reason": cand.get("var_origin_reason"),
                "model": effective_model,
                "response": None,
                "prompt": prompt,
            }

        # try wrapper per task to avoid cross-thread sharing issues
        content = None
        wrapper_api_base = None
        wrapper_api_key = None
        wrapper_model = effective_model
        try:
            from scripts.utils.openai_client import OpenAIClient
            cfg_path = Path(__file__).parent / "scripts" / "utils" / "openai_config.yaml"
            client_wrapper = OpenAIClient(model=effective_model, config_path=str(cfg_path))
            wrapper_api_base = getattr(client_wrapper, "base_url", None)
            wrapper_api_key = getattr(client_wrapper, "api_key", None)
            wrapper_model = getattr(client_wrapper, "model", effective_model)
            content = client_wrapper.send_message(prompt)
        except Exception as e:
            logger.info(f"Wrapper failed for {cand['func_name']}, fallback: {e}")
            try:
                fb_base = wrapper_api_base or norm_base
                fb_key = wrapper_api_key or api_key
                resp = call_openai(fb_base, fb_key, wrapper_model, prompt)
                if resp is None:
                    raise RuntimeError("call_openai returned None")
                content = resp.choices[0].message.content
            except Exception as e2:
                logger.error(f"LLM request failed for {cand['func_name']}: {e2}")
                content = None

        return {
            "func_name": cand["func_name"],
            "var": cand["var"],
            "var_statements": cand["var_statements"],
            "code_slice": cand["code_slice"],
            "function": cand.get("function", ""),
            "var_origin": cand.get("var_origin"),
            "var_origin_reason": cand.get("var_origin_reason"),
            "model": effective_model,
            "response": content,
            "prompt": prompt,
        }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_run_one, cand) for cand in prepared]
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Stage-2 LLM", unit="req"):
            outputs.append(fut.result())

    # simple formatted stdout preview
    for out in outputs:
        snippet = (out.get("response") or "")
        if snippet:
            snippet = snippet.replace("\n", " ")[:160]
        logger.info(f"LLM result func={out['func_name']} model={out['model']} preview={snippet}")

    return outputs


def main():
    parser = argparse.ArgumentParser(description="Run dominate-analysis LLM summarization for a secop")
    parser.add_argument("secop", help="secop name")
    parser.add_argument("repo", nargs="?", default="linux", help="repo key in config.json (default: linux)")
    parser.add_argument("--api-base", required=False, help="override API base; else use config.json or env")
    parser.add_argument("--api-key", required=False, help="override API key; else use config.json or env")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model id (default: gpt-4.1)")
    parser.add_argument("--local-only", action="store_true", help="only use contexts with is_local_var true")
    parser.add_argument("--prompt-version", type=int, choices=[1, 2], default=2,
                        help="prompt style: 1=full function context, 2=sliced code with dominator hints (default)")
    parser.add_argument("--out", help="optional output json file to save LLM responses")
    args = parser.parse_args()

    secop = args.secop
    repo = args.repo

    config = load_config()
    vuln_data_path = config["vuln_data_path"]
    cfg_api_base = config.get("openai_api_base") or os.environ.get("OPENAI_API_BASE", "https://api.openai.com")
    cfg_api_key = config.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")

    api_base = normalize_api_base(args.api_base or cfg_api_base)
    api_key = args.api_key or cfg_api_key

    contexts_path = os.path.join(vuln_data_path, repo, "contexts", f"{secop}.json")
    if not os.path.exists(contexts_path):
        # try to generate via defensive locator
        locator = DefensiveCodeLocator(secop, repo)
        contexts_path = locator.pipeline()
    if not contexts_path or not os.path.exists(contexts_path):
        sys.exit(f"No contexts for secop={secop} repo={repo}")

    with open(contexts_path, "r") as f:
        contexts = json.load(f)

    outputs = []
    candidates = []
    for ctx in contexts:
        if args.local_only and not ctx.get("is_local_var"):
            continue
        var_name = ctx.get("var", "")
        func_name = ctx.get("func_name", "")
        func_code = ctx.get("function", "")

        var_statements, _dom_funcs = build_var_statements(secop, repo, func_name, func_code, var_name)
        code_slice = slice_code(func_code, var_statements)

        var_seq = tuple(item.get("func", "") for item in var_statements)
        candidates.append({
            "func_name": func_name,
            "var": var_name,
            "var_statements": var_statements,
            "code_slice": code_slice,
            "model": args.model,
            "function": func_code,
            "var_seq": var_seq,
            "var_origin": ctx.get("var_origin", "unknown"),
            "var_origin_reason": ctx.get("var_origin_reason", ""),
        })

    # No dedup: keep all candidates
    selected = candidates

    logger.info(f"LLM requests planned: {len(selected)} (dedup from {len(candidates)})")

    for cand in selected:
        prompt = build_prompt(
            secop,
            cand["func_name"],
            cand["var"],
            cand["code_slice"],
            cand["var_statements"],
            cand.get("function", ""),
            args.prompt_version,
            cand.get("var_origin", "unknown"),
            cand.get("var_origin_reason", ""),
        )

        if not api_key:
            logger.info("api_key not provided; printing prompt only")
            print("--- Prompt ---")
            print(prompt)
            continue

        try:
            resp = call_openai(api_base, api_key, args.model, prompt)
            content = resp.choices[0].message.content
        except Exception as e:
            logger.error(f"LLM request failed for {cand['func_name']}: {e}")
            content = None

        outputs.append({
            "func_name": cand["func_name"],
            "var": cand["var"],
            "var_statements": cand["var_statements"],
            "code_slice": cand["code_slice"],
            "model": args.model,
            "response": content,
        })

    if args.out and outputs:
        with open(args.out, "w") as f:
            json.dump(outputs, f, indent=2)
        logger.info(f"Saved LLM responses to {args.out}")


if __name__ == "__main__":
    main()
