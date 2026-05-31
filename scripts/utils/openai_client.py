#!/usr/bin/env python3
"""
OpenAI-compatible LLM client with YAML configuration support.
Adopted from SpecAuditor; placed under scripts/utils for reuse.
"""

import os
import sys
import json
import time
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
from openai import OpenAI


class OpenAIClient:
    def __init__(self, model: str = None, system_prompt: str = "", config_path: Optional[str] = None):
        # resolve config path
        if config_path is None:
            config_path = Path(__file__).parent / "openai_config.yaml"
        self.config = self._load_config(config_path)
        self.model = model or self.config.get("default_model", "gpt-4o-mini")
        self.system_prompt = system_prompt

        model_config, resolved_model = self._get_model_config(self.model)
        self.model = resolved_model
        self.api_key = model_config.get("api_key", "")
        self.base_url = model_config.get("base_url", "https://api.openai.com/v1")
        self.temperature = model_config.get("temperature", 0)
        self.max_tokens = model_config.get("max_tokens")
        self.max_retries = max(1, model_config.get("max_retries", 3))
        self.request_timeout = model_config.get("request_timeout", 60)

        if not self.api_key:
            raise ValueError("API key is required")

        # Disable built-in retries (we handle retries ourselves in send_message*)
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.request_timeout,
            max_retries=0,
        )

    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")

    def _get_model_config(self, model: str):
        """Return (model_config, resolved_model_name) with fallback to default_model."""
        models = self.config.get("models", {})
        if model in models:
            return models[model], model
        resolved = model
        # case-insensitive fallback for convenience
        for key in models:
            if key.lower() == resolved.lower():
                resolved = key
                break
        if resolved not in models:
            default_model = self.config.get("default_model")
            if default_model and default_model in models:
                return models[default_model], default_model
            raise ValueError(f"Model '{model}' not configured and no valid default found")
        return models[resolved], resolved


    def _remove_think_tags(self, content: str) -> str:
        import re
        cleaned = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        cleaned = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned)
        return cleaned.strip()

    def send_message(self, user_prompt: str, system_prompt: Optional[str] = None, temperature: Optional[float] = None) -> str:
        current_system_prompt = system_prompt if system_prompt is not None else self.system_prompt
        current_temperature = temperature if temperature is not None else self.temperature

        messages = []
        if current_system_prompt:
            messages.append({"role": "system", "content": current_system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=current_temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.request_timeout,
                )
                content = response.choices[0].message.content
                return self._remove_think_tags(content)
            except Exception as e:
                last_error = e
                wait_seconds = min(2 ** attempt, 10)
                if attempt < self.max_retries - 1:
                    print(f"API call error: {e}, retrying in {wait_seconds}s ({attempt + 1}/{self.max_retries})")
                    time.sleep(wait_seconds)
                else:
                    print(f"API call error: {e}")
        if last_error:
            raise last_error
        return "unknown"

    def send_message_with_tokens(self, user_prompt: str, system_prompt: Optional[str] = None, temperature: Optional[float] = None):
        current_system_prompt = system_prompt if system_prompt is not None else self.system_prompt
        current_temperature = temperature if temperature is not None else self.temperature

        messages = []
        if current_system_prompt:
            messages.append({"role": "system", "content": current_system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=current_temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.request_timeout,
                )
                content = response.choices[0].message.content
                usage = response.usage or {}
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)
                return self._remove_think_tags(content), input_tokens, output_tokens
            except Exception as e:
                last_error = e
                wait_seconds = min(2 ** attempt, 10)
                if attempt < self.max_retries - 1:
                    print(f"API call error: {e}, retrying in {wait_seconds}s ({attempt + 1}/{self.max_retries})")
                    time.sleep(wait_seconds)
                else:
                    print(f"API call error: {e}")
        if last_error:
            raise last_error
        return "unknown", 0, 0

    def get_config(self) -> Dict[str, Any]:
        cfg = {
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.system_prompt:
            cfg["system_prompt"] = (self.system_prompt[:100] + "...") if len(self.system_prompt) > 100 else self.system_prompt
        return cfg

    def print_config(self):
        cfg = self.get_config()
        print("OpenAI Client Configuration:")
        print("=" * 50)
        for k, v in cfg.items():
            print(f"  {k}: {v}")
        print("=" * 50)


if __name__ == "__main__":
    client = OpenAIClient()
    client.print_config()
    try:
        resp = client.send_message("ping")
        print("Response:", resp)
    except Exception as e:
        print("Error:", e)
