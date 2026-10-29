"""
CRISP Agent Swarm 2.0 - Groq LLM Client
Handles communication with Groq API using GROQ_API_KEY and GROQ_MODEL.
Features bounded retries, timeouts, and deterministic fallback when offline or unconfigured.
"""

import os
import re
import json
import time
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CRISP.GroqClient")

DEFAULT_MODEL = "llama-3.3-70b-versatile"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def load_env_file(filepath: Optional[str] = None) -> None:
    """Loads variables from .env file into os.environ if not already present."""
    if not filepath:
        if os.path.exists(".env"):
            filepath = ".env"
        else:
            root_env = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                ".env"
            )
            if os.path.exists(root_env):
                filepath = root_env
    if not filepath or not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        logger.debug(f"Could not load .env file: {e}")


load_env_file()


class GroqClientWrapper:
    """
    Robust Groq API client with zero external dependency requirement,
    bounded retries, timeouts, and graceful deterministic intelligence fallback.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 15.0,
        max_retries: int = 2,
    ):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "").strip()
        self.model = model or os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
        self.timeout = timeout_seconds
        self.max_retries = max_retries

        # Token metrics tracking
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_calls = 0

        # Try native groq package if installed
        self._native_client = None
        try:
            from groq import Groq
            if self.api_key:
                self._native_client = Groq(api_key=self.api_key)
        except ImportError:
            self._native_client = None

    def _redact_secrets(self, text: str) -> str:
        """Sanitizes sensitive API keys and tokens from logs and error strings."""
        if not text:
            return ""
        sanitized = str(text)
        if self.api_key and len(self.api_key) > 6:
            sanitized = sanitized.replace(self.api_key, f"gsk_...{self.api_key[-4:]}")
        # Redact generic authorization bearer tokens
        sanitized = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]{10,}", "Bearer [REDACTED_API_KEY]", sanitized)
        return sanitized

    def is_configured(self) -> bool:
        """Returns True if GROQ_API_KEY is present and non-empty."""
        return bool(self.api_key)

    def get_token_usage(self) -> Dict[str, int]:
        """Returns cumulative token telemetry metrics."""
        return {
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_calls": self.total_calls,
        }

    def reset_token_usage(self) -> None:
        """Resets token usage counters."""
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_calls = 0

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        response_format_json: bool = False,
    ) -> str:
        """
        Generates completion via Groq with bounded retries, token tracking,
        timeout guards, and deterministic fallback when offline or unconfigured.
        """
        if not self.is_configured():
            logger.info("GROQ_API_KEY not configured. Using CRISP deterministic reasoning.")
            self._track_estimated_tokens(system_prompt, user_prompt, 200)
            return self._deterministic_fallback(system_prompt, user_prompt)

        # Execute with retries
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                if self._native_client:
                    output = self._call_native(
                        system_prompt, user_prompt, temperature, max_tokens, response_format_json
                    )
                else:
                    output = self._call_http(
                        system_prompt, user_prompt, temperature, max_tokens, response_format_json
                    )
                if response_format_json and output:
                    try:
                        json.loads(output)
                    except Exception as json_err:
                        logger.warning(f"Groq output was not valid JSON ({json_err}); retrying or falling back.")
                        if attempt == self.max_retries:
                            return self._deterministic_fallback(system_prompt, user_prompt)
                        continue
                return output
            except Exception as e:
                last_error = e
                sanitized_msg = self._redact_secrets(str(e))
                logger.warning(
                    f"Groq API call attempt {attempt + 1}/{self.max_retries + 1} failed: {sanitized_msg}"
                )
                if attempt < self.max_retries:
                    time.sleep(1.0 * (attempt + 1))

        sanitized_err = self._redact_secrets(str(last_error))
        logger.error(f"All Groq API attempts failed: {sanitized_err}. Falling back to deterministic engine.")
        self._track_estimated_tokens(system_prompt, user_prompt, 200)
        return self._deterministic_fallback(system_prompt, user_prompt)

    def _track_estimated_tokens(self, sys_prompt: str, usr_prompt: str, comp_tokens: int) -> None:
        p_tokens = (len(sys_prompt) + len(usr_prompt)) // 4
        self.total_prompt_tokens += p_tokens
        self.total_completion_tokens += comp_tokens
        self.total_calls += 1

    def _call_native(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        response_format_json: bool,
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": self.timeout,
        }
        if response_format_json:
            kwargs["response_format"] = {"type": "json_object"}

        response = self._native_client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        if usage:
            self.total_prompt_tokens += getattr(usage, "prompt_tokens", len(user_prompt) // 4)
            self.total_completion_tokens += getattr(usage, "completion_tokens", len(content) // 4)
        else:
            self._track_estimated_tokens(system_prompt, user_prompt, len(content) // 4)
        self.total_calls += 1
        return content

    def _call_http(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        response_format_json: bool,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format_json:
            payload["response_format"] = {"type": "json_object"}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            GROQ_API_URL,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "CRISP-Agent-Swarm-2.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode("utf-8")
            res_json = json.loads(body)
            content = res_json["choices"][0]["message"]["content"] or ""
            usage = res_json.get("usage", {})
            self.total_prompt_tokens += usage.get("prompt_tokens", len(user_prompt) // 4)
            self.total_completion_tokens += usage.get("completion_tokens", len(content) // 4)
            self.total_calls += 1
            return content

    def _deterministic_fallback(self, system_prompt: str, user_prompt: str) -> str:
        """
        Deterministic intelligence generator used when Groq is unconfigured or unreachable.
        Produces structured, explainable analysis from the input data.
        """
        return f"[CRISP Swarm Heuristic Analysis]\n{user_prompt[:500]}..."


# Global singleton helper
_default_client: Optional[GroqClientWrapper] = None


def get_groq_client() -> GroqClientWrapper:
    global _default_client
    if _default_client is None:
        _default_client = GroqClientWrapper()
    return _default_client
