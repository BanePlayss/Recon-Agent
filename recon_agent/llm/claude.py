from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# claude-sonnet-4-6 pricing per million tokens
_INPUT_PRICE_PER_M = 3.0
_OUTPUT_PRICE_PER_M = 15.0
_CACHE_WRITE_PRICE_PER_M = 3.75
_CACHE_READ_PRICE_PER_M = 0.30

_MODEL = "claude-sonnet-4-6"

_DEEP_ANALYSIS_SYSTEM = """You are a senior penetration tester and bug bounty hunter with 10+ years of experience.

You are reviewing security findings from an automated recon agent. Your job is to:
1. Validate whether each finding is a genuine vulnerability or a false positive
2. Enrich confirmed findings with precise technical detail
3. Generate a clear, step-by-step proof-of-concept that a human can reproduce
4. Assign an accurate CVSS 3.1 base score and CWE identifier
5. Write actionable remediation guidance

Be precise and technical. Only use evidence actually present in the output — do not fabricate data.
Mark as false positive if the evidence is ambiguous, the finding is informational only,
or if it's a known scanner false-positive pattern (e.g. nuclei template matching a CDN response)."""


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence_match:
        text = fence_match.group(1)
    return json.loads(text)


class ClaudeClient:
    def __init__(self, api_key: str | None = None, model: str = _MODEL) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Export it or set it in ~/.recon-agent/.env"
            )
        self._model = model
        self._total_cost = 0.0
        self._client: Any = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._api_key)
            self._initialized = True
        except ImportError:
            raise ImportError("anthropic is not installed. Run: pip install anthropic")

    def _calc_cost(self, usage: Any) -> float:
        input_tokens = getattr(usage, "input_tokens", 0)
        output_tokens = getattr(usage, "output_tokens", 0)
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0)
        cache_read = getattr(usage, "cache_read_input_tokens", 0)

        cost = (
            (input_tokens / 1_000_000) * _INPUT_PRICE_PER_M
            + (output_tokens / 1_000_000) * _OUTPUT_PRICE_PER_M
            + (cache_creation / 1_000_000) * _CACHE_WRITE_PRICE_PER_M
            + (cache_read / 1_000_000) * _CACHE_READ_PRICE_PER_M
        )
        return cost

    async def deep_analyze(self, prompt: str) -> tuple[dict[str, Any], float]:
        """
        Analyze a finding with the premium Claude model.
        System prompt is cached — subsequent calls reuse the cache for the static instructions.
        """
        self._ensure_initialized()
        import asyncio

        start = time.monotonic()
        logger.debug("claude.deep_analyze_start", model=self._model)

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.messages.create(
                    model=self._model,
                    max_tokens=2048,
                    system=[
                        {
                            "type": "text",
                            "text": _DEEP_ANALYSIS_SYSTEM,
                            # Cache the system prompt — it's identical across all calls
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
        except Exception as e:
            logger.error("claude.api_error", error=str(e))
            raise

        elapsed = time.monotonic() - start
        cost = self._calc_cost(response.usage)
        self._total_cost += cost

        cache_read = getattr(response.usage, "cache_read_input_tokens", 0)
        logger.debug(
            "claude.deep_analyze_done",
            elapsed_s=f"{elapsed:.2f}",
            cost_usd=f"{cost:.6f}",
            cache_read_tokens=cache_read,
        )

        text = response.content[0].text
        try:
            result = _extract_json(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Claude did not return valid JSON: {e}\n\nResponse: {text[:500]}")

        return result, cost

    @property
    def total_cost(self) -> float:
        return self._total_cost
