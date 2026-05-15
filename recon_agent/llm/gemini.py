from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Pricing as of 2024 — Gemini 1.5 Flash
_INPUT_PRICE_PER_1K = 0.000075
_OUTPUT_PRICE_PER_1K = 0.0003


def _extract_json(text: str) -> dict[str, Any]:
    """Extract JSON from LLM response that may include markdown fences."""
    text = text.strip()

    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence_match:
        text = fence_match.group(1)

    return json.loads(text)


class GeminiClient:
    def __init__(self, api_key: str | None = None, model: str = "gemini-1.5-flash") -> None:
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self._api_key:
            raise ValueError(
                "GEMINI_API_KEY is not set. "
                "Export it or set it in ~/.recon-agent/.env"
            )
        self._model_name = model
        self._total_cost = 0.0
        self._client: Any = None
        self._model: Any = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            import google.generativeai as genai
            genai.configure(api_key=self._api_key)
            self._model = genai.GenerativeModel(self._model_name)
            self._initialized = True
        except ImportError:
            raise ImportError(
                "google-generativeai is not installed. "
                "Run: pip install google-generativeai"
            )

    async def generate_json(
        self,
        prompt: str,
        temperature: float = 0.2,
    ) -> tuple[dict[str, Any], float]:
        """Generate a JSON response. Returns (parsed_dict, cost_usd)."""
        self._ensure_initialized()

        start = time.monotonic()
        logger.debug("gemini.generate_start", model=self._model_name, prompt_len=len(prompt))

        try:
            import asyncio
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._model.generate_content(
                    prompt,
                    generation_config={"temperature": temperature},
                ),
            )
        except Exception as e:
            logger.error("gemini.api_error", error=str(e))
            raise

        elapsed = time.monotonic() - start

        text = response.text
        input_tokens = len(prompt) // 4
        output_tokens = len(text) // 4
        cost = (input_tokens / 1000 * _INPUT_PRICE_PER_1K) + (
            output_tokens / 1000 * _OUTPUT_PRICE_PER_1K
        )
        self._total_cost += cost

        logger.debug(
            "gemini.generate_done",
            elapsed_s=f"{elapsed:.2f}",
            cost_usd=f"{cost:.6f}",
            output_len=len(text),
        )

        try:
            result = _extract_json(text)
        except json.JSONDecodeError as e:
            logger.error("gemini.json_parse_error", error=str(e), response=text[:500])
            raise ValueError(f"LLM did not return valid JSON: {e}\n\nResponse: {text[:500]}")

        return result, cost

    @property
    def total_cost(self) -> float:
        return self._total_cost
