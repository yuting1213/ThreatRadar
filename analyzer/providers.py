"""
Provider abstraction for LLM analysis.

A provider knows how to turn (title, content) into a normalized analysis dict.
The shared timing / parsing / normalization / error-handling lives in the base
class so every concrete provider (Ollama, cloud) returns the SAME shape:

    {
      "provider": str, "model": str, "prompt_version": str,
      "status": "ok" | "error" | "skipped",
      "threat_level": str | None,
      "cve_ids": list[str], "affected_products": list[str], "action_summary": str,
      "latency_ms": int | None, "error": str | None, "warnings": list[str],
    }

Concrete providers only implement `_call(prompt) -> str` (return the model's raw
text, expected to be JSON) and set `.provider` / `.model`.
"""

import abc
import json
import time

from analyzer.llm import build_prompt, normalize_analysis_result, PROMPT_VERSION


class AnalysisProvider(abc.ABC):
    provider: str = "unknown"
    model: str = "unknown"

    @abc.abstractmethod
    def _call(self, prompt: str) -> str:
        """Send the prompt to the model and return its raw text response (JSON)."""
        raise NotImplementedError

    def _base_result(self, status: str, **extra) -> dict:
        base = {
            "provider": self.provider,
            "model": self.model,
            "prompt_version": PROMPT_VERSION,
            "status": status,
            "threat_level": None,
            "cve_ids": [],
            "affected_products": [],
            "action_summary": "",
            "latency_ms": None,
            "error": None,
            "warnings": [],
        }
        base.update(extra)
        return base

    def analyze(self, title: str, content: str) -> dict:
        """Run the full prompt -> call -> parse -> normalize pipeline, timed."""
        prompt = build_prompt(title, content)
        start = time.monotonic()
        try:
            raw = self._call(prompt)
            latency = int((time.monotonic() - start) * 1000)
            parsed = json.loads(raw)
            norm = normalize_analysis_result(parsed)
            return self._base_result(
                "ok",
                threat_level=norm["threat_level"],
                cve_ids=norm["cve_ids"],
                affected_products=norm["affected_products"],
                action_summary=norm["action_summary"],
                latency_ms=latency,
                warnings=norm["warnings"],
            )
        except Exception as e:  # network error, bad JSON, etc.
            latency = int((time.monotonic() - start) * 1000)
            return self._base_result("error", latency_ms=latency, error=f"{type(e).__name__}: {e}")


def make_provider(kind: str) -> AnalysisProvider:
    """Factory. kind is config.LOCAL_PROVIDER ("ollama") or "cloud".

    Concrete classes are imported lazily so this module has no hard import of
    the adapters (and no import cycle through analyzer.llm).
    """
    from config import LOCAL_PROVIDER

    if kind == LOCAL_PROVIDER or kind == "ollama":
        from analyzer.ollama_provider import OllamaProvider
        return OllamaProvider()
    if kind == "cloud":
        from analyzer.cloud_provider import CloudProvider
        return CloudProvider()
    raise ValueError(f"unknown provider kind: {kind!r}")
