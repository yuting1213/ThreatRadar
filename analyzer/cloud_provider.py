"""
Cloud LLM adapter — deliberately vendor-neutral.

It speaks the OpenAI-compatible POST {base_url}/chat/completions schema, which
OpenAI, Together, Groq, OpenRouter, Anyscale, vLLM and most hosted gateways all
expose. To target a specific vendor, set CLOUD_LLM_BASE_URL / CLOUD_LLM_MODEL /
CLOUD_LLM_API_KEY — or pass them to the constructor (used by the benchmark to
evaluate several cloud models in one run).

When not configured (no API key / model), analyze() short-circuits to
status="skipped" instead of erroring, so compare/hybrid degrade gracefully.
"""

import requests

from analyzer.providers import AnalysisProvider
import config


class CloudProvider(AnalysisProvider):
    def __init__(self, model: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, provider_name: str | None = None,
                 timeout: int | None = None):
        self.provider = provider_name or config.CLOUD_LLM_PROVIDER or "cloud"
        self.model = model or config.CLOUD_LLM_MODEL or "unconfigured"
        self.base_url = base_url or config.CLOUD_LLM_BASE_URL
        self.api_key = api_key or config.CLOUD_LLM_API_KEY
        self.timeout = timeout or config.CLOUD_LLM_TIMEOUT

    def _configured(self) -> bool:
        return bool(self.api_key and self.model and self.model != "unconfigured")

    def analyze(self, title: str, content: str) -> dict:
        # Guard before doing any work so an unconfigured cloud never errors.
        if not self._configured():
            return self._base_result(
                "skipped",
                error="cloud LLM not configured (set CLOUD_LLM_API_KEY and CLOUD_LLM_MODEL)",
            )
        return super().analyze(title, content)

    def _call(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
