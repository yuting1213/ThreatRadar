"""
Cloud LLM adapter — deliberately vendor-neutral.

It speaks the OpenAI-compatible POST {base_url}/chat/completions schema, which
OpenAI, Together, Groq, OpenRouter, Anyscale, vLLM and most hosted gateways all
expose. To target a specific vendor, set CLOUD_LLM_BASE_URL / CLOUD_LLM_MODEL /
CLOUD_LLM_API_KEY — no code change needed.

When the cloud provider isn't configured (no API key / model), analyze() short-
circuits to status="skipped" instead of erroring, so `compare` mode degrades
gracefully to local-only on machines without cloud credentials.
"""

import requests

from analyzer.providers import AnalysisProvider
import config


class CloudProvider(AnalysisProvider):
    def __init__(self):
        self.provider = config.CLOUD_LLM_PROVIDER or "cloud"
        self.model = config.CLOUD_LLM_MODEL or "unconfigured"

    def analyze(self, title: str, content: str) -> dict:
        # Guard before doing any work so an unconfigured cloud never errors.
        if not config.cloud_enabled():
            return self._base_result(
                "skipped",
                error="cloud LLM not configured (set CLOUD_LLM_API_KEY and CLOUD_LLM_MODEL)",
            )
        return super().analyze(title, content)

    def _call(self, prompt: str) -> str:
        resp = requests.post(
            f"{config.CLOUD_LLM_BASE_URL.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {config.CLOUD_LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": config.CLOUD_LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                # Ask for JSON object output where the provider supports it.
                "response_format": {"type": "json_object"},
            },
            timeout=config.CLOUD_LLM_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
