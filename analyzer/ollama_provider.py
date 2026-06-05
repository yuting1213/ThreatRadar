"""Local Ollama adapter. POSTs to /api/chat with format=json so the response
is guaranteed-parseable JSON (no markdown stripping needed)."""

import requests

from analyzer.providers import AnalysisProvider
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, LOCAL_PROVIDER


class OllamaProvider(AnalysisProvider):
    def __init__(self, model: str | None = None, base_url: str | None = None,
                 timeout: int | None = None):
        # Args default to config but can be overridden (e.g. by the benchmark
        # harness to evaluate several local models in one run).
        self.provider = LOCAL_PROVIDER
        self.model = model or OLLAMA_MODEL
        self.base_url = base_url or OLLAMA_BASE_URL
        self.timeout = timeout or OLLAMA_TIMEOUT

    def _call(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",  # Ollama constrains output to valid JSON
                "options": {"num_predict": 300, "temperature": 0.1},
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
