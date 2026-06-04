"""Local Ollama adapter. POSTs to /api/chat with format=json so the response
is guaranteed-parseable JSON (no markdown stripping needed)."""

import requests

from analyzer.providers import AnalysisProvider
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, LOCAL_PROVIDER


class OllamaProvider(AnalysisProvider):
    def __init__(self):
        self.provider = LOCAL_PROVIDER
        self.model = OLLAMA_MODEL

    def _call(self, prompt: str) -> str:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",  # Ollama constrains output to valid JSON
                "options": {"num_predict": 300, "temperature": 0.1},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
