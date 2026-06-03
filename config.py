import os


# Minimal .env loader (no external dependency). If a .env file sits next to this
# module, load its KEY=VALUE lines into the environment before reading config,
# so teammates can drop their API key / backend choice in .env instead of
# exporting env vars by hand. Real environment variables take precedence.
def _load_dotenv():
    path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_dotenv()

# RSS feeds to crawl
RSS_FEEDS = [
    {"name": "CISA Alerts",       "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
    {"name": "BleepingComputer",   "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",    "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security",  "url": "https://krebsonsecurity.com/feed/"},
    {"name": "iThome",             "url": "https://www.ithome.com.tw/rss"},
]

# NVD API - no key needed, but rate limited to 5 requests/30s
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 20

# Ollama -- override via env var so Docker can point to the ollama service
# Default model chosen from the Track A eval (eval/FINDINGS.md): qwen2.5:7b
# scored highest on zh-TW threat-level classification (84% exact / 100% ±1,
# vs 61% for llama3.2:3b). Must be pulled in Ollama before first run.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "qwen2.5:7b")
OLLAMA_TIMEOUT  = 120

# ---- LLM backend selection ----
# "ollama" (default, runs locally) or "openai" (any OpenAI-compatible chat API).
# Teammates without a local GPU set LLM_PROVIDER=openai and point the three
# OPENAI_* vars at a hosted service — OpenAI, Groq, OpenRouter, Together,
# DeepInfra, or even `ollama serve`'s own /v1 endpoint. The prompt, few-shot
# exemplars and the rest of the pipeline are identical for both backends.
LLM_PROVIDER    = os.environ.get("LLM_PROVIDER", "ollama").strip().lower()
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_API_KEY  = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL    = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Max LLM analysis attempts per news item before giving up.
MAX_ANALYSIS_RETRIES = 3

# How many news items to analyze concurrently.
LLM_CONCURRENCY = 3

# Crawler schedule: every 60 minutes
CRAWL_INTERVAL_MINUTES = 60

# SQLite database path
DB_PATH = "threat_radar.db"

# Threat levels
THREAT_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Threat level colors for Gradio
LEVEL_COLORS = {
    "CRITICAL": "#FF4444",
    "HIGH":     "#FF8800",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#44BB44",
    "INFO":     "#888888",
}
