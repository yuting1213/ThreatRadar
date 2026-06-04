import os

# RSS feeds to crawl
RSS_FEEDS = [
    {"name": "CISA Alerts",       "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
    {"name": "BleepingComputer",   "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News",    "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security",  "url": "https://krebsonsecurity.com/feed/"},
    {"name": "iThome",             "url": "https://www.ithome.com.tw/rss"},
]

# NVD API - no key needed, but rate limited to 5 requests/30s (50/30s with a key)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 20
# Stop after this many pages so a busy CVE day doesn't make a demo crawl run forever.
NVD_MAX_PAGES = int(os.environ.get("NVD_MAX_PAGES", "5"))
# Optional NVD API key - raises the unauthenticated rate limit when present.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

# Optional GitHub token - raises the unauthenticated 60 req/hr contents-API limit.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

# -- Local LLM (Ollama) ---------------------------------------------------------
# Override via env var so Docker can point to the ollama service.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "llama3.2")
OLLAMA_TIMEOUT  = 120

# Stable identifier for the local provider's results in news_analyses.
LOCAL_PROVIDER = "ollama"

# -- Cloud LLM (second provider, optional) --------------------------------------
# Kept vendor-neutral: cloud_provider.py speaks the OpenAI-compatible
# /chat/completions schema, which OpenAI, Together, Groq, OpenRouter, vLLM, etc.
# all expose. Leave CLOUD_LLM_API_KEY empty to disable the cloud provider - the
# adapter then reports status="skipped" instead of erroring.
CLOUD_LLM_PROVIDER = os.environ.get("CLOUD_LLM_PROVIDER", "openai-compatible").strip()
CLOUD_LLM_MODEL    = os.environ.get("CLOUD_LLM_MODEL", "").strip()
CLOUD_LLM_API_KEY  = os.environ.get("CLOUD_LLM_API_KEY", "").strip()
CLOUD_LLM_BASE_URL = os.environ.get("CLOUD_LLM_BASE_URL", "https://api.openai.com/v1").strip()
CLOUD_LLM_TIMEOUT  = int(os.environ.get("CLOUD_LLM_TIMEOUT", "120"))

# Which model is AUTHORITATIVE — it fills the news table (the dashboard's primary
# view) and drives the retry budget. Switch the whole pipeline between the local
# model and an online API by changing this one value:
#   local  -> Ollama (config below)
#   cloud  -> the online API configured in the CLOUD_LLM_* block (DeepSeek, Qwen,
#            OpenAI, Groq, ... any OpenAI-compatible endpoint)
PRIMARY_PROVIDER = os.environ.get("PRIMARY_PROVIDER", "local").strip().lower()
if PRIMARY_PROVIDER in ("ollama", "local"):
    PRIMARY_PROVIDER = "local"
elif PRIMARY_PROVIDER in ("cloud", "api", "online"):
    PRIMARY_PROVIDER = "cloud"
else:
    PRIMARY_PROVIDER = "local"

# Analysis mode controls whether a SECOND model also runs (for comparison):
#   single   - only the primary model (default).
#   compare  - run primary + the other model on every item, store both.
#   hybrid   - primary on every item; the other only re-checks HIGH/CRITICAL items.
# "local_only" is accepted as a legacy alias for "single".
ANALYSIS_MODE = os.environ.get("ANALYSIS_MODE", "single").strip().lower()
if ANALYSIS_MODE in ("local_only", "primary_only", "only"):
    ANALYSIS_MODE = "single"

# Bump when ANALYSIS_PROMPT changes so news_analyses rows stay comparable across versions.
PROMPT_VERSION = os.environ.get("PROMPT_VERSION", "v1").strip()

# Max LLM analysis attempts per news item before giving up.
# At 60 min/cycle, an item with transient Ollama failures retries for up to
# MAX_ANALYSIS_RETRIES hours before being marked failed.
MAX_ANALYSIS_RETRIES = 3

# How many news items to analyze concurrently. Ollama serializes inference per-model
# on a single device, but parallelism still wins on HTTP round-trip and JSON parsing.
LLM_CONCURRENCY = 3

# Crawler schedule: every 60 minutes
CRAWL_INTERVAL_MINUTES = 60

# SQLite database path
DB_PATH = "threat_radar.db"

# Where exported CSV/JSONL reports are written (git-ignored; created on demand).
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "outputs")

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


def cloud_enabled() -> bool:
    """True when the cloud provider has the minimum config to run."""
    return bool(CLOUD_LLM_API_KEY and CLOUD_LLM_MODEL)


def primary_provider_kind() -> str:
    """Provider kind (for make_provider) of the authoritative model."""
    return "cloud" if PRIMARY_PROVIDER == "cloud" else LOCAL_PROVIDER


def secondary_provider_kind() -> str:
    """The other provider kind — runs only in compare/hybrid mode."""
    return LOCAL_PROVIDER if PRIMARY_PROVIDER == "cloud" else "cloud"


def primary_label() -> tuple[str, str]:
    """(provider_name, model) of the authoritative model, for UI display."""
    if PRIMARY_PROVIDER == "cloud":
        return (CLOUD_LLM_PROVIDER or "cloud", CLOUD_LLM_MODEL or "unconfigured")
    return (LOCAL_PROVIDER, OLLAMA_MODEL)


def secondary_enabled() -> bool:
    """Whether the secondary provider can actually run given current config.

    The cloud side needs an API key + model; the local (Ollama) side is always
    considered available (its reachability is surfaced separately in the UI).
    """
    return cloud_enabled() if secondary_provider_kind() == "cloud" else True
