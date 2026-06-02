import os

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
