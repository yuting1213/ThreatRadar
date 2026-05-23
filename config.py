# RSS feeds to crawl
RSS_FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "iThome", "url": "https://www.ithome.com.tw/rss"},
]

# NVD API - no key needed, but rate limited to 5 requests/30s
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 20

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2"  # or qwen2.5, mistral, etc.
OLLAMA_TIMEOUT = 120

# Max LLM analysis attempts per news item before giving up.
# At 60 min/cycle, an item with transient Ollama failures retries
# for up to MAX_ANALYSIS_RETRIES hours before being marked failed.
MAX_ANALYSIS_RETRIES = 3

# How many news items to analyze concurrently. Ollama serializes inference
# per-model on a single device, but parallelism still wins on HTTP round-trip
# and JSON parsing overhead. Bump higher if OLLAMA_NUM_PARALLEL > 1.
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
