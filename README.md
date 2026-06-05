# 資安新聞威脅雷達 (Security News Threat Radar)

An hourly cybersecurity news crawler with local LLM threat analysis and a GitHub dependency scanner, served through a Gradio dashboard.

## Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) running locally at `http://localhost:11434`
- A pulled model — by default `llama3.2`:
  ```
  ollama pull llama3.2
  ```

## Installation

```
pip install -r requirements.txt
```

## Run

```
python main.py
```

On startup the app will:
1. Initialize a local SQLite DB (`threat_radar.db`)
2. Run an initial crawl (RSS feeds + NVD CVEs) and analyze new items with Ollama
3. Schedule the same job to repeat every 60 minutes
4. Launch the dashboard at <http://localhost:7860>

## Tabs

- **威脅雷達** — recent threats as color-coded cards, filterable by threat level
- **GitHub 掃描** — paste a public GitHub repo URL, the scanner parses its `requirements.txt` / `package.json` and matches against affected products from the news DB
- **掃描歷史** — past GitHub scans with expandable hit details
- **模型比較 / 匯出** — local vs cloud threat-level comparison, plus CSV / JSONL / comparison-CSV exports to `outputs/`
- **系統狀態** — counts per threat level, Ollama health, cloud-model status and current analysis mode

## Choosing the analysis model (local vs online API)

The model that performs the analysis is fully swappable via two environment variables — no code edits needed.

**`PRIMARY_PROVIDER`** picks the authoritative model (it fills the dashboard and drives retries):

- `local` (default) — the Ollama model in `OLLAMA_MODEL`, fully offline.
- `cloud` — the online API configured in the `CLOUD_LLM_*` block.

The cloud adapter is **vendor-neutral**: it speaks the OpenAI-compatible `/chat/completions` schema, so any compatible endpoint works. Set `CLOUD_LLM_BASE_URL`, `CLOUD_LLM_MODEL`, `CLOUD_LLM_API_KEY`. Examples (use the provider's current model id):

| Provider | `CLOUD_LLM_BASE_URL` | example `CLOUD_LLM_MODEL` |
|----------|----------------------|---------------------------|
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Qwen (DashScope) | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Groq / Together / OpenRouter / local vLLM | (their base URL) | (their model id) |

So to run everything on, say, **DeepSeek**: set `PRIMARY_PROVIDER=cloud`, `CLOUD_LLM_BASE_URL=https://api.deepseek.com/v1`, `CLOUD_LLM_MODEL=deepseek-chat`, `CLOUD_LLM_API_KEY=...`.

**`ANALYSIS_MODE`** decides whether a *second* model also runs (for comparison):

- `single` (default) — only the primary model.
- `compare` — primary + the other model on every item.
- `hybrid` — primary on every item; the other only re-checks HIGH/CRITICAL items.

Every model's full output is stored per-item in the `news_analyses` table, so the two never overwrite each other; the `news` table keeps the primary model's result as the dashboard's default view. **API keys are read from the environment only — never commit them.**

## Configuration

Runtime config is read from environment variables (see `.env.example`); `config.py` holds the defaults.

| 設定 | 預設 | 說明 |
|------|------|------|
| `RSS_FEEDS` | 5 個來源 | 要爬的 RSS feed 清單 |
| `OLLAMA_MODEL` | `llama3.2` | 本地分析用的 Ollama 模型 |
| `OLLAMA_TIMEOUT` | 120 秒 | 單次 LLM call 的 timeout |
| `PRIMARY_PROVIDER` | `local` | 主要分析模型：`local`（Ollama）或 `cloud`（線上 API） |
| `ANALYSIS_MODE` | `single` | `single` / `compare` / `hybrid`（是否同時跑第二個模型） |
| `CLOUD_LLM_BASE_URL` | OpenAI v1 | 雲端 LLM 的 OpenAI 相容端點（DeepSeek、Qwen…） |
| `CLOUD_LLM_MODEL` | （空） | 雲端模型名稱；與 API key 都設定後才啟用 |
| `CLOUD_LLM_API_KEY` | （空） | 由環境變數提供，切勿 commit |
| `NVD_MAX_PAGES` | 5 | 每次 NVD 爬取最多翻幾頁（每頁 20 筆） |
| `GITHUB_TOKEN` / `NVD_API_KEY` | （空） | 設定後可提高對應 API 的 rate limit |
| `CRAWL_INTERVAL_MINUTES` | 60 | scheduler 觸發間隔 |
| `MAX_ANALYSIS_RETRIES` | 3 | Ollama 短暫故障時，每筆新聞最多重試幾次才放棄 |
| `LLM_CONCURRENCY` | 3 | 同時跑幾個 LLM 分析 worker（Ollama 開 `OLLAMA_NUM_PARALLEL` 才有完整效益） |
| `DB_PATH` | `threat_radar.db` | SQLite 檔案位置（WAL 模式） |

## Evaluation, prioritization & briefing

**Model benchmark** (`eval/benchmark.py`) — scores each provider (local Ollama and
cloud DeepSeek/Qwen/OpenAI) on the hand-labeled gold set in `eval/dataset.jsonl`,
through the same provider layer the app uses. Metrics: per-class F1, macro-F1,
confusion matrix, Cohen's kappa, CVE-F1, product recall, latency. Outputs a
`benchmark_*.csv` and a self-contained `benchmark_*.html` (inline SVG charts) to
`eval/results/`.

```
python eval/benchmark.py            # local; add CLOUD_LLM_* to include a cloud model
```

**Priority enrichment** (`enrichment/`) — for each analyzed item, looks up whether
its CVEs are on the CISA KEV catalog and their EPSS exploit-probabilities, then
combines `threat_level + CVSS + EPSS + KEV` into a 0–100 composite priority score
(`enrichment/priority.py`). Runs automatically after each crawl; the radar can be
sorted by priority and KEV-flagged items are surfaced.

**Threat briefing** (`reporting/briefing.py`) — one-click self-contained HTML
briefing (KPIs, threat-level + priority distributions, highest-priority items,
KEV hits, top products/CVEs) written to `outputs/`. Generate it from the
"模型比較 / 匯出" dashboard tab or:

```
python -m reporting.briefing
```

All charts are zero-dependency inline SVG (`reporting/charts_svg.py`) — reports
open in any browser with no extra packages.

## Development

架構與設計決策詳見 [CLAUDE.md](CLAUDE.md)。團隊分工請看 [TASKS.md](TASKS.md)。
