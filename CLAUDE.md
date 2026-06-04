# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Run

```
pip install -r requirements.txt
python main.py
```

`main.py` is the only entry point. It blocks: init SQLite → one synchronous crawl+analyze pass → start APScheduler (`CRAWL_INTERVAL_MINUTES`, default 60) → launch Gradio on `0.0.0.0:7860`.

There is no test suite, linter config, or build step in this repo — do not invent commands for them.

## Hard runtime dependency: Ollama

The analyzer (`analyzer/llm.py`) POSTs to `http://localhost:11434/api/chat`. Without a running Ollama daemon and the model in `config.OLLAMA_MODEL` (default `llama3.2`) pulled, items will fail analysis. When debugging "everything is INFO / 分析失敗", check Ollama first.

Failures are retried up to `config.MAX_ANALYSIS_RETRIES` (default 3) before being permanently marked `analysis_done=1` with `action_summary="分析失敗"`. The retry counter lives in `news.analysis_retries`. Don't change `analyze_single` to mark failures done on the first try — that's what the retry budget is preventing.

## Architecture

The pipeline is a one-way fan-in to SQLite, then a one-way fan-out to the UI:

```
RSS feeds  ─┐
            ├──► insert_news() ──► news table ──► analyze_pending_news() ──► same row, updated
NVD API   ─┘   (URL UNIQUE de-dupes)              (LLM fills threat_level,
                                                   cve_ids, affected_products,
                                                   action_summary)
                                                          │
                       ┌──────────────────────────────────┤
                       ▼                                  ▼
            dashboard (reads news)         github_scanner (reads news.affected_products)
```

`pipeline.run_crawl_cycle()` is the **only** function that should run a full crawl+analyze pass. Both the APScheduler job in `main.py` and the "立即爬取" button in the dashboard call it. It holds a module-level `threading.Lock` acquired non-blocking, so overlapping triggers return `(False, "已在執行中")` instead of double-firing Ollama on the same rows. Don't reintroduce direct calls to `crawl_all_feeds() + fetch_recent_cves() + analyze_pending_news()` from elsewhere — you'll bypass the lock.

Key consequence: **`affected_products` is the join key** between the news pipeline and the GitHub scanner. The scanner tokenizes each affected_products entry on non-alphanumeric boundaries and requires the dep name (or its first hyphen component, when ≥4 chars) to appear as a whole token. The quality of GitHub scan results is therefore tied to how the LLM names products in `ANALYSIS_PROMPT` — changing that prompt's `affected_products` formatting will silently shift matching behavior. There's also a `SHORT_NAME_BLACKLIST` in `scanner.py` that drops 2–4 char generic names (`js`, `go`, `py`, …) from ever being a match key, since their token would hit too many products.

### Module responsibilities

- `config.py` — single source of truth for feeds, model name, schedule, DB path, threat levels, and UI colors. All other modules import from here; never hardcode these values elsewhere.
- `database/db.py` — only place that touches SQLite. `_connect()` is a per-call context manager (no shared connection, no pooling). `ORDER_BY_LEVEL` defines the canonical CRITICAL→INFO sort and is reused across queries.
- `crawler/rss.py`, `crawler/nvd.py` — both end at `insert_news()`; duplicate URLs are dropped by the UNIQUE constraint, not by app logic. NVD crawler does `time.sleep(1)` for the unauthenticated rate limit (5 req / 30s).
- `analyzer/llm.py` — owns the shared layer: the injection-hardened `ANALYSIS_PROMPT` / `build_prompt()` (RSS content is wrapped in an `<article>` block and treated as untrusted; literal delimiters are stripped from the input), `normalize_analysis_result()` (validates threat_level against the enum, regex-filters CVE IDs, dedupes products, caps the summary), and orchestration (`analyze_single` / `analyze_pending_news`). It pulls `WHERE analysis_done = 0` and runs through a `ThreadPoolExecutor(max_workers=LLM_CONCURRENCY)`; each worker opens its own SQLite connection and WAL + `busy_timeout` keep concurrent writes from failing. On primary-provider failure it calls `mark_analysis_failed()` so the retry budget applies.
- `analyzer/providers.py` + `analyzer/ollama_provider.py` + `analyzer/cloud_provider.py` — provider abstraction. The base class runs prompt→call→parse→normalize and returns a uniform dict (`provider/model/status/threat_level/.../latency_ms/error`); concrete adapters only implement `_call(prompt)`. `make_provider()` is the factory (lazy imports break the cycle with `llm.py`). **`config.PRIMARY_PROVIDER` (`local`/`cloud`) chooses the authoritative model** — it fills the `news` table and drives the retry budget; `analyze_single` resolves it via `config.primary_provider_kind()`, never hard-coding Ollama. The **cloud** provider (vendor-neutral, OpenAI-compatible — DeepSeek/Qwen/OpenAI/Groq via `CLOUD_LLM_BASE_URL`+`CLOUD_LLM_MODEL`) is unconfigured-safe (returns `status="skipped"`). `ANALYSIS_MODE` (`single`/`compare`/`hybrid`) controls whether the *other* provider also runs. Every provider result is appended to `news_analyses` so two models never overwrite each other.
- `exporter/report_exporter.py` — writes `threat_report_*.csv` / `.jsonl` and `model_comparison_*.csv` to `config.OUTPUT_DIR` (git-ignored). CSVs use `utf-8-sig` so Excel renders zh-TW.
- `github_scanner/github.py` — fetches `requirements.txt` and `package.json` via the GitHub contents API (60 req/hr, or 5000 with `GITHUB_TOKEN`). Other dependency formats (pom.xml, go.mod) are **not** implemented.
- `dashboard/app.py` — five Gradio tabs (威脅雷達 / GitHub 掃描 / 掃描歷史 / 模型比較·匯出 / 系統狀態). Cards show the primary provider/model and a ⚖ review flag when local and cloud disagree. The "立即爬取" button delegates to `pipeline.run_crawl_cycle()`.
- `crawler/rss.py` — fetches feed bytes via `requests` (15s timeout) before handing to `feedparser`, because `feedparser.parse(url)` has no timeout knob and would hang the entire scheduler tick if a feed stalls.

### Threat levels are a closed enum

`THREAT_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]` in `config.py` drives: LLM prompt instructions, DB sort order (`ORDER_BY_LEVEL`), dashboard filter dropdown, stats grouping, and `LEVEL_COLORS`. Adding or renaming a level requires touching all five and re-checking the LLM prompt's judgement criteria.

### Schema migration

There is no migration framework. `init_db()` runs `CREATE TABLE IF NOT EXISTS` plus an idempotent `ALTER TABLE ... ADD COLUMN` block wrapped in `try/except sqlite3.OperationalError` (because SQLite has no `ADD COLUMN IF NOT EXISTS`). When adding a new column, extend the `SCHEMA` constant **and** append a matching `try/except` ALTER in `init_db()` so existing `threat_radar.db` files upgrade in place. New *tables* (e.g. `news_analyses`) only need to be added to `SCHEMA` — `executescript` creates them via `CREATE TABLE IF NOT EXISTS`, no ALTER required.

### Two-layer analysis storage

The `news` table holds ONE "primary" result per item (the local model's) for the dashboard's default view. The `news_analyses` table holds the full per-(news, provider) history (threat_level, cve_ids, products, latency_ms, status, error, prompt_version). This is what makes two-model comparison possible — never go back to overwriting a single shared result per news row.

## Language / locale

The product is Traditional Chinese facing: LLM prompt, dashboard labels, error strings, and `action_summary` outputs are all zh-TW. Keep new user-visible strings in Traditional Chinese to match.
