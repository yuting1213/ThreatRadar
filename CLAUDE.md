# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Run

```
pip install -r requirements.txt
python main.py
```

`main.py` is the only entry point. It blocks: init SQLite → one synchronous crawl+analyze pass → start APScheduler (`CRAWL_INTERVAL_MINUTES`, default 60) → launch Gradio on `0.0.0.0:7860`.

There is no unit-test suite, linter config, or build step in this repo — do not invent commands for them.

### Offline model/prompt evaluation (Track A)

```
python eval/run_eval.py
```

`eval/run_eval.py` is standalone (not wired into `main.py`). It scores every (model × prompt-variant) combination against the hand-labeled `eval/dataset.jsonl` and writes a markdown table to `eval/results/`. Variants: `V0` zero-shot (reuses the production `ANALYSIS_PROMPT`), `V1` few-shot, `V2` two-stage. It talks directly to Ollama, so the models in its `MODELS` list must be pulled. Edit `MODELS` / `VARIANTS` in the file to run a subset. The few-shot split is seed-fixed (`SPLIT_SEED`) so V1 never sees a test item's label.

### Report generation

```
python scripts/generate_report.py
```

Renders a Traditional-Chinese `.docx` progress report (with code-screenshot and architecture PNGs) into `scripts/report_outputs/`. Requires `python-docx` and `Pillow`, which are **not** in `requirements.txt` — install them separately. It embeds source as images by hardcoded line range (e.g. `dashboard/app.py:510-649`), so those ranges silently drift when the referenced files change.

## LLM backend: Ollama (default) or any OpenAI-compatible API

`analyzer/llm.py` routes every analysis through `_chat_json()`, which dispatches on `config.LLM_PROVIDER`:

- **`ollama`** (default) — POSTs to `{OLLAMA_BASE_URL}/api/chat` with `format:"json"`. Needs a running Ollama daemon and `config.OLLAMA_MODEL` (default `qwen2.5:7b`, chosen by the Track A eval) pulled, or items fail analysis. When debugging "everything is INFO / 分析失敗", check Ollama first.
- **`openai`** — POSTs to `{OPENAI_BASE_URL}/chat/completions` with `response_format: json_object` and a Bearer key. Works with OpenAI, Groq, OpenRouter, Together, or `ollama serve`'s own `/v1` endpoint. This is for teammates without a local GPU; set `LLM_PROVIDER=openai` + the three `OPENAI_*` vars.

Both backends receive the **same** few-shot messages and produce the same parsed dict, so the rest of the pipeline is backend-agnostic. `config.py` auto-loads a local `.env` (no dependency; real env vars win) — see `.env.example`. `.env` is gitignored. The offline eval (`eval/run_eval.py`) is still Ollama-only by design (it compares local models).

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

`pipeline.run_crawl_cycle()` is the **only** function that should run a full crawl+analyze pass. Both the APScheduler job in `main.py` and the "立即爬取" button in the dashboard call it. It holds a module-level `threading.Lock` acquired non-blocking, so overlapping triggers return `(False, "已在執行中")` instead of double-firing Ollama on the same rows. Don't reintroduce direct calls to `crawl_all_feeds() + fetch_recent_cves() + analyze_pending_news()` from elsewhere — you'll bypass the lock. `pipeline.reanalyze_one(news_id)` (the dashboard's per-item re-analyze button) shares **the same lock**, so a manual re-analyze and a scheduled crawl can't hit Ollama at once; it resets one row via `reset_analysis()` then runs `analyze_single` synchronously for an immediate result. After a full cycle, `run_crawl_cycle()` calls `record_crawl_run()` so `get_enhanced_stats()` reflects the real last-run time even when no new rows were inserted.

Key consequence: **`affected_products` is the join key** between the news pipeline and the GitHub scanner. The scanner tokenizes each affected_products entry on non-alphanumeric boundaries and requires the dep name (or its first hyphen component, when ≥4 chars) to appear as a whole token. The quality of GitHub scan results is therefore tied to how the LLM names products in `ANALYSIS_PROMPT` — changing that prompt's `affected_products` formatting will silently shift matching behavior. There's also a `SHORT_NAME_BLACKLIST` in `scanner.py` that drops 2–4 char generic names (`js`, `go`, `py`, …) from ever being a match key, since their token would hit too many products.

### Module responsibilities

- `config.py` — single source of truth for feeds, model name, schedule, DB path, threat levels, and UI colors. All other modules import from here; never hardcode these values elsewhere.
- `database/db.py` — only place that touches SQLite. `_connect()` is a per-call context manager (no shared connection, no pooling). `ORDER_BY_LEVEL` defines the canonical CRITICAL→INFO sort and is reused across queries.
- `crawler/rss.py`, `crawler/nvd.py` — both end at `insert_news()`; duplicate URLs are dropped by the UNIQUE constraint, not by app logic. NVD crawler does `time.sleep(1)` for the unauthenticated rate limit (5 req / 30s).
- `analyzer/llm.py` — pulls `WHERE analysis_done = 0`, calls Ollama with a Traditional Chinese prompt and `format: "json"` so the response is guaranteed-parseable JSON (no markdown stripping or regex extraction needed). Content is truncated to 800 chars before being sent to the model. Each call is **few-shot**: `_build_messages()` prepends the `FEWSHOT_EXAMPLES` (CRITICAL/LOW/INFO exemplars) as user/assistant turns before the real item — this is the V1 strategy the Track A eval picked (see `eval/FINDINGS.md`); keep exemplars out of `eval/dataset.jsonl` so the offline eval stays honest. `analyze_pending_news` runs `analyze_single` calls through a `ThreadPoolExecutor(max_workers=LLM_CONCURRENCY)` — each worker opens its own SQLite connection, and WAL keeps writes from blocking. On failure, calls `mark_analysis_failed()` rather than `update_analysis()` so the retry budget applies.
- `github_scanner/github.py` — fetches `requirements.txt` and `package.json` via the unauthenticated GitHub contents API (60 req/hr limit). Other dependency formats listed in its docstring (pom.xml, go.mod) are **not** actually implemented.
- `dashboard/app.py` — four Gradio tabs (威脅雷達 / GitHub 掃描 / 掃描歷史 / 系統狀態). The "立即爬取" button delegates to `pipeline.run_crawl_cycle()`; the per-item re-analyze control delegates to `pipeline.reanalyze_one()`; both surface the returned message. Renders external strings (RSS/LLM/repo URLs) into `gr.HTML`, so it routes them through `html.escape()` / `_safe_url()` — keep that escaping when adding fields.
- `crawler/rss.py` — fetches feed bytes via `requests` (15s timeout) before handing to `feedparser`, because `feedparser.parse(url)` has no timeout knob and would hang the entire scheduler tick if a feed stalls.

### Threat levels are a closed enum

`THREAT_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]` in `config.py` drives: LLM prompt instructions, DB sort order (`ORDER_BY_LEVEL`), dashboard filter dropdown, stats grouping, and `LEVEL_COLORS`. Adding or renaming a level requires touching all five and re-checking the LLM prompt's judgement criteria.

### Schema migration

Three tables: `news` (the pipeline row), `github_scans` (scanner history, read by the 掃描歷史 tab), and `crawl_runs` (one row per finished cycle, the source of truth for "last crawl time" in `get_enhanced_stats()` — with a `MAX(news.created_at)` fallback for DBs predating this table).

There is no migration framework. `init_db()` runs `CREATE TABLE IF NOT EXISTS` plus an idempotent `ALTER TABLE ... ADD COLUMN` block wrapped in `try/except sqlite3.OperationalError` (because SQLite has no `ADD COLUMN IF NOT EXISTS`). When adding a new column, extend the `SCHEMA` constant **and** append a matching `try/except` ALTER in `init_db()` so existing `threat_radar.db` files upgrade in place.

## Language / locale

The product is Traditional Chinese facing: LLM prompt, dashboard labels, error strings, and `action_summary` outputs are all zh-TW. Keep new user-visible strings in Traditional Chinese to match.
