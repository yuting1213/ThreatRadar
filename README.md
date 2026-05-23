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
- **系統狀態** — counts per threat level + a refresh button

## Configuration

Edit `config.py` to tune:

| 設定 | 預設 | 說明 |
|------|------|------|
| `RSS_FEEDS` | 5 個來源 | 要爬的 RSS feed 清單 |
| `OLLAMA_MODEL` | `llama3.2` | 分析用的 Ollama 模型 |
| `OLLAMA_TIMEOUT` | 120 秒 | 單次 LLM call 的 timeout |
| `CRAWL_INTERVAL_MINUTES` | 60 | scheduler 觸發間隔 |
| `MAX_ANALYSIS_RETRIES` | 3 | Ollama 短暫故障時，每筆新聞最多重試幾次才放棄 |
| `LLM_CONCURRENCY` | 3 | 同時跑幾個 LLM 分析 worker（Ollama 開 `OLLAMA_NUM_PARALLEL` 才有完整效益） |
| `DB_PATH` | `threat_radar.db` | SQLite 檔案位置（WAL 模式） |

## Development

架構與設計決策詳見 [CLAUDE.md](CLAUDE.md)。團隊分工請看 [TASKS.md](TASKS.md)。
