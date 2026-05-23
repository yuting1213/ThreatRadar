# 團隊分工 (4 人)

四條軌道盡量讓檔案範圍互不重疊，方便平行開發。挑選原則：對 demo 加分 + 能獨立交付。

---

## A：LLM / 資料品質

**負責範圍**：`analyzer/`、`config.py`、新建 `eval/`

**任務**
- 建立評測集：人工標註 20 篇 CRITICAL/HIGH + 20 篇 LOW/INFO 新聞作為 ground truth
- 多模型比較：跑 `llama3.2`、`qwen2.5:7b`、`mistral`，量化 `threat_level` 分類準確率 + `affected_products` 召回率
- Prompt iteration：試 few-shot（範例放 prompt 裡）vs 現在的 zero-shot，看 `affected_products` 命名一致性能否改善
- 可選：把 `threat_level` 跟 `affected_products` 拆成兩次 LLM call（單一職責），驗證準確率

**Demo 角度**：表格 + 圖表展示「我們為什麼選 X 模型」（學術角度最強）

---

## B：GitHub Scanner 擴充

**負責範圍**：`github_scanner/`、可能新增 `database/db.py` 欄位

**任務**
- 補齊 `scanner.py` docstring 已寫但未實作的格式：`pom.xml`（Java）、`go.mod`（Go）、`Cargo.toml`（Rust）
- 加 Python 生態系常見的：`Pipfile.lock`、`poetry.lock`
- 版本比對：現在只比對名字，加上 version range 解析（如 `< 4.17.21`）才算 hit
- 可選：用 NVD CPE Dictionary API 做正向查詢 —— 給定套件名直接抓官方 CVE 列表，不依賴 LLM 從新聞抽取

**Demo 角度**：「支援 6 種語言的依賴掃描」聽起來就很強（功能廣度）

---

## C：Dashboard / UX

**負責範圍**：`dashboard/`、可能新增 `database/db.py` 查詢函式

**任務**
- 威脅雷達分頁加搜尋框 + CVE-ID 直接搜尋
- 多排序選項：按發布時間 / 威脅等級 / 來源
- 新分頁「掃描歷史」：使用現有但目前沒被讀取的 `github_scans` 表
- 單篇 re-analyze 按鈕：點一下對某條新聞重跑 LLM 分析（將 `analysis_done` 設回 0）
- 視覺優化：dark mode、行動裝置 responsive、CVSS 分數視覺化

**Demo 角度**：直接決定教授第一印象

---

## D：DevOps / 工程品質

**負責範圍**：根目錄、新增 `Dockerfile`、`tests/`、`.github/workflows/`

**任務**
- `Dockerfile` + `docker-compose.yml`：把 app 跟 Ollama 包成一鍵啟動
- `logging` module 取代所有 `print()`，加 rotating file handler
- `pytest` 測試套件：從純函式開始（`_find_dep_matches`、`mark_analysis_failed`、`_tokenize`），retry 邏輯的 smoke test 已在 commit history 裡可以參考改寫
- 可選：GitHub Actions 跑 lint + test on PR
- 可選：環境變數化 `config.py`，加 `.env.example`

**Demo 角度**：`docker compose up` 一鍵跑起來，工程品質直接加分

---

## 整合風險

| 風險 | 緩解 |
|------|------|
| A 改 prompt 會影響 B/C 看到的 `affected_products` 格式 | A 鎖定 prompt 介面後再讓 B/C 開發；或 A 提前產出 fixture data 給 B/C 用 |
| D 把 `print()` 換成 `logging` 會碰到所有檔案 | D 最後一週做這個 migration，前面先做 Docker + tests |
| 多人想動 `database/db.py` | 開發前先談好誰要加哪些欄位 / 查詢，集中在一個 PR 改 schema |

## 建議 Git workflow

- 每人開 feature branch：`a/eval`、`b/multi-format`、`c/ux-polish`、`d/devops`
- A 與 D 衝突機率最高（都會碰 config / 跨檔案），優先溝通
- C 與 B 之間獨立性最高，可以最後合併
