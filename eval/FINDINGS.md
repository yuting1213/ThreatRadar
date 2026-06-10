# Track A 評測結論：模型與 Prompt 策略選擇

> 資料來源：`eval/run_eval.py` 對 `eval/dataset.jsonl`（40 筆人工標註，38 題測試集 + 2 筆 few-shot 範例）的評測。
> 原始輸出：[`eval/results/eval_20260602_154004.md`](results/eval_20260602_154004.md)。
> 評測環境：本機 Ollama，`temperature=0.1`，`format=json`，固定 split seed=42。

## 完整結果

| Model | Prompt | n | Err | 等級 exact | 等級 ±1 | CVE P | CVE R | 產品召回 | s/item |
|-------|--------|---|-----|-----------|--------|-------|-------|---------|--------|
| `llama3.2:3b` | V0 zero-shot | 38 | 0 | 61% | 89% | 18% | 45% | 86% | 3.8s |
| `llama3.2:3b` | V1 few-shot  | 38 | 0 | 76% | 100% | 8% | 45% | 88% | 3.5s |
| `llama3.2:3b` | V2 two-stage | 38 | 0 | 61% | 100% | 11% | 45% | 91% | 5.7s |
| **`qwen2.5:7b`** | **V1 few-shot** | 38 | 0 | **92%** | **100%** | 16% | 47% | 88% | 4.4s |
| `qwen2.5:7b` | V0 zero-shot | 38 | 0 | 84% | 100% | 16% | 45% | 89% | 4.5s |
| `qwen2.5:7b` | V2 two-stage | 38 | 0 | 82% | 100% | 3% | 45% | 88% | 6.6s |
| `mistral:7b` | V0 zero-shot | 38 | 0 | 71% | 92% | 26% | 50% | 90% | 4.1s |
| `mistral:7b` | V1 few-shot  | 38 | 0 | 79% | 100% | 26% | 53% | 89% | 3.2s |
| `mistral:7b` | V2 two-stage | 38 | 0 | 76% | 95% | 21% | 47% | 90% | 6.0s |

指標說明：
- **等級 exact / ±1**：`threat_level` 完全命中 / 容許 1 級誤差的比例。±1 對本系統很關鍵——把 HIGH 判成 CRITICAL 不會漏掉真正的威脅。
- **CVE P/R**：抽取 CVE-ID 的 set precision / recall。
- **產品召回**：`affected_products` 的 token 級召回（GitHub Scanner 的命中關鍵）。
- **s/item**：每題平均秒數（含模型推論）。

## 三個主要結論

### 1. 模型選擇：`qwen2.5:7b` 是威脅分級的最佳選擇
- `qwen2.5:7b` 在威脅等級判斷上明顯領先：zero-shot 已達 84%，few-shot 達 **92%**，且 ±1 全部 100%。
- `llama3.2:3b`（原 `config.py` 預設）最弱，zero-shot 僅 61%——**這也是先前「everything is INFO」體感的根因之一**。
- `mistral:7b` 居中（71–79%），但在**實體抽取**上最強：CVE precision 26%、recall 53% 全場最高，產品召回也穩定 ~90%。中文語境分級略遜 qwen。

### 2. Prompt 策略：few-shot（V1）全面優於 zero-shot
- 三個模型加上 few-shot 範例後，等級 exact 全部上升（llama 61→76、qwen 84→92、mistral 71→79），且 ±1 幾乎都拉到 100%。
- **two-stage（V2）不值得**：準確率沒提升，速度卻慢 ~50%（6s vs 4s），qwen 的 CVE precision 還掉到 3%。把 threat_level 與實體拆成兩次 call 的「單一職責」假設在這個任務上不成立。

### 3. CVE 抽取是共同弱點
- 所有組合的 CVE precision 都偏低（3–26%），代表模型常**幻覺出資料中不存在的 CVE-ID**。
- 對照之下產品名稱召回都很高（86–91%），所以 GitHub Scanner 的 `affected_products` 介面品質是穩的。
- 建議：CVE-ID 不要完全信任 LLM，**改由 NVD crawler 帶入的權威 CVE 為主**，LLM 抽取的 CVE 僅作輔助（這同時是 B 軌 NVD CPE 正向查詢的切入點）。

## 對系統的具體建議

1. **預設模型 `qwen2.5:7b`**（`config.py` 的 `OLLAMA_MODEL` 已是此值）——分級準確率比舊的 `llama3.2:3b` 從 61% → 84%（zero-shot）。
2. **建議導入 few-shot**（尚未進 production）：評測顯示 V1 few-shot 把 qwen2.5:7b 從 84% 拉到 92%、±1 達 100%。可在 analyzer 的 `build_prompt()` / provider 呼叫前，前置 2–3 筆涵蓋 CRITICAL/LOW/INFO 的標註範例即可。代價是每次呼叫 token 變多、稍慢；若 pipeline 吞吐吃緊可調降範例數或維持 zero-shot。
3. **CVE 以 NVD 為準**：LLM 的 `cve_ids` 僅補充，避免幻覺 CVE 污染 Dashboard 與 Scanner（評測中 CVE precision 僅 3–26%，會幻覺不存在的 CVE-ID，佐證此點）。

## 重現方式

```bash
# 需先 ollama pull llama3.2:3b / qwen2.5:7b / mistral:7b
set OLLAMA_KEEP_ALIVE=0    # Windows；其他平台用 export
python eval/run_eval.py
```

調整 `eval/run_eval.py` 裡的 `MODELS` / `VARIANTS` 可跑子集；12GB GPU 可解除 `qwen2.5:14b` 註解做更大比較。

> 偏誤提醒：資料集多為知名事件（Log4Shell、Heartbleed…），可能落在模型訓練資料中而是「記得」而非「分析」。後續應從 `threat_radar.db` 撈實際爬到的新鮮新聞補進評測集，數字會更具代表性。
