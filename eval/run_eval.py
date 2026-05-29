"""
Track A evaluation: compare Ollama models AND prompt strategies on a
hand-labeled news set.

Run from repo root:
    python eval/run_eval.py

It evaluates every (model × prompt-variant) combination on a held-out
test split and writes a markdown report to eval/results/.

Prompt variants:
    V0  zero-shot   — the production ANALYSIS_PROMPT as-is (baseline)
    V1  few-shot    — prepends a few labeled examples as chat history
    V2  two-stage   — one call for threat_level, one for entities

Held-out split: a few items are reserved as few-shot exemplars (used only
by V1) and excluded from the test set, so V1 never sees a test item's
answer. All variants are scored on the same test split for fairness.

Before running:
  1. Edit eval/dataset.jsonl — add 30+ labeled items
     (mix of CRITICAL / HIGH / MEDIUM / LOW / INFO)
  2. Make sure Ollama is up and the models in MODELS are pulled.
  3. Recommended: OLLAMA_KEEP_ALIVE=0 and stop other Ollama clients so
     VRAM is yours and timing is clean.
"""

import json
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# Make repo root importable when running this file directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import OLLAMA_BASE_URL, OLLAMA_TIMEOUT
from analyzer.llm_analyzer import ANALYSIS_PROMPT


# Each model must be pulled in Ollama. On a 3060 12GB qwen2.5:14b also fits.
MODELS = [
    "llama3.2:3b",      # baseline — current default in config.py
    "qwen2.5:7b",       # strongest on Chinese in this size class
    "mistral:7b",       # diversity check (Western-corpus heavy)
    # "qwen2.5:14b",    # uncomment for the bigger comparison
]

# Which prompt strategies to evaluate. Comment out to run a subset.
VARIANTS = ["V0", "V1", "V2"]

# How many items to reserve as few-shot exemplars for V1 (excluded from test).
N_FEWSHOT = 2
SPLIT_SEED = 42

DATASET = Path(__file__).parent / "dataset.jsonl"
RESULTS_DIR = Path(__file__).parent / "results"
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ---------- IO ----------

def load_dataset() -> list[dict]:
    """Read JSONL, skipping blank lines and lines starting with #."""
    items = []
    with open(DATASET, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  [!] dataset line {n} not valid JSON: {e}")
    return items


def split_dataset(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Reserve N_FEWSHOT items as few-shot exemplars (for V1), rest are the test
    set. Fixed seed keeps the split reproducible across runs and models.
    """
    shuffled = items[:]
    random.Random(SPLIT_SEED).shuffle(shuffled)
    fewshot = shuffled[:N_FEWSHOT]
    test = shuffled[N_FEWSHOT:] or shuffled  # fall back if dataset is tiny
    return fewshot, test


# ---------- Ollama calls ----------

def _chat(model: str, messages: list[dict], num_predict: int = 300) -> dict:
    """One chat call with format=json. Returns parsed dict, raises on failure."""
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json={
            "model": model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {"num_predict": num_predict, "temperature": 0.1},
        },
        timeout=OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    return json.loads(resp.json()["message"]["content"])


# Two-stage (V2) prompts, derived from the production ANALYSIS_PROMPT.
THREAT_ONLY_PROMPT = """你是一位資安威脅情報分析師。請判斷以下資安新聞的威脅等級。

標題：{title}
內容：{content}

請只回傳以下 JSON：
{{"threat_level": "CRITICAL 或 HIGH 或 MEDIUM 或 LOW 或 INFO"}}

判斷標準：
- CRITICAL：正在被積極利用的 RCE、勒索軟體、供應鏈攻擊
- HIGH：重大漏洞、大規模資料外洩、APT 攻擊
- MEDIUM：有 PoC 但未廣泛利用的漏洞、釣魚活動
- LOW：已修補漏洞、低風險告警
- INFO：資安新聞、研究報告、無立即風險"""

ENTITY_ONLY_PROMPT = """你是一位資安威脅情報分析師。請從以下資安新聞抽取結構化資訊。

標題：{title}
內容：{content}

請只回傳以下 JSON：
{{
  "cve_ids": ["CVE-2024-XXXX"],
  "affected_products": ["產品名稱1", "產品名稱2"],
  "action_summary": "30字以內的行動建議（繁體中文）"
}}"""


def predict_v0(model: str, title: str, content: str, fewshot: list[dict]) -> dict:
    """Zero-shot: the production prompt as-is."""
    msg = [{"role": "user", "content": ANALYSIS_PROMPT.format(title=title, content=content[:800])}]
    return _chat(model, msg)


def predict_v1(model: str, title: str, content: str, fewshot: list[dict]) -> dict:
    """Few-shot: prepend labeled exemplars as prior chat turns."""
    messages = []
    for ex in fewshot:
        messages.append({
            "role": "user",
            "content": ANALYSIS_PROMPT.format(title=ex["title"], content=ex.get("content", "")[:800]),
        })
        messages.append({
            "role": "assistant",
            "content": json.dumps(ex["labels"], ensure_ascii=False),
        })
    messages.append({
        "role": "user",
        "content": ANALYSIS_PROMPT.format(title=title, content=content[:800]),
    })
    return _chat(model, messages)


def predict_v2(model: str, title: str, content: str, fewshot: list[dict]) -> dict:
    """Two-stage: separate threat_level call and entity-extraction call."""
    c = content[:800]
    lvl = _chat(model, [{"role": "user", "content": THREAT_ONLY_PROMPT.format(title=title, content=c)}], num_predict=20)
    ent = _chat(model, [{"role": "user", "content": ENTITY_ONLY_PROMPT.format(title=title, content=c)}])
    return {
        "threat_level": lvl.get("threat_level", ""),
        "cve_ids": ent.get("cve_ids", []),
        "affected_products": ent.get("affected_products", []),
        "action_summary": ent.get("action_summary", ""),
    }


PROMPT_VARIANTS = {"V0": predict_v0, "V1": predict_v1, "V2": predict_v2}


# ---------- Metrics ----------

_TOKEN = re.compile(r'[^a-z0-9]+')


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN.split(text.lower()) if t}


def threat_metric(true_level: str, pred_level: str) -> tuple[bool, bool]:
    """Returns (exact, near). near = ±1 step in severity order."""
    if true_level not in LEVEL_ORDER or pred_level not in LEVEL_ORDER:
        return False, False
    diff = abs(LEVEL_ORDER.index(true_level) - LEVEL_ORDER.index(pred_level))
    return diff == 0, diff <= 1


def cve_metric(true_cves: list[str], pred_cves: list[str]) -> tuple[float, float]:
    """Set precision/recall on CVE IDs (case-insensitive)."""
    t = {c.upper() for c in true_cves}
    p = {c.upper() for c in pred_cves}
    if not t and not p:
        return 1.0, 1.0
    precision = len(t & p) / len(p) if p else 0.0
    recall = len(t & p) / len(t) if t else 1.0
    return precision, recall


def product_recall(true_products: list[str], pred_products: list[str]) -> float:
    """Token-level recall: fraction of true-product tokens that appear in pred."""
    true_t = set().union(*(_tokens(p) for p in true_products)) if true_products else set()
    pred_t = set().union(*(_tokens(p) for p in pred_products)) if pred_products else set()
    if not true_t:
        return 1.0
    return len(true_t & pred_t) / len(true_t)


# ---------- Eval loop ----------

def eval_combo(model: str, variant: str, test: list[dict], fewshot: list[dict]) -> dict | None:
    """Evaluate one (model, prompt-variant) combo over the test set."""
    predict = PROMPT_VARIANTS[variant]
    n = len(test)
    exact_lv = near_lv = 0
    cve_p_sum = cve_r_sum = 0.0
    prod_r_sum = 0.0
    errors = 0

    t0 = time.time()
    for item in test:
        try:
            pred = predict(model, item["title"], item.get("content", ""), fewshot)
        except Exception as e:
            errors += 1
            print(f"  [!] {model}/{variant} {item['id']} failed: {e}")
            continue

        labels = item["labels"]
        e_lv, near = threat_metric(labels["threat_level"], pred.get("threat_level", ""))
        exact_lv += int(e_lv)
        near_lv += int(near)

        p, r = cve_metric(labels.get("cve_ids", []), pred.get("cve_ids", []))
        cve_p_sum += p
        cve_r_sum += r

        prod_r_sum += product_recall(
            labels.get("affected_products", []),
            pred.get("affected_products", []),
        )
    dt = time.time() - t0

    valid = n - errors
    if valid == 0:
        return None
    return {
        "model":    model,
        "variant":  variant,
        "n":        n,
        "errors":   errors,
        "exact_lv": exact_lv / valid,
        "near_lv":  near_lv  / valid,
        "cve_p":    cve_p_sum / valid,
        "cve_r":    cve_r_sum / valid,
        "prod_r":   prod_r_sum / valid,
        "seconds":  dt,
        "per_item": dt / n,
    }


def format_markdown_table(rows: list[dict]) -> str:
    lines = [
        "| Model | Prompt | n | Err | L exact | L ±1 | CVE P | CVE R | Prod R | s/item |",
        "|-------|--------|---|-----|---------|------|-------|-------|--------|--------|",
    ]
    for r in rows:
        if r is None:
            continue
        lines.append(
            f"| `{r['model']}` | {r['variant']} | {r['n']} | {r['errors']} "
            f"| {r['exact_lv']:.0%} | {r['near_lv']:.0%} "
            f"| {r['cve_p']:.0%} | {r['cve_r']:.0%} | {r['prod_r']:.0%} "
            f"| {r['per_item']:.1f}s |"
        )
    return "\n".join(lines)


def save_results(table: str, fewshot: list[dict], test: list[dict]) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"eval_{stamp}.md"
    header = (
        f"# Evaluation run {stamp}\n\n"
        f"- Models: {', '.join(MODELS)}\n"
        f"- Variants: {', '.join(VARIANTS)}\n"
        f"- Test items: {len(test)}  |  Few-shot exemplars (V1): {len(fewshot)}\n"
        f"- Split seed: {SPLIT_SEED}\n\n"
    )
    out.write_text(header + table + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    items = load_dataset()
    if not items:
        print(f"No items found in {DATASET}. Add labeled lines first.")
        sys.exit(1)

    fewshot, test = split_dataset(items)
    print(f"Loaded {len(items)} items → {len(test)} test, {len(fewshot)} few-shot exemplars")

    rows = []
    for model in MODELS:
        for variant in VARIANTS:
            print(f"\n=== {model} / {variant} ===")
            rows.append(eval_combo(model, variant, test, fewshot))

    table = format_markdown_table(rows)
    print("\n" + table)

    out = save_results(table, fewshot, test)
    print(f"\nSaved → {out}")
