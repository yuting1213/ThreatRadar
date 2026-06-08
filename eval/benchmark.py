"""
Benchmark LLM providers (local Ollama AND cloud DeepSeek/Qwen/OpenAI) on the
hand-labeled gold set, through the SAME provider layer the app uses in
production. Outputs a metrics.csv and a self-contained HTML report with charts.

Run from repo root:
    # local only (needs Ollama up):
    python eval/benchmark.py
    # add a cloud model:
    CLOUD_LLM_API_KEY=... CLOUD_LLM_BASE_URL=https://api.deepseek.com/v1 \
      CLOUD_LLM_MODEL=deepseek-chat python eval/benchmark.py

Edit BENCHMARK_PROVIDERS to choose which models to compare.
"""

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.providers import make_provider
from eval.metrics import evaluate, LEVEL_ORDER
from reporting import charts_svg as C

DATASET = Path(__file__).parent / "dataset.jsonl"
RESULTS_DIR = Path(__file__).parent / "results"

# Which models to benchmark. Each spec: kind + label + constructor kwargs.
# Cloud api_key defaults to CLOUD_LLM_API_KEY from the environment.
BENCHMARK_PROVIDERS = [
    {"kind": "ollama", "label": "llama3.2 (local)", "kwargs": {"model": "llama3.2"}},
    {"kind": "cloud",  "label": "deepseek (cloud)",
     "kwargs": {"model": "deepseek-chat", "base_url": "https://api.deepseek.com/v1",
                "provider_name": "deepseek"}},
]

_SCALAR_COLUMNS = [
    "label", "provider", "model", "n", "errors", "level_accuracy",
    "level_near_accuracy", "macro_f1", "cohen_kappa", "cve_precision",
    "cve_recall", "cve_f1", "product_recall", "latency_ms_mean",
]


def load_gold(path=DATASET) -> list[dict]:
    items = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return items


def evaluate_provider(label: str, provider, gold: list[dict], max_items=None) -> dict:
    """Run one provider over the gold set and compute metrics."""
    records = []
    errors = 0
    for item in gold[: max_items or len(gold)]:
        labels = item["labels"]
        res = provider.analyze(item["title"], item.get("content", ""))
        ok = res.get("status") == "ok"
        if not ok:
            errors += 1
        records.append({
            "true_level": labels["threat_level"],
            "pred_level": res.get("threat_level") if ok else "",
            "true_cves": labels.get("cve_ids", []),
            "pred_cves": res.get("cve_ids", []) if ok else [],
            "true_products": labels.get("affected_products", []),
            "pred_products": res.get("affected_products", []) if ok else [],
            "latency_ms": res.get("latency_ms"),
        })
    metrics = evaluate(records)
    return {
        "label": label,
        "provider": getattr(provider, "provider", "?"),
        "model": getattr(provider, "model", "?"),
        "errors": errors,
        "metrics": metrics,
        "records": records,
    }


# ── Output ──────────────────────────────────────────────────────────────────

def _scalar_row(r: dict) -> dict:
    m = r["metrics"]
    return {
        "label": r["label"], "provider": r["provider"], "model": r["model"],
        "n": m["n"], "errors": r["errors"],
        "level_accuracy": round(m["level_accuracy"], 4),
        "level_near_accuracy": round(m["level_near_accuracy"], 4),
        "macro_f1": round(m["macro_f1"], 4),
        "cohen_kappa": round(m["cohen_kappa"], 4),
        "cve_precision": round(m["cve_precision"], 4),
        "cve_recall": round(m["cve_recall"], 4),
        "cve_f1": round(m["cve_f1"], 4),
        "product_recall": round(m["product_recall"], 4),
        "latency_ms_mean": round(m["latency_ms_mean"], 1) if m["latency_ms_mean"] is not None else "",
    }


def write_csv(results: list[dict], path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_SCALAR_COLUMNS)
        w.writeheader()
        for r in results:
            w.writerow(_scalar_row(r))
    return path


def _pct(x):
    return f"{x*100:.0f}%"


def build_html_report(results: list[dict], gold_n: int) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    # Summary table
    head = ("<tr><th>模型</th><th>n</th><th>錯誤</th><th>等級 exact</th><th>等級 ±1</th>"
            "<th>macro-F1</th><th>κ</th><th>CVE-F1</th><th>產品 recall</th><th>延遲/題</th></tr>")
    body = ""
    for r in results:
        m = r["metrics"]
        lat = f'{m["latency_ms_mean"]:.0f} ms' if m["latency_ms_mean"] is not None else "—"
        body += (f'<tr><td class="lbl">{r["label"]}</td><td>{m["n"]}</td><td>{r["errors"]}</td>'
                 f'<td>{_pct(m["level_accuracy"])}</td><td>{_pct(m["level_near_accuracy"])}</td>'
                 f'<td><b>{_pct(m["macro_f1"])}</b></td><td>{m["cohen_kappa"]:.2f}</td>'
                 f'<td>{_pct(m["cve_f1"])}</td><td>{_pct(m["product_recall"])}</td><td>{lat}</td></tr>')

    # macro-F1 by provider + latency by provider (cost/quality story)
    f1_bar = C.bar_chart({r["label"]: r["metrics"]["macro_f1"] for r in results},
                         title="macro-F1（越高越好）")
    lat_data = {r["label"]: (r["metrics"]["latency_ms_mean"] or 0) for r in results}
    lat_bar = C.bar_chart(lat_data, title="平均延遲 ms（越低越好）", color="#534AB7")

    # per-class F1 grouped bar
    series = {r["label"]: [r["metrics"]["per_class"][lv]["f1"] for lv in LEVEL_ORDER]
              for r in results}
    grouped = C.grouped_bar(LEVEL_ORDER, series, title="各威脅等級 F1（依模型）")

    # confusion matrices
    cms = ""
    for r in results:
        cm = r["metrics"]["confusion_matrix"]
        matrix = [[cm[t][p] for p in LEVEL_ORDER] for t in LEVEL_ORDER]
        cms += (f'<div class="cmcard"><div class="cmh">{r["label"]}</div>'
                f'{C.heatmap(matrix, LEVEL_ORDER, LEVEL_ORDER, title=None)}</div>')

    support = {}
    if results:
        pc = results[0]["metrics"]["per_class"]
        support = {lv: pc[lv]["support"] for lv in LEVEL_ORDER}
    support_line = "、".join(f"{lv} {support.get(lv,0)}" for lv in LEVEL_ORDER)

    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>ThreatRadar 模型評估報告 {stamp}</title>
<style>
 body{{font-family:system-ui,"Noto Sans TC",sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1a1a1a}}
 h1{{font-size:22px;font-weight:600}} h2{{font-size:17px;font-weight:600;margin-top:28px}}
 .meta{{color:#777;font-size:13px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}
 th,td{{border:1px solid #e3e3e3;padding:6px 9px;text-align:center}}
 th{{background:#f6f6f6}} td.lbl{{text-align:left;font-weight:500}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 .cmgrid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 .cmcard{{border:1px solid #eee;border-radius:8px;padding:8px}}
 .cmh{{font-size:13px;font-weight:600;margin-bottom:4px}}
 .note{{color:#888;font-size:12px;margin-top:8px}}
</style></head><body>
<h1>🛡 ThreatRadar — 模型評估報告</h1>
<p class="meta">產生時間 {stamp} · gold set {gold_n} 題 · 透過 production provider 層評估</p>

<h2>總覽</h2>
<table><thead>{head}</thead><tbody>{body}</tbody></table>
<p class="note">等級 exact＝威脅等級完全正確比例；±1＝相差一級內；κ＝Cohen's kappa（&gt;0.6 算不錯）。<br>gold set 每類題數 (support)：{support_line}（小樣本，per-class F1 變異較大）。</p>

<h2>品質 vs 成本</h2>
<div class="grid2"><div>{f1_bar}</div><div>{lat_bar}</div></div>

<h2>各威脅等級 F1</h2>
{grouped}

<h2>混淆矩陣（列＝正解，欄＝預測）</h2>
<div class="cmgrid">{cms}</div>
</body></html>"""


def write_outputs(results: list[dict], gold_n: int, out_dir=RESULTS_DIR) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = write_csv(results, out_dir / f"benchmark_{stamp}.csv")
    html_path = out_dir / f"benchmark_{stamp}.html"
    html_path.write_text(build_html_report(results, gold_n), encoding="utf-8")
    return csv_path, html_path


def run_benchmark(specs=None, gold_path=DATASET, out_dir=RESULTS_DIR, max_items=None,
                  provider_factory=make_provider) -> dict:
    specs = specs or BENCHMARK_PROVIDERS
    gold = load_gold(gold_path)
    if not gold:
        raise SystemExit(f"No gold items in {gold_path}")
    results = []
    for spec in specs:
        provider = provider_factory(spec["kind"], **spec.get("kwargs", {}))
        chk = getattr(provider, "_configured", None)
        if chk is not None and not chk():
            print(f"=== {spec['label']} === [skip: provider not configured "
                  f"(set CLOUD_LLM_API_KEY/CLOUD_LLM_MODEL)]")
            continue
        print(f"=== {spec['label']} ===")
        results.append(evaluate_provider(spec["label"], provider, gold, max_items))

    if not results:
        raise SystemExit("No configured providers to benchmark. "
                         "Set up Ollama and/or CLOUD_LLM_* and edit BENCHMARK_PROVIDERS.")
    csv_path, html_path = write_outputs(results, len(gold[:max_items or len(gold)]), out_dir)
    print(f"\nWrote {csv_path}\nWrote {html_path}")
    return {"results": results, "csv": csv_path, "html": html_path}


if __name__ == "__main__":
    run_benchmark()
