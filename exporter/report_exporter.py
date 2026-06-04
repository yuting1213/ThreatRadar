"""
Export threat intelligence to shareable files under config.OUTPUT_DIR.

Three exports:
  - export_threat_csv()            primary (local) result per news, Excel-friendly
  - export_threat_jsonl()          same data but list fields kept as JSON arrays
  - export_model_comparison_csv()  latest local vs cloud per news, for demos

CSVs are written with a UTF-8 BOM (utf-8-sig) so Excel shows Traditional Chinese
correctly. Files land in OUTPUT_DIR (git-ignored); the directory is created on
demand. Each function returns the written file path.
"""

import os
import csv
import json
from datetime import datetime

from database.db import (
    get_recent_news, get_latest_news_analysis, get_analysis_comparison,
)
from config import OUTPUT_DIR, LOCAL_PROVIDER


def _ensure_dir() -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    return OUTPUT_DIR


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M")


def _to_list(maybe_json) -> list:
    """Parse a JSON-array string back into a list; tolerate junk/None."""
    if isinstance(maybe_json, list):
        return maybe_json
    try:
        v = json.loads(maybe_json or "[]")
        return v if isinstance(v, list) else [v]
    except Exception:
        return []


def _rows_for_threats(limit: int) -> list[dict]:
    """Join each analyzed news row with its latest LOCAL analysis metadata."""
    rows = []
    for n in get_recent_news(limit=limit):
        meta = get_latest_news_analysis(n["id"], LOCAL_PROVIDER) or {}
        rows.append({
            "news_id": n["id"],
            "source": n.get("source", ""),
            "title": n.get("title", ""),
            "url": n.get("url", ""),
            "published": n.get("published", ""),
            "cvss_score": n.get("cvss_score", ""),
            "provider": meta.get("provider", LOCAL_PROVIDER),
            "model": meta.get("model", ""),
            "prompt_version": meta.get("prompt_version", ""),
            "threat_level": n.get("threat_level", ""),
            "cve_ids": _to_list(n.get("cve_ids")),
            "affected_products": _to_list(n.get("affected_products")),
            "action_summary": n.get("action_summary", ""),
            "latency_ms": meta.get("latency_ms", ""),
            "analyzed_at": meta.get("created_at", ""),
        })
    return rows


_THREAT_COLUMNS = [
    "news_id", "source", "title", "url", "published", "cvss_score",
    "provider", "model", "prompt_version", "threat_level", "cve_ids",
    "affected_products", "action_summary", "latency_ms", "analyzed_at",
]


def export_threat_csv(path: str | None = None, limit: int = 5000) -> str:
    """Write the threat report as CSV. List fields are joined with '; '."""
    _ensure_dir()
    path = path or os.path.join(OUTPUT_DIR, f"threat_report_{_stamp()}.csv")
    rows = _rows_for_threats(limit)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_THREAT_COLUMNS)
        w.writeheader()
        for r in rows:
            out = dict(r)
            out["cve_ids"] = "; ".join(r["cve_ids"])
            out["affected_products"] = "; ".join(r["affected_products"])
            w.writerow(out)
    return path


def export_threat_jsonl(path: str | None = None, limit: int = 5000) -> str:
    """Write the threat report as JSONL, preserving list fields as arrays."""
    _ensure_dir()
    path = path or os.path.join(OUTPUT_DIR, f"threat_report_{_stamp()}.jsonl")
    rows = _rows_for_threats(limit)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


_COMPARISON_COLUMNS = [
    "news_id", "title", "local_provider", "local_model", "local_level",
    "cloud_provider", "cloud_model", "cloud_level", "level_agree",
    "local_cve_ids", "cloud_cve_ids", "local_products", "cloud_products",
    "local_latency_ms", "cloud_latency_ms",
]


def export_model_comparison_csv(path: str | None = None, limit: int = 5000) -> str:
    """Write latest local-vs-cloud analysis per news item as CSV."""
    _ensure_dir()
    path = path or os.path.join(OUTPUT_DIR, f"model_comparison_{_stamp()}.csv")
    comparison = get_analysis_comparison(limit=limit)

    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_COMPARISON_COLUMNS)
        w.writeheader()
        for e in comparison:
            local = e.get("local") or {}
            cloud = e.get("cloud") or {}
            w.writerow({
                "news_id": e["news_id"],
                "title": e.get("title", ""),
                "local_provider": local.get("provider", ""),
                "local_model": local.get("model", ""),
                "local_level": local.get("threat_level", ""),
                "cloud_provider": cloud.get("provider", ""),
                "cloud_model": cloud.get("model", ""),
                "cloud_level": cloud.get("threat_level", ""),
                "level_agree": e.get("level_agree", False),
                "local_cve_ids": "; ".join(_to_list(local.get("cve_ids"))),
                "cloud_cve_ids": "; ".join(_to_list(cloud.get("cve_ids"))),
                "local_products": "; ".join(_to_list(local.get("affected_products"))),
                "cloud_products": "; ".join(_to_list(cloud.get("affected_products"))),
                "local_latency_ms": local.get("latency_ms", ""),
                "cloud_latency_ms": cloud.get("latency_ms", ""),
            })
    return path
