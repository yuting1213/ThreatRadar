"""
Enrichment orchestration: turn analyzed news into prioritized news.

For every analyzed item that lacks a priority score, look up whether its CVEs
are on CISA KEV and their EPSS exploit-probabilities, compute the composite
priority, and write it back. Network lookups are batched once per pass (one KEV
fetch, one EPSS batch) rather than per-item.
"""

import database.db as db
from enrichment.kev import load_kev_set
from enrichment.epss import fetch_epss
from enrichment.priority import priority_for_news


def _collect_cves(items) -> list[str]:
    import json
    out = set()
    for it in items:
        raw = it.get("cve_ids")
        try:
            for c in (raw if isinstance(raw, list) else json.loads(raw or "[]")):
                out.add(str(c).upper())
        except Exception:
            pass
    return sorted(out)


def enrich_items(items, kev_set: set, epss_map: dict) -> list[tuple[int, dict]]:
    """Pure computation: return [(news_id, enrichment_dict), ...] — no DB writes."""
    return [(it["id"], priority_for_news(it, kev_set, epss_map)) for it in items]


def enrich_pending(limit: int = 500, fetch: bool = True) -> int:
    """Enrich all analyzed-but-unprioritised items. Returns count enriched."""
    items = db.get_unenriched_news(limit)
    if not items:
        return 0

    kev_set = load_kev_set(fetch=fetch)
    cves = _collect_cves(items)
    epss_map = fetch_epss(cves) if (fetch and cves) else {}

    n = 0
    for news_id, enr in enrich_items(items, kev_set, epss_map):
        db.update_enrichment(
            news_id, enr["kev_hit"], enr["epss_score"],
            enr["priority_score"], enr["priority_band"],
        )
        n += 1
    print(f"[Enrich] prioritised {n} items "
          f"(KEV set={len(kev_set)}, EPSS scores={len(epss_map)})")
    return n
