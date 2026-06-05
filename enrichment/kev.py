"""
CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV lists CVEs with confirmed in-the-wild exploitation — the single most
actionable signal for prioritisation. The catalog is a public JSON feed; we
cache it locally so a crawl cycle doesn't refetch ~1MB every time, and fall back
to a stale cache if the network is down.
"""

import json
import time
from pathlib import Path

import requests

import config

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH = Path(config.OUTPUT_DIR) / "_cache" / "kev_catalog.json"
USER_AGENT = "ThreatRadar/1.0"


def fetch_kev_catalog(timeout: int = 30) -> dict:
    resp = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def parse_kev(raw: dict) -> dict:
    """Return {CVE_ID_upper: dateAdded} from a KEV catalog dict."""
    out = {}
    for v in raw.get("vulnerabilities", []):
        cid = str(v.get("cveID", "")).upper().strip()
        if cid:
            out[cid] = v.get("dateAdded", "")
    return out


def load_kev_set(cache_path: Path = CACHE_PATH, max_age_hours: float = 24,
                 fetch: bool = True) -> set:
    """Return a set of KEV CVE IDs, using a local cache when fresh.

    Falls back to a stale cache (then empty set) if the network fetch fails, so
    enrichment degrades gracefully offline.
    """
    cache_path = Path(cache_path)
    fresh = (
        cache_path.exists()
        and (time.time() - cache_path.stat().st_mtime) < max_age_hours * 3600
    )
    if fresh or not fetch:
        if cache_path.exists():
            try:
                return set(parse_kev(json.loads(cache_path.read_text(encoding="utf-8"))))
            except Exception:
                pass
        if not fetch:
            return set()

    try:
        raw = fetch_kev_catalog()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(raw), encoding="utf-8")
        return set(parse_kev(raw))
    except Exception as e:
        print(f"[KEV] fetch failed ({e}); using cache if available")
        if cache_path.exists():
            try:
                return set(parse_kev(json.loads(cache_path.read_text(encoding="utf-8"))))
            except Exception:
                pass
        return set()
