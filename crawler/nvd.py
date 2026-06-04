"""
Fetch recent CVEs from NVD API and insert each as a news item.

Rate limit: 5 req / 30s without an API key, 50 req / 30s with one. We page
through results with startIndex until totalResults is covered or NVD_MAX_PAGES
is hit, sleeping between requests so a busy CVE day isn't silently truncated to
the first page.
"""

import requests
import time
from datetime import datetime, timedelta, timezone

from database.db import insert_news
from config import (
    NVD_API_BASE, NVD_RESULTS_PER_PAGE, NVD_MAX_PAGES, NVD_API_KEY,
)

# Seconds to wait between page requests (well within the unauthenticated limit;
# a key relaxes the limit but the small sleep keeps us a good API citizen).
_PAGE_SLEEP = 1.0


def _parse_vuln(vuln: dict, published_iso: str):
    """Turn one NVD 'vulnerabilities[]' entry into insert_news() args, or None."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No description available",
    )
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    title = f"[NVD] {cve_id}: {desc[:100]}"

    # Extract CVSS baseScore — try v3.1, then v3.0, then v2.
    cvss_score = None
    metrics = cve.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key, [])
        if entries:
            cvss_score = entries[0].get("cvssData", {}).get("baseScore")
            if cvss_score is not None:
                break

    return ("NVD", title, url, published_iso, desc[:1000], cvss_score)


def fetch_recent_cves(days_back: int = 1) -> int:
    """
    Fetch CVEs published in the last `days_back` days from NVD, paginating until
    all results are seen (capped at NVD_MAX_PAGES). Insert as source='NVD' news
    items. Return number of NEW CVEs inserted (duplicates dropped by URL UNIQUE).
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)
    published_iso = now.isoformat()

    base_params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    new_count = 0
    start_index = 0
    pages_fetched = 0

    try:
        while pages_fetched < NVD_MAX_PAGES:
            time.sleep(_PAGE_SLEEP)  # respect rate limit
            params = dict(base_params, startIndex=start_index)
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                args = _parse_vuln(vuln, published_iso)
                if args and insert_news(*args[:5], cvss_score=args[5]):
                    new_count += 1

            pages_fetched += 1
            total = data.get("totalResults", 0)
            per_page = data.get("resultsPerPage", NVD_RESULTS_PER_PAGE) or NVD_RESULTS_PER_PAGE
            start_index += per_page
            # Stop when we've covered everything or NVD returned an empty page.
            if start_index >= total or not vulns:
                break

    except Exception as e:
        print(f"[NVD] Error fetching CVEs: {e}")

    return new_count
