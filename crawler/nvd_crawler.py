"""
Fetch recent CVEs from NVD API (no API key needed).
Insert each CVE as a news item into DB.
Rate limit: max 5 requests per 30 seconds without API key.
"""

import requests
import time
from database.db import insert_news
from config import NVD_API_BASE, NVD_RESULTS_PER_PAGE

def fetch_recent_cves(days_back: int = 1) -> int:
    """
    Fetch CVEs published in the last `days_back` days from NVD.
    Insert into DB as news items with source='NVD'.
    Return number of new CVEs inserted.

    NVD API endpoint:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0
    Params: pubStartDate, pubEndDate (format: 2024-01-01T00:00:00.000)

    Response structure:
    {
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2024-XXXX",
            "descriptions": [{"lang": "en", "value": "..."}],
            "metrics": {
              "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
            }
          }
        }
      ]
    }

    Map NVD severity to our threat levels:
    CRITICAL (9.0-10.0) -> CRITICAL
    HIGH (7.0-8.9)      -> HIGH
    MEDIUM (4.0-6.9)    -> MEDIUM
    LOW (0.1-3.9)       -> LOW
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
    }

    new_count = 0
    try:
        time.sleep(1)  # respect rate limit
        resp = requests.get(NVD_API_BASE, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            # Get English description
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available"
            )
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            title = f"[NVD] {cve_id}: {desc[:100]}"

            inserted = insert_news("NVD", title, url, now.isoformat(), desc[:1000])
            if inserted:
                new_count += 1

    except Exception as e:
        print(f"[NVD] Error fetching CVEs: {e}")

    return new_count
