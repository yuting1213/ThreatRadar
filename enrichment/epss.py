"""
EPSS (Exploit Prediction Scoring System) lookups from FIRST.org.

EPSS gives each CVE a 0–1 probability of being exploited in the next 30 days —
a forward-looking complement to CVSS (which only measures severity). The public
API accepts a comma-separated CVE list; we chunk requests to stay polite.
"""

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "ThreatRadar/1.0"


def parse_epss(raw: dict) -> dict:
    """Return {CVE_ID_upper: epss_float} from an EPSS API response dict."""
    out = {}
    for row in raw.get("data", []):
        cid = str(row.get("cve", "")).upper().strip()
        try:
            out[cid] = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
    return out


def fetch_epss(cve_ids, timeout: int = 30, chunk: int = 100) -> dict:
    """Look up EPSS scores for a list of CVE IDs. Network failures yield {}."""
    ids = sorted({str(c).upper().strip() for c in cve_ids if c})
    scores: dict = {}
    for i in range(0, len(ids), chunk):
        batch = ids[i:i + chunk]
        try:
            resp = requests.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
            )
            resp.raise_for_status()
            scores.update(parse_epss(resp.json()))
        except Exception as e:
            print(f"[EPSS] batch fetch failed ({e})")
    return scores
