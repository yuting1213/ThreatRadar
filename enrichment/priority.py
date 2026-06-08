"""
Composite vulnerability priority score.

Blends four orthogonal signals into one transparent 0–100 number so the radar
can rank by "what to fix first", not just the LLM's threat_level:

  - threat_level   the LLM's judgement (context: exploited? ransomware?)
  - cvss           severity of the flaw itself (NVD)
  - epss           probability it will be exploited in the next 30 days (FIRST.org)
  - kev            is it on CISA's Known-Exploited-Vulnerabilities list (yes/no)

KEV is the strongest signal — a confirmed in-the-wild exploit floors the score
high regardless of the others. Everything is bounded and explainable.
"""

LEVEL_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}

# Blend weights for the non-KEV part (sum to 1.0).
W_LEVEL, W_CVSS, W_EPSS = 0.40, 0.35, 0.25

# A confirmed exploited vuln (KEV) can't score below this.
KEV_FLOOR = 80.0
KEV_BONUS = 15.0

BANDS = [(80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (0, "LOW")]


def composite_priority(threat_level: str, cvss=None, epss=None, kev: bool = False) -> float:
    """Return a 0–100 priority score. All inputs optional except threat_level."""
    base = LEVEL_WEIGHT.get((threat_level or "").upper(), 0.1)
    cvss_norm = (cvss / 10.0) if (cvss is not None) else base   # fall back to LLM level
    epss_norm = epss if (epss is not None) else 0.0
    cvss_norm = min(max(cvss_norm, 0.0), 1.0)
    epss_norm = min(max(epss_norm, 0.0), 1.0)

    score = 100.0 * (W_LEVEL * base + W_CVSS * cvss_norm + W_EPSS * epss_norm)
    if kev:
        score = max(KEV_FLOOR, score) + KEV_BONUS
    return round(min(score, 100.0), 1)


def priority_band(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


def priority_for_news(item: dict, kev_set: set, epss_map: dict) -> dict:
    """Compute enrichment fields for one news row.

    item needs: threat_level, cvss_score, cve_ids (JSON string or list).
    kev_set: set of upper-case CVE IDs on CISA KEV.
    epss_map: {CVE_ID_upper: epss_float}.
    """
    import json
    raw = item.get("cve_ids")
    if isinstance(raw, list):
        cves = raw
    else:
        try:
            cves = json.loads(raw or "[]")
        except Exception:
            cves = []
    cves = [str(c).upper() for c in cves]

    kev_hit = any(c in kev_set for c in cves)
    epss_vals = [epss_map[c] for c in cves if c in epss_map]
    epss_max = max(epss_vals) if epss_vals else None

    score = composite_priority(
        item.get("threat_level"), item.get("cvss_score"), epss_max, kev_hit
    )
    return {
        "kev_hit": kev_hit,
        "epss_score": epss_max,
        "priority_score": score,
        "priority_band": priority_band(score),
    }
