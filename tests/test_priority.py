from enrichment.priority import composite_priority, priority_band, priority_for_news


def test_kev_floors_high():
    assert composite_priority("INFO", cvss=0, epss=0, kev=True) >= 80


def test_high_signals_near_max():
    assert 90 <= composite_priority("CRITICAL", cvss=9.8, epss=0.97) <= 100


def test_low_signals_low():
    assert composite_priority("INFO", cvss=1.0, epss=0.01) < 35


def test_kev_monotonic():
    assert (composite_priority("MEDIUM", 6, 0.2, kev=True)
            > composite_priority("MEDIUM", 6, 0.2, kev=False))


def test_clamps_out_of_range_cvss():
    assert composite_priority("LOW", cvss=99, epss=5) <= 100


def test_bands():
    assert priority_band(85) == "CRITICAL"
    assert priority_band(65) == "HIGH"
    assert priority_band(40) == "MEDIUM"
    assert priority_band(10) == "LOW"


def test_priority_for_news():
    item = {"threat_level": "HIGH", "cvss_score": 8.1, "cve_ids": '["CVE-2024-1","cve-2024-2"]'}
    r = priority_for_news(item, kev_set={"CVE-2024-1"}, epss_map={"CVE-2024-2": 0.5})
    assert r["kev_hit"] is True
    assert r["epss_score"] == 0.5
    assert r["priority_band"] in ("CRITICAL", "HIGH")


def test_priority_for_news_no_cves():
    item = {"threat_level": "INFO", "cvss_score": None, "cve_ids": "[]"}
    r = priority_for_news(item, set(), {})
    assert r["kev_hit"] is False and r["epss_score"] is None
