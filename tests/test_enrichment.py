from unittest import mock

import config
import database.db as db
import enrichment.service as svc
from enrichment.kev import parse_kev
from enrichment.epss import parse_epss


def test_parse_kev():
    raw = {"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-02"},
                               {"cveID": "cve-2024-2"}]}
    assert parse_kev(raw) == {"CVE-2024-1": "2024-01-02", "CVE-2024-2": ""}


def test_parse_epss_drops_bad():
    raw = {"data": [{"cve": "CVE-2024-1", "epss": "0.97"}, {"cve": "CVE-2024-2", "epss": "bad"}]}
    assert parse_epss(raw) == {"CVE-2024-1": 0.97}


def test_enrich_items_pure():
    items = [{"id": 1, "threat_level": "CRITICAL", "cvss_score": 9.8, "cve_ids": '["CVE-2024-1"]'}]
    out = svc.enrich_items(items, {"CVE-2024-1"}, {"CVE-2024-1": 0.9})
    nid, enr = out[0]
    assert nid == 1 and enr["kev_hit"] and enr["priority_band"] == "CRITICAL"


def test_enrich_pending_writes_back(tmp_path):
    dbfile = str(tmp_path / "t.db")
    config.DB_PATH = dbfile
    db.DB_PATH = dbfile
    db.init_db()
    db.insert_news("NVD", "x", "http://x/1", "2026-06-03", "d", cvss_score=9.8)
    db.update_analysis(1, "CRITICAL", '["CVE-2024-1"]', '["Exchange"]', "patch")
    with mock.patch.object(svc, "load_kev_set", return_value={"CVE-2024-1"}), \
         mock.patch.object(svc, "fetch_epss", return_value={"CVE-2024-1": 0.9}):
        assert svc.enrich_pending() == 1
        # idempotent: nothing left unenriched
        assert svc.enrich_pending() == 0
    row = db.get_news_by_id(1)
    assert row["kev_hit"] == 1 and row["priority_band"] == "CRITICAL"
