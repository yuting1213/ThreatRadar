import sqlite3
import pytest
import database.db as db_module

@pytest.fixture
def mock_db(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    
    conn.execute("""
        CREATE TABLE news (
            id INTEGER PRIMARY KEY,
            analysis_retries INTEGER DEFAULT 0,
            analysis_done INTEGER DEFAULT 0,
            threat_level TEXT,
            cve_ids TEXT,
            affected_products TEXT,
            action_summary TEXT
        )
    """)
    
    conn.execute("INSERT INTO news (id, analysis_retries) VALUES (1, 0)")
    conn.execute("INSERT INTO news (id, analysis_retries) VALUES (2, 2)")
    conn.commit()

    monkeypatch.setattr(db_module, "_connect", lambda: conn)
    return conn

def test_retry_not_exhausted(mock_db):
    retries = db_module.mark_analysis_failed(1, 3)
    
    assert retries == 1
    row = mock_db.execute("SELECT analysis_retries, analysis_done FROM news WHERE id=1").fetchone()
    assert row["analysis_retries"] == 1
    assert row["analysis_done"] == 0

def test_retry_budget_exhausted(mock_db):
    retries = db_module.mark_analysis_failed(2, 3)
    
    assert retries == 3
    row = mock_db.execute("SELECT analysis_retries, analysis_done, action_summary FROM news WHERE id=2").fetchone()
    assert row["analysis_retries"] == 3
    assert row["analysis_done"] == 1
    assert row["action_summary"] == "分析失敗"