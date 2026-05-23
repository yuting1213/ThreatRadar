"""SQLite persistence layer for the threat radar."""

import sqlite3
from contextlib import contextmanager

from config import DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS news (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    title       TEXT NOT NULL,
    url         TEXT UNIQUE NOT NULL,
    published   TEXT,
    raw_content TEXT,
    threat_level     TEXT,
    cve_ids          TEXT,
    affected_products TEXT,
    action_summary   TEXT,
    analysis_done    INTEGER DEFAULT 0,
    analysis_retries INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS github_scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url     TEXT NOT NULL,
    dependencies TEXT,
    matched_cves TEXT,
    scanned_at   TEXT DEFAULT (datetime('now'))
);
"""

ORDER_BY_LEVEL = """
ORDER BY CASE threat_level
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE 5
END, created_at DESC
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if not exist, run idempotent column migrations, set WAL."""
    with _connect() as conn:
        # WAL persists in the DB file header — setting it here once is enough
        # for all future connections. Writers no longer block readers, so the
        # dashboard stays responsive while the scheduler is mid-cycle.
        conn.execute("PRAGMA journal_mode=WAL")

        conn.executescript(SCHEMA)
        # Migration for DBs created before analysis_retries existed.
        # SQLite has no "ADD COLUMN IF NOT EXISTS", so we swallow the
        # "duplicate column name" error on already-migrated DBs.
        try:
            conn.execute("ALTER TABLE news ADD COLUMN analysis_retries INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def insert_news(source, title, url, published, raw_content) -> bool:
    """Insert news item. Return False if URL already exists (duplicate)."""
    with _connect() as conn:
        try:
            conn.execute(
                "INSERT INTO news (source, title, url, published, raw_content) "
                "VALUES (?, ?, ?, ?, ?)",
                (source, title, url, published, raw_content),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_unanalyzed_news(limit: int = 50) -> list[dict]:
    """Return news items where analysis_done = 0."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, title, raw_content FROM news "
            "WHERE analysis_done = 0 ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def update_analysis(news_id, threat_level, cve_ids, affected_products, action_summary) -> None:
    """Mark LLM analysis successful and store results."""
    with _connect() as conn:
        conn.execute(
            "UPDATE news SET threat_level=?, cve_ids=?, affected_products=?, "
            "action_summary=?, analysis_done=1 WHERE id=?",
            (threat_level, cve_ids, affected_products, action_summary, news_id),
        )
        conn.commit()


def mark_analysis_failed(news_id: int, max_retries: int) -> int:
    """
    Bump retry counter. Only mark analysis_done=1 once the retry budget
    is exhausted — so a transient Ollama outage doesn't permanently lose
    the row, but a permanently malformed row still stops being re-tried.
    Returns the new retry count.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT analysis_retries FROM news WHERE id=?", (news_id,)
        ).fetchone()
        retries = (row["analysis_retries"] if row else 0) + 1
        if retries >= max_retries:
            conn.execute(
                "UPDATE news SET threat_level='INFO', cve_ids='[]', "
                "affected_products='[]', action_summary='分析失敗', "
                "analysis_retries=?, analysis_done=1 WHERE id=?",
                (retries, news_id),
            )
        else:
            conn.execute(
                "UPDATE news SET analysis_retries=? WHERE id=?",
                (retries, news_id),
            )
        conn.commit()
        return retries


def get_recent_news(limit: int = 100, level_filter: str | None = None) -> list[dict]:
    """Return recent analyzed news, optionally filtered by threat level."""
    with _connect() as conn:
        if level_filter:
            query = (
                "SELECT * FROM news WHERE analysis_done = 1 AND threat_level = ? "
                + ORDER_BY_LEVEL
                + " LIMIT ?"
            )
            rows = conn.execute(query, (level_filter, limit)).fetchall()
        else:
            query = (
                "SELECT * FROM news WHERE analysis_done = 1 "
                + ORDER_BY_LEVEL
                + " LIMIT ?"
            )
            rows = conn.execute(query, (limit,)).fetchall()
        return [dict(row) for row in rows]


def save_github_scan(repo_url, dependencies, matched_cves) -> None:
    """Save GitHub scan results. `dependencies` and `matched_cves` are JSON strings."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO github_scans (repo_url, dependencies, matched_cves) "
            "VALUES (?, ?, ?)",
            (repo_url, dependencies, matched_cves),
        )
        conn.commit()


def get_stats() -> dict:
    """Return counts per threat level for dashboard stats."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT threat_level, COUNT(*) AS n FROM news "
            "WHERE analysis_done = 1 GROUP BY threat_level"
        ).fetchall()
        return {row["threat_level"] or "INFO": row["n"] for row in rows}
