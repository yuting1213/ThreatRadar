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
    cvss_score  REAL,
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

CREATE TABLE IF NOT EXISTS crawl_runs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ran_at   TEXT DEFAULT (datetime('now')),
    rss_new  INTEGER DEFAULT 0,
    nvd_new  INTEGER DEFAULT 0,
    analyzed INTEGER DEFAULT 0
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
        # cvss_score: populated by NVD crawler (team integration point)
        try:
            conn.execute("ALTER TABLE news ADD COLUMN cvss_score REAL")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def insert_news(source, title, url, published, raw_content, cvss_score=None) -> bool:
    """Insert news item. Return False if URL already exists (duplicate).

    cvss_score: optional float from NVD API (baseScore). Pass None for RSS items.
    """
    with _connect() as conn:
        try:
            conn.execute(
                "INSERT INTO news (source, title, url, published, raw_content, cvss_score) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (source, title, url, published, raw_content, cvss_score),
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


def get_recent_news(
    limit: int = 100,
    level_filter: str | None = None,
    search_query: str | None = None,
    sort_by: str = "threat_level",
    cve_only: bool = False,
) -> list[dict]:
    """Return recent analyzed news with optional filter, full-text search, and sort.

    sort_by: "threat_level" | "published" | "source" | "cvss_score"
    search_query: LIKE match on title, cve_ids, action_summary, affected_products.
    cve_only: if True, only return items that have at least one CVE.
    """
    _SORT_CLAUSES = {
        "published":   "ORDER BY published DESC, created_at DESC",
        "source":      "ORDER BY source ASC, created_at DESC",
        "cvss_score":  "ORDER BY cvss_score DESC, created_at DESC",
        "threat_level": ORDER_BY_LEVEL,
    }
    order = _SORT_CLAUSES.get(sort_by, ORDER_BY_LEVEL)

    conditions: list[str] = ["analysis_done = 1"]
    params: list = []

    if level_filter:
        conditions.append("threat_level = ?")
        params.append(level_filter)

    if cve_only:
        conditions.append(
            "(cve_ids IS NOT NULL AND cve_ids != '' AND cve_ids != '[]')"
        )

    if search_query and search_query.strip():
        q = f"%{search_query.strip()}%"
        conditions.append(
            "(title LIKE ? OR cve_ids LIKE ? OR action_summary LIKE ? OR affected_products LIKE ?)"
        )
        params.extend([q, q, q, q])

    where = " AND ".join(conditions)
    query = f"SELECT * FROM news WHERE {where} {order} LIMIT ?"
    params.append(limit)

    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def save_github_scan(repo_url, dependencies, matched_cves) -> None:
    """Save GitHub scan results. Dependencies and matched_cves are JSON strings."""
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


# ── C 部分新增函數 ─────────────────────────────────────────────────────────────

def get_news_by_id(news_id: int) -> dict | None:
    """Return a single news row by ID, or None if not found."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM news WHERE id=?", (news_id,)).fetchone()
        return dict(row) if row else None


def get_enhanced_stats() -> dict:
    """Return comprehensive stats for the system status dashboard.

    Keys: total_analyzed, by_level, unanalyzed, failed, scan_count, last_crawl
    """
    with _connect() as conn:
        level_rows = conn.execute(
            "SELECT threat_level, COUNT(*) AS n FROM news "
            "WHERE analysis_done=1 GROUP BY threat_level"
        ).fetchall()
        by_level = {row["threat_level"] or "INFO": row["n"] for row in level_rows}

        unanalyzed = conn.execute(
            "SELECT COUNT(*) AS n FROM news WHERE analysis_done=0"
        ).fetchone()["n"]


        failed = conn.execute(
            "SELECT COUNT(*) AS n FROM news WHERE action_summary='分析失敗'"
        ).fetchone()["n"]

        scan_count = conn.execute(
            "SELECT COUNT(*) AS n FROM github_scans"
        ).fetchone()["n"]

        # Use crawl_runs for accurate last-crawl time. Falls back to MAX(news.created_at)
        # for DBs that predate the crawl_runs table (i.e. ran before this migration).
        last_run_row = conn.execute(
            "SELECT MAX(ran_at) AS last FROM crawl_runs"
        ).fetchone()
        last_crawl = (last_run_row["last"] or "")[:16].replace("T", " ") if last_run_row and last_run_row["last"] else ""

        if not last_crawl:
            # Fallback for legacy DBs without crawl_runs records
            fallback = conn.execute(
                "SELECT MAX(created_at) AS last FROM news"
            ).fetchone()
            last_crawl = (fallback["last"] or "")[:16].replace("T", " ") if fallback else ""

        return {
            "total_analyzed": sum(by_level.values()),
            "by_level":       by_level,
            "unanalyzed":     unanalyzed,
            "failed":         failed,
            "scan_count":     scan_count,
            "last_crawl":     last_crawl,
        }


def get_scan_history(limit: int = 50) -> list[dict]:
    """Return past GitHub scan records from github_scans table, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, repo_url, dependencies, matched_cves, scanned_at "
            "FROM github_scans ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def reset_analysis(news_id: int) -> None:
    """Reset a news item so it gets re-processed on the next crawl cycle."""
    with _connect() as conn:
        conn.execute(
            "UPDATE news SET analysis_done=0, analysis_retries=0 WHERE id=?",
            (news_id,),
        )
        conn.commit()


def get_analyzed_news_for_dropdown(limit: int = 200) -> list[tuple[str, int]]:
    """Return (display_label, news_id) pairs for the re-analyze dropdown."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, title, threat_level FROM news WHERE analysis_done=1 "
            + ORDER_BY_LEVEL
            + " LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            (f"[{row['threat_level']}] {row['title'][:80]}", row["id"])
            for row in rows
        ]


def record_crawl_run(rss_new: int = 0, nvd_new: int = 0, analyzed: int = 0) -> None:
    """Insert a crawl_runs row with the actual finish timestamp.

    Called by pipeline.run_crawl_cycle() after every successful crawl so that
    get_enhanced_stats() can report the true last-run time even when no new
    news items were inserted.
    """
    with _connect() as conn:
        conn.execute(
            "INSERT INTO crawl_runs (rss_new, nvd_new, analyzed) VALUES (?, ?, ?)",
            (rss_new, nvd_new, analyzed),
        )
        conn.commit()
