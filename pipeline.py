"""
Single entry point for a crawl+analyze cycle.

Both the APScheduler job (main.py) and the dashboard's manual button
(dashboard/app.py) run this. The module-level lock prevents the two
from overlapping — each cycle calls Ollama on every pending item, so
overlap means duplicate LLM work and racing DB writes.

Acquire is non-blocking: callers find out immediately whether they
ran or got skipped, so the Gradio UI never sits waiting on a 5-minute
LLM batch.
"""

import threading

from crawler.rss import crawl_all_feeds
from crawler.nvd import fetch_recent_cves
from analyzer.llm import analyze_pending_news, analyze_single
from database.db import record_crawl_run


_lock = threading.Lock()


def run_crawl_cycle() -> tuple[bool, str]:
    """
    Run RSS + NVD crawl + LLM analyze under the global lock.
    Returns (ran, message). ran=False means another cycle was already running.
    """
    if not _lock.acquire(blocking=False):
        return False, "⏳ 已有爬取任務正在執行，請稍候"

    try:
        rss_new  = crawl_all_feeds()
        nvd_new  = fetch_recent_cves(days_back=1)
        analyzed = analyze_pending_news()
        # Record the actual finish time so get_enhanced_stats() always reflects
        # when the scheduler last ran, even if no new items were inserted.
        record_crawl_run(rss_new=rss_new, nvd_new=nvd_new, analyzed=analyzed)
        return True, f"✅ 爬取完成：RSS +{rss_new} 筆，NVD +{nvd_new} 筆，分析 {analyzed} 筆"
    finally:
        _lock.release()


def reanalyze_one(news_id: int) -> tuple[bool, str]:
    """
    Immediately re-analyze a single news item under the global lock.

    Resets the item's analysis state then calls Ollama synchronously so
    the dashboard shows the result right away (unlike run_crawl_cycle
    which batches all pending items).  The same lock prevents overlap with
    the APScheduler job or a concurrent manual crawl.
    """
    if not _lock.acquire(blocking=False):
        return False, "\u23f3 \u722c\u53d6\u4efb\u52d9\u6b63\u5728\u57f7\u884c\u4e2d\uff0c\u8acb\u7a0d\u5f8c\u518d\u8a66"

    try:
        from database.db import get_news_by_id, reset_analysis

        item = get_news_by_id(news_id)
        if not item:
            return False, f"\u274c \u627e\u4e0d\u5230 news ID={news_id}"

        reset_analysis(news_id)
        ok = analyze_single(news_id, item["title"], item.get("raw_content") or "")

        title_short = item["title"][:50]
        if ok:
            return True, f"\u2705 \u91cd\u65b0\u5206\u6790\u5b8c\u6210\uff1a\u300a{title_short}\u300b"
        else:
            return False, (
                f"\u26a0 Ollama \u5206\u6790\u5931\u6557\uff08ID={news_id}\uff09\uff0c"
                "\u5df2\u91cd\u8a2d\u72c0\u614b\uff0c\u5c07\u5728\u4e0b\u6b21\u722c\u53d6\u9031\u671f\u81ea\u52d5\u91cd\u8a66"
            )
    finally:
        _lock.release()
