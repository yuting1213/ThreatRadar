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

from crawler.rss_crawler import crawl_all_feeds
from crawler.nvd_crawler import fetch_recent_cves
from analyzer.llm_analyzer import analyze_pending_news


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
        return True, f"✅ 爬取完成：RSS +{rss_new} 筆，NVD +{nvd_new} 筆，分析 {analyzed} 筆"
    finally:
        _lock.release()
