"""
Entry point:
1. Initialize database
2. Run first crawl immediately
3. Start APScheduler for hourly crawls
4. Launch Gradio dashboard
"""

from database.db import init_db
from pipeline import run_crawl_cycle
from dashboard.app import launch
from config import CRAWL_INTERVAL_MINUTES
from apscheduler.schedulers.background import BackgroundScheduler
from logger_config import setup_logger
logger = setup_logger(__name__)

def _scheduled_crawl():
    logger.info("[Scheduler] Starting crawl cycle...")
    ran, msg = run_crawl_cycle()
    prefix = "[Scheduler]" if ran else "[Scheduler] Skipped:"
    logger.info(f"{prefix} {msg}")


if __name__ == "__main__":
    init_db()
    logger.info("[Main] Database initialized")

    # First crawl on startup
    _scheduled_crawl()

    # Schedule hourly crawls
    scheduler = BackgroundScheduler()
    scheduler.add_job(_scheduled_crawl, "interval", minutes=CRAWL_INTERVAL_MINUTES)
    scheduler.start()
    logger.info(f"[Main] Scheduler started (every {CRAWL_INTERVAL_MINUTES} min)")

    # Launch dashboard (blocking)
    logger.info("[Main] Launching dashboard at http://localhost:7860")
    launch()
