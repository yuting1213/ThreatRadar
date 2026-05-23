"""
Fetch news from RSS feeds defined in config.RSS_FEEDS.
For each feed, parse with feedparser and insert new items into DB.
Extract plain text from HTML content using basic regex (no extra deps).
"""

import feedparser
import re
import requests
from database.db import insert_news
from config import RSS_FEEDS

# feedparser.parse(url) has no timeout knob and will hang the whole
# scheduler tick if a feed stalls. Fetch with requests first, then
# hand the bytes to feedparser.
RSS_FETCH_TIMEOUT = 15
RSS_USER_AGENT = "ThreatRadar/1.0"


def clean_html(html: str) -> str:
    """Strip HTML tags, return plain text (max 1000 chars)."""
    text = re.sub(r'<[^>]+>', ' ', html or '')
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:1000]

def crawl_all_feeds() -> int:
    """
    Crawl all RSS feeds in config.RSS_FEEDS.
    Insert new items into DB.
    Return total number of NEW items inserted.
    """
    total_new = 0
    for feed_config in RSS_FEEDS:
        try:
            resp = requests.get(
                feed_config["url"],
                timeout=RSS_FETCH_TIMEOUT,
                headers={"User-Agent": RSS_USER_AGENT},
            )
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
            for entry in feed.entries:
                title   = entry.get("title", "").strip()
                url     = entry.get("link", "").strip()
                published = entry.get("published", "")
                # Try to get full content, fallback to summary
                content = ""
                if hasattr(entry, "content"):
                    content = entry.content[0].value
                else:
                    content = entry.get("summary", "")
                content = clean_html(content)

                if title and url:
                    inserted = insert_news(feed_config["name"], title, url, published, content)
                    if inserted:
                        total_new += 1
        except Exception as e:
            print(f"[RSS] Error crawling {feed_config['name']}: {e}")
    return total_new
