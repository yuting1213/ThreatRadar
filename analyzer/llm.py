"""
Use Ollama to analyze news items and extract structured threat intelligence.
Process items in batches from the DB.
"""

import requests
import json
from concurrent.futures import ThreadPoolExecutor

from database.db import get_unanalyzed_news, update_analysis, mark_analysis_failed
from config import (
    OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT,
    MAX_ANALYSIS_RETRIES, LLM_CONCURRENCY,
)

ANALYSIS_PROMPT = """你是一位資安威脅情報分析師。請分析以下資安新聞並以 JSON 格式回應。

標題：{title}
內容：{content}

請只回傳以下 JSON，不要其他文字：
{{
  "threat_level": "CRITICAL 或 HIGH 或 MEDIUM 或 LOW 或 INFO",
  "cve_ids": ["CVE-2024-XXXX"],
  "affected_products": ["產品名稱1", "產品名稱2"],
  "action_summary": "30字以內的行動建議（繁體中文）"
}}

判斷標準：
- CRITICAL：正在被積極利用的 RCE、勒索軟體、供應鏈攻擊
- HIGH：重大漏洞、大規模資料外洩、APT 攻擊
- MEDIUM：有 PoC 但未廣泛利用的漏洞、釣魚活動
- LOW：已修補漏洞、低風險告警
- INFO：資安新聞、研究報告、無立即風險"""


def analyze_single(news_id: int, title: str, content: str) -> bool:
    """
    Call Ollama to analyze a single news item.
    Update DB with results.
    Return True on success.
    """
    prompt = ANALYSIS_PROMPT.format(title=title, content=content[:800])

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",  # Ollama constrains output to valid JSON
                "options": {"num_predict": 300, "temperature": 0.1},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        result = json.loads(resp.json()["message"]["content"])

        update_analysis(
            news_id=news_id,
            threat_level=result.get("threat_level", "INFO"),
            cve_ids=json.dumps(result.get("cve_ids", []), ensure_ascii=False),
            affected_products=json.dumps(result.get("affected_products", []), ensure_ascii=False),
            action_summary=result.get("action_summary", ""),
        )
        return True

    except Exception as e:
        retries = mark_analysis_failed(news_id, MAX_ANALYSIS_RETRIES)
        if retries >= MAX_ANALYSIS_RETRIES:
            print(f"[LLM] news {news_id} giving up after {retries} attempts: {e}")
        else:
            print(f"[LLM] news {news_id} attempt {retries}/{MAX_ANALYSIS_RETRIES} failed: {e}")
        return False


def analyze_pending_news() -> int:
    """
    Fetch all unanalyzed news and run analyze_single in parallel.
    Each worker opens its own sqlite connection inside _connect(), and
    sqlite is in WAL mode so concurrent writes don't block each other.
    Return number of items successfully analyzed.
    """
    pending = get_unanalyzed_news(limit=50)
    if not pending:
        return 0

    success = 0
    with ThreadPoolExecutor(max_workers=LLM_CONCURRENCY) as pool:
        futures = [
            pool.submit(analyze_single, item["id"], item["title"], item.get("raw_content", ""))
            for item in pending
        ]
        for f in futures:
            if f.result():
                success += 1

    print(f"[LLM] Analyzed {success}/{len(pending)} items (concurrency={LLM_CONCURRENCY})")
    return success
