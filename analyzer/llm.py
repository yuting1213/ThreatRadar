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
    LLM_PROVIDER, OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL,
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


# Few-shot exemplars prepended to every analysis call as prior chat turns.
# Chosen to anchor the full severity range (CRITICAL / LOW / INFO) and to
# demonstrate the exact JSON shape — including empty lists and a zh-TW
# action_summary. The Track A eval (eval/FINDINGS.md) showed this few-shot
# strategy (V1) lifts qwen2.5:7b threat-level accuracy from 84% to 92% over
# the zero-shot prompt, with ±1 accuracy at 100%.
#
# These are hand-written and intentionally NOT drawn from eval/dataset.jsonl,
# so the offline eval stays honest (its V1 uses its own held-out split).
FEWSHOT_EXAMPLES = [
    {
        "title": "CISA 警告 Microsoft Exchange 零時差正遭積極利用",
        "content": "CISA 將一個 Microsoft Exchange Server 重大漏洞列入已知遭利用漏洞清單，"
                   "未經認證的攻擊者可遠端執行程式碼，目前正被野外積極利用，修補已釋出。",
        "answer": {
            "threat_level": "CRITICAL",
            "cve_ids": ["CVE-2024-12345"],
            "affected_products": ["Microsoft Exchange Server", "Microsoft"],
            "action_summary": "立即套用 Exchange 修補並檢查入侵跡象",
        },
    },
    {
        "title": "OpenSSL 釋出例行維護更新",
        "content": "OpenSSL 釋出 3.0.13，包含小型臭蟲修正與一個低嚴重度安全修補，"
                   "需攻擊者同時控制 TLS 連線兩端才能觸發，目前無野外利用。",
        "answer": {
            "threat_level": "LOW",
            "cve_ids": ["CVE-2024-45678"],
            "affected_products": ["OpenSSL"],
            "action_summary": "於常規維護週期更新 OpenSSL 即可",
        },
    },
    {
        "title": "Verizon 發布 2024 年資料外洩調查報告 DBIR",
        "content": "Verizon 公布年度報告，分析全球逾萬起資安事件，指出勒索軟體與供應鏈攻擊"
                   "持續成長。屬產業趨勢分析，無具體漏洞披露。",
        "answer": {
            "threat_level": "INFO",
            "cve_ids": [],
            "affected_products": [],
            "action_summary": "參考報告趨勢，無需立即處置",
        },
    },
]


def _build_messages(title: str, content: str) -> list[dict]:
    """
    Build the chat messages for one analysis: the few-shot exemplars as
    user/assistant pairs, then the real item as the final user turn. Content
    is truncated to 800 chars (matches what the eval scored).
    """
    messages = []
    for ex in FEWSHOT_EXAMPLES:
        messages.append({
            "role": "user",
            "content": ANALYSIS_PROMPT.format(title=ex["title"], content=ex["content"][:800]),
        })
        messages.append({
            "role": "assistant",
            "content": json.dumps(ex["answer"], ensure_ascii=False),
        })
    messages.append({
        "role": "user",
        "content": ANALYSIS_PROMPT.format(title=title, content=content[:800]),
    })
    return messages


def _chat_json(messages: list[dict]) -> dict:
    """
    Send chat messages to the configured LLM backend and return the parsed JSON.

    Two backends, selected by config.LLM_PROVIDER:
      - "ollama" (default): local Ollama /api/chat with format=json.
      - "openai": any OpenAI-compatible /chat/completions endpoint (OpenAI,
        Groq, OpenRouter, Together, ... or `ollama serve`'s own /v1), so
        teammates without a local GPU can point at a hosted API instead.

    Both ask the model to constrain output to a JSON object. Raises on HTTP
    error or unparseable content (the caller's retry budget then applies).
    """
    if LLM_PROVIDER == "openai":
        resp = requests.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": OPENAI_MODEL,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 300,
                "response_format": {"type": "json_object"},  # JSON mode
            },
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        return json.loads(resp.json()["choices"][0]["message"]["content"])

    # default: local Ollama
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "format": "json",  # Ollama constrains output to valid JSON
            "options": {"num_predict": 300, "temperature": 0.1},
        },
        timeout=OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    return json.loads(resp.json()["message"]["content"])


def analyze_single(news_id: int, title: str, content: str) -> bool:
    """
    Call the configured LLM backend to analyze a single news item.
    Update DB with results.
    Return True on success.
    """
    try:
        result = _chat_json(_build_messages(title, content))

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
