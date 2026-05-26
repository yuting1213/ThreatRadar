"""
Gradio dashboard — C 部分：Dashboard / UX 改善
================================================
改善重點：
  1. 威脅雷達加搜尋框（標題 / CVE-ID / 行動建議全文搜尋）
  2. 多排序：威脅等級 / 發布時間 / 來源
  3. 新分頁「掃描歷史」：讀取 github_scans 表，顯示歷史記錄
  4. 單篇 re-analyze：下拉選單選標題 → 重設 analysis_done=0
  5. Dark mode toggle（JS 注入 + custom CSS）
  6. 威脅等級分布橫條圖（系統狀態頁）
  7. Responsive CSS（手機裝置適配）
"""

import json
import gradio as gr

from database.db import (
    get_recent_news,
    get_stats,
    get_scan_history,
    reset_analysis,
    get_analyzed_news_for_dropdown,
)
from github_scanner.scanner import scan_repo
from pipeline import run_crawl_cycle
from config import LEVEL_COLORS, THREAT_LEVELS


# ── CSS ────────────────────────────────────────────────────────────────────────

CUSTOM_CSS = """
/* ===== Dark Mode ===== */
body.dark-mode .gradio-container,
body.dark-mode .main,
body.dark-mode .wrap,
body.dark-mode .block {
    background: #0d1117 !important;
    color: #c9d1d9 !important;
}
body.dark-mode .prose,
body.dark-mode label,
body.dark-mode .label-wrap span,
body.dark-mode p {
    color: #c9d1d9 !important;
}
body.dark-mode input,
body.dark-mode select,
body.dark-mode textarea {
    background: #161b22 !important;
    color: #c9d1d9 !important;
    border-color: #30363d !important;
}
body.dark-mode .tab-nav button {
    background: #161b22 !important;
    color: #8b949e !important;
    border-color: #30363d !important;
}
body.dark-mode .tab-nav button.selected {
    background: #1f6feb !important;
    color: #ffffff !important;
}
body.dark-mode .news-card {
    background: #161b22 !important;
    box-shadow: 0 1px 4px rgba(0,0,0,.5) !important;
}
body.dark-mode .news-card a {
    color: #58a6ff !important;
}
body.dark-mode .news-card .card-action {
    color: #8b949e !important;
}
body.dark-mode .scan-card {
    background: #161b22 !important;
    border-color: #30363d !important;
}

/* ===== Responsive ===== */
@media (max-width: 640px) {
    .gr-button { font-size: 12px !important; padding: 5px 8px !important; }
    .card-header { flex-direction: column !important; gap: 4px !important; }
}

/* ===== Threat level bar chart ===== */
.level-bar-wrap {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 5px 0;
}
.level-bar-label {
    width: 72px;
    font-size: 12px;
    font-weight: 700;
    flex-shrink: 0;
}
.level-bar-track {
    flex: 1;
    background: #e8e8e8;
    border-radius: 6px;
    height: 14px;
    overflow: hidden;
}
.level-bar-fill {
    height: 100%;
    border-radius: 6px;
    transition: width .5s ease;
}
.level-bar-count {
    width: 32px;
    font-size: 12px;
    text-align: right;
    flex-shrink: 0;
}
"""

# ── JavaScript for dark mode ───────────────────────────────────────────────────

# Runs when the dark-mode toggle button is clicked (no Python roundtrip needed)
DARK_TOGGLE_JS = """
() => {
    const isDark = document.body.classList.toggle('dark-mode');
    localStorage.setItem('threatRadarDark', String(isDark));
    return [];
}
"""

# Runs once on page load to restore preference
RESTORE_DARK_JS = """
() => {
    if (localStorage.getItem('threatRadarDark') === 'true') {
        document.body.classList.add('dark-mode');
    }
    return [];
}
"""

# ── Threat level visual score (5 filled squares) ──────────────────────────────

_SCORE = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _threat_meter(level: str) -> str:
    """Render a compact 5-segment SVG threat meter to embed in each news card."""
    score = _SCORE.get(level, 1)
    color = LEVEL_COLORS.get(level, "#888")
    segs = "".join(
        f'<rect x="{i * 13}" y="0" width="10" height="10" rx="2" '
        f'fill="{color if i < score else "#e0e0e0"}"/>'
        for i in range(5)
    )
    return (
        f'<svg width="70" height="10" style="vertical-align:middle;margin-left:6px">'
        f"{segs}</svg>"
    )


# ── News card renderer ─────────────────────────────────────────────────────────

def render_news_card(item: dict) -> str:
    level  = item.get("threat_level", "INFO")
    color  = LEVEL_COLORS.get(level, "#888888")
    title  = item.get("title", "（無標題）")
    url    = item.get("url", "#")
    source = item.get("source", "")
    action = item.get("action_summary", "")
    pub    = (item.get("published") or item.get("created_at", ""))[:10]
    meter  = _threat_meter(level)

    cves: list = []
    try:
        cves = json.loads(item.get("cve_ids") or "[]")
    except Exception:
        pass

    cve_html = (
        " ".join(
            f'<span style="background:#f0f0f0;padding:1px 7px;border-radius:4px;'
            f'font-size:11px;color:#333">{c}</span>'
            for c in cves[:5]
        )
        if cves
        else ""
    )

    return f"""
<div class="news-card" style="border-left:4px solid {color};padding:10px 14px;
     margin-bottom:8px;background:white;border-radius:0 8px 8px 0;
     box-shadow:0 1px 3px rgba(0,0,0,.06)">
  <div class="card-header" style="display:flex;justify-content:space-between;
       align-items:center;margin-bottom:4px">
    <div style="display:flex;align-items:center">
      <span style="background:{color};color:white;padding:2px 9px;border-radius:12px;
                   font-size:11px;font-weight:700">{level}</span>
      {meter}
    </div>
    <span style="font-size:11px;color:#888">{source} · {pub}</span>
  </div>
  <a href="{url}" target="_blank"
     style="font-size:13px;font-weight:500;color:#1a1a1a;text-decoration:none">
    {title[:120]}
  </a>
  <div class="card-action" style="margin-top:6px;font-size:12px;color:#555">{action}</div>
  {f'<div style="margin-top:5px">{cve_html}</div>' if cve_html else ''}
</div>
"""


# ── Tab 1: 威脅雷達 ───────────────────────────────────────────────────────────

_SORT_MAP = {"威脅等級": "threat_level", "發布時間": "published", "來源": "source"}


def build_news_html(level_filter: str, search_query: str, sort_by: str) -> str:
    filter_val = None if level_filter == "全部" else level_filter
    sort_key   = _SORT_MAP.get(sort_by, "threat_level")
    news = get_recent_news(
        limit=80,
        level_filter=filter_val,
        search_query=search_query or None,
        sort_by=sort_key,
    )
    if not news:
        msg = (
            "尚無符合條件的資料，請調整搜尋條件"
            if (filter_val or search_query)
            else "尚無資料，請先點擊「立即爬取」"
        )
        return f"<p style='color:#888;text-align:center;padding:40px'>{msg}</p>"
    return "".join(render_news_card(item) for item in news)


def do_reanalyze(selected_value) -> str:
    """Reset the analysis state of one news item."""
    if selected_value is None:
        return "⚠ 請先從下拉選單選擇一篇新聞"
    try:
        news_id = int(selected_value)
        reset_analysis(news_id)
        return (
            f"✅ 已重設 news ID={news_id} 的分析狀態，"
            "下次爬取週期（或手動點「立即爬取」）將重新分析"
        )
    except Exception as e:
        return f"❌ 操作失敗：{e}"


def refresh_reanalyze_choices():
    """Reload dropdown choices after a crawl or manual request."""
    return gr.Dropdown(choices=get_analyzed_news_for_dropdown(), value=None)


def manual_crawl() -> str:
    _, msg = run_crawl_cycle()
    return msg


# ── Tab 2: GitHub 掃描 ────────────────────────────────────────────────────────

def run_github_scan(repo_url: str) -> str:
    if not repo_url.strip():
        return "<p style='color:#888'>請輸入 GitHub repo URL</p>"

    result     = scan_repo(repo_url.strip())
    if result.get("error"):
        return f"<p style='color:#E24B4A'>⚠ {result['error']}</p>"

    matches    = result.get("matches", [])
    deps_found = result.get("deps_found", 0)

    if not matches:
        return f"""
<div style='padding:12px;background:#e8f5e9;border-radius:8px'>
  <strong>✅ 未發現已知漏洞</strong><br>
  掃描了 {deps_found} 個依賴套件，與目前資料庫中的漏洞無匹配。
</div>"""

    cards = []
    for m in matches:
        color = LEVEL_COLORS.get(m.get("threat_level", "INFO"), "#888")
        cards.append(f"""
<div style='border-left:4px solid {color};padding:10px 14px;margin-bottom:8px;
     background:white;border-radius:0 8px 8px 0'>
  <span style='background:{color};color:white;padding:1px 7px;border-radius:10px;
               font-size:11px'>{m.get("threat_level","INFO")}</span>
  <strong style='margin-left:8px'>{m["dep_name"]}</strong><br>
  <span style='font-size:12px;color:#555'>{m["news_title"][:100]}</span><br>
  <span style='font-size:12px;color:#333'>建議：{m.get("action_summary","")}</span>
</div>""")

    return f"""
<div style='padding:8px;background:#fff3e0;border-radius:8px;margin-bottom:12px'>
  ⚠ 在 {deps_found} 個依賴中發現 <strong>{len(matches)}</strong> 個潛在漏洞
</div>
{"".join(cards)}"""


# ── Tab 3: 掃描歷史 (新分頁) ──────────────────────────────────────────────────

def build_scan_history_html() -> str:
    records = get_scan_history(limit=50)
    if not records:
        return (
            "<p style='color:#888;text-align:center;padding:40px'>"
            "尚無掃描歷史記錄，請先在「GitHub 掃描」分頁掃描一個 repo</p>"
        )

    cards = []
    for r in records:
        deps: list    = []
        matches: list = []
        try:
            deps = json.loads(r.get("dependencies") or "[]")
        except Exception:
            pass
        try:
            matches = json.loads(r.get("matched_cves") or "[]")
        except Exception:
            pass

        dep_count  = len(deps)
        hit_count  = len(matches)
        status_col = "#E24B4A" if hit_count > 0 else "#44BB44"
        status_txt = f"⚠ {hit_count} 個漏洞命中" if hit_count > 0 else "✅ 無漏洞命中"
        ts         = (r.get("scanned_at") or "")[:16].replace("T", " ")

        matched_names = list(
            {m.get("dep_name", "") for m in matches if m.get("dep_name")}
        )[:6]
        matched_chips = " ".join(
            f'<span style="background:#fff3e0;padding:1px 7px;border-radius:4px;'
            f'font-size:11px;color:#b45309">{d}</span>'
            for d in matched_names
        )

        repo_display = r["repo_url"].replace("https://github.com/", "")

        cards.append(f"""
<div class="scan-card" style='border:1px solid #e0e0e0;padding:12px 16px;
     margin-bottom:8px;border-radius:8px;background:white;
     box-shadow:0 1px 3px rgba(0,0,0,.05)'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>
    <a href='{r["repo_url"]}' target='_blank'
       style='font-size:13px;font-weight:600;color:#1a1a1a;text-decoration:none'>
      ⬡ {repo_display}
    </a>
    <span style='font-size:11px;color:#888'>{ts}</span>
  </div>
  <div style='display:flex;gap:14px;align-items:center'>
    <span style='font-size:12px;color:{status_col};font-weight:600'>{status_txt}</span>
    <span style='font-size:12px;color:#888'>掃描了 {dep_count} 個依賴</span>
  </div>
  {f'<div style="margin-top:6px">{matched_chips}</div>' if matched_chips else ''}
</div>""")

    return "".join(cards)


# ── Tab 4: 系統狀態 ───────────────────────────────────────────────────────────

def get_status_html() -> str:
    stats = get_stats()
    total = sum(stats.values())

    if total == 0:
        return "<p style='color:#888;padding:20px;text-align:center'>資料庫尚無已分析的資料</p>"

    bars = ""
    for level in THREAT_LEVELS:
        count = stats.get(level, 0)
        pct   = round(count / total * 100) if total else 0
        color = LEVEL_COLORS[level]
        bars += f"""
<div class="level-bar-wrap">
  <span class="level-bar-label" style="color:{color}">{level}</span>
  <div class="level-bar-track">
    <div class="level-bar-fill" style="width:{pct}%;background:{color}"></div>
  </div>
  <span class="level-bar-count" style="color:#555">{count}</span>
</div>"""

    return f"""
<div style='margin-bottom:14px;font-size:13px;color:#555'>
  資料庫共 <strong>{total}</strong> 筆已分析威脅情報
</div>
{bars}
<p style='font-size:11px;color:#aaa;margin-top:10px'>
  條形長度代表各等級佔比；數字為絕對筆數
</p>"""


# ── Gradio app builder ─────────────────────────────────────────────────────────

def create_app() -> gr.Blocks:
    with gr.Blocks(
        css=CUSTOM_CSS,
        title="資安新聞威脅雷達",
        theme=gr.themes.Soft(),
    ) as app:

        # ── Header row（含 dark mode 切換）
        with gr.Row():
            gr.Markdown(
                "# 🛡 資安新聞即時威脅雷達\n"
                "*Security News Threat Radar — 讓 AI 替你讀資安新聞*",
                scale=5,
            )
            dark_btn = gr.Button("🌙 深色模式", scale=0, min_width=120)

        dark_btn.click(fn=None, js=DARK_TOGGLE_JS)
        app.load(fn=None, js=RESTORE_DARK_JS)

        with gr.Tabs():

            # ══ Tab 1: 威脅雷達 ══════════════════════════════════════════════
            with gr.Tab("📡 威脅雷達"):

                with gr.Row():
                    search_box = gr.Textbox(
                        placeholder="🔍 搜尋標題、CVE-ID（如 CVE-2024-1234）、行動建議…",
                        label="全文搜尋",
                        scale=4,
                    )
                    level_dd = gr.Dropdown(
                        choices=["全部"] + THREAT_LEVELS,
                        value="全部",
                        label="威脅等級篩選",
                        scale=2,
                    )
                    sort_dd = gr.Dropdown(
                        choices=["威脅等級", "發布時間", "來源"],
                        value="威脅等級",
                        label="排序方式",
                        scale=2,
                    )

                with gr.Row():
                    refresh_btn = gr.Button("🔄 重新整理", scale=1)
                    crawl_btn   = gr.Button("⬇ 立即爬取", variant="primary", scale=1)

                crawl_status = gr.Textbox(
                    label="爬取狀態", interactive=False, visible=True
                )
                news_html = gr.HTML(value=build_news_html("全部", "", "威脅等級"))

                gr.Markdown("---\n#### 🔁 重新分析單篇新聞")
                with gr.Row():
                    reanalyze_dd = gr.Dropdown(
                        choices=get_analyzed_news_for_dropdown(),
                        label="選擇要重新分析的新聞（下拉選標題）",
                        scale=5,
                        interactive=True,
                    )
                    reanalyze_btn     = gr.Button("重新分析", variant="primary", scale=1)
                    reanalyze_ref_btn = gr.Button("🔄", scale=0, min_width=44)

                reanalyze_status = gr.Textbox(label="操作狀態", interactive=False)

                # ── 事件連接（所有元件都已宣告後才綁定）──────────────────────
                _news_ins = [level_dd, search_box, sort_dd]
                refresh_btn.click(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                level_dd.change(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                sort_dd.change(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                search_box.submit(fn=build_news_html, inputs=_news_ins, outputs=news_html)

                # 爬取完成後依序：更新狀態列 → 重整新聞卡片 → 更新 re-analyze 下拉
                # 單一 .then() 鏈確保順序執行，dropdown 一定在 crawl 結束後才刷新
                crawl_btn.click(fn=manual_crawl, outputs=crawl_status).then(
                    fn=build_news_html, inputs=_news_ins, outputs=news_html
                ).then(
                    fn=refresh_reanalyze_choices, outputs=reanalyze_dd
                )

                reanalyze_btn.click(
                    fn=do_reanalyze,
                    inputs=reanalyze_dd,
                    outputs=reanalyze_status,
                )
                reanalyze_ref_btn.click(
                    fn=refresh_reanalyze_choices,
                    outputs=reanalyze_dd,
                )

            # ══ Tab 2: GitHub 掃描 ═══════════════════════════════════════════
            with gr.Tab("🔍 GitHub 掃描"):
                gr.Markdown("輸入 GitHub repo URL，系統自動比對依賴套件是否有已知漏洞")
                repo_input = gr.Textbox(
                    placeholder="https://github.com/owner/repo",
                    label="GitHub Repo URL",
                )
                scan_btn    = gr.Button("開始掃描", variant="primary")
                scan_result = gr.HTML()
                scan_btn.click(fn=run_github_scan, inputs=repo_input, outputs=scan_result)

            # ══ Tab 3: 掃描歷史 ══════════════════════════════════════════════
            with gr.Tab("📋 掃描歷史"):
                gr.Markdown(
                    "過去所有 GitHub repo 的掃描紀錄（讀取 `github_scans` 表，最新在前）"
                )
                history_ref_btn = gr.Button("🔄 重新整理")
                history_html    = gr.HTML(value=build_scan_history_html())
                history_ref_btn.click(fn=build_scan_history_html, outputs=history_html)

            # ══ Tab 4: 系統狀態 ════