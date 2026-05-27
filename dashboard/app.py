"""
Gradio dashboard — C module: Dashboard / UX
============================================
Features:
  1. Full-text search (title / CVE-ID / product / action) with result count
  2. Multi-sort: threat level / published time / source / CVSS score
  3. CVE-only filter toggle
  4. Clickable CVE chips linking to NVD
  5. CVSS score badge per card (when available)
  6. Threat-level SVG meter per card
  7. Scan history tab with expandable match details + max threat level
  8. Immediate re-analysis (lock-protected, calls Ollama synchronously)
  9. Dark mode toggle (pure JS + localStorage)
 10. Enhanced system status: Ollama health, unanalyzed/failed counts, DB stats
 11. Responsive CSS for mobile
"""

import html
import json
import requests as _req
import gradio as gr

from database.db import (
    get_recent_news,
    get_stats,
    get_enhanced_stats,
    get_scan_history,
    reset_analysis,
    get_analyzed_news_for_dropdown,
    get_news_by_id,
)
from github_scanner.scanner import scan_repo
from pipeline import run_crawl_cycle, reanalyze_one
from config import LEVEL_COLORS, THREAT_LEVELS, OLLAMA_BASE_URL, OLLAMA_MODEL


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
body.dark-mode .news-card a { color: #58a6ff !important; }
body.dark-mode .news-card .card-action { color: #8b949e !important; }
body.dark-mode .scan-card {
    background: #161b22 !important;
    border-color: #30363d !important;
}
body.dark-mode details summary { color: #58a6ff !important; }
body.dark-mode .stat-row { border-color: #30363d !important; }

/* ===== Responsive ===== */
@media (max-width: 640px) {
    .gr-button { font-size: 12px !important; padding: 5px 8px !important; }
    .card-header { flex-direction: column !important; gap: 4px !important; }
}

/* ===== Threat level bar chart ===== */
.level-bar-wrap { display:flex; align-items:center; gap:10px; margin:5px 0; }
.level-bar-label { width:72px; font-size:12px; font-weight:700; flex-shrink:0; }
.level-bar-track { flex:1; background:#e8e8e8; border-radius:6px; height:14px; overflow:hidden; }
.level-bar-fill  { height:100%; border-radius:6px; transition:width .5s ease; }
.level-bar-count { width:32px; font-size:12px; text-align:right; flex-shrink:0; }

/* ===== Stat rows ===== */
.stat-row {
    display:flex; justify-content:space-between; padding:6px 10px;
    border-left:3px solid #ccc; margin-bottom:4px;
    background:white; border-radius:0 6px 6px 0;
}

/* ===== Scan history expand ===== */
details { margin-top:6px; }
details summary {
    cursor:pointer; font-size:12px; color:#1f6feb;
    list-style:none; user-select:none;
}
details summary::before { content:"▶ "; font-size:10px; }
details[open] summary::before { content:"▼ "; }
details table { width:100%; border-collapse:collapse; margin-top:6px; font-size:12px; }
details th { background:#f5f5f5; padding:4px 8px; text-align:left; }
details td { padding:4px 8px; border-top:1px solid #eee; }
"""

# ── JavaScript for dark mode ───────────────────────────────────────────────────

DARK_TOGGLE_JS = """
() => {
    const isDark = document.body.classList.toggle('dark-mode');
    localStorage.setItem('threatRadarDark', String(isDark));
    return [];
}
"""

RESTORE_DARK_JS = """
() => {
    if (localStorage.getItem('threatRadarDark') === 'true') {
        document.body.classList.add('dark-mode');
    }
    return [];
}
"""

# ── Constants ──────────────────────────────────────────────────────────────────

_SCORE = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_SORT_MAP = {
    "威脅等級":      "threat_level",
    "發布時間":      "published",
    "來源":          "source",
    "CVSS 分數":     "cvss_score",
}
_LEVEL_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _safe_url(url: str) -> str:
    """Allow only http/https URLs; replace anything else with '#' to prevent XSS."""
    if url and url.startswith(("http://", "https://")):
        return url
    return "#"


# ── Helper: SVG threat meter ───────────────────────────────────────────────────

def _threat_meter(level: str) -> str:
    score = _SCORE.get(level, 1)
    color = LEVEL_COLORS.get(level, "#888")
    segs = "".join(
        f'<rect x="{i*13}" y="0" width="10" height="10" rx="2" '
        f'fill="{color if i < score else "#e0e0e0"}"/>'
        for i in range(5)
    )
    return (
        f'<svg width="70" height="10" style="vertical-align:middle;margin-left:6px">'
        f"{segs}</svg>"
    )


# ── Helper: CVSS badge ────────────────────────────────────────────────────────

def _cvss_badge(score) -> str:
    if score is None:
        return ""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 9.0:
        color = "#FF4444"
    elif s >= 7.0:
        color = "#FF8800"
    elif s >= 4.0:
        color = "#FFCC00"
    else:
        color = "#44BB44"
    return (
        f'<span style="background:{color};color:white;padding:1px 7px;'
        f'border-radius:4px;font-size:11px;font-weight:700;margin-left:6px">'
        f"CVSS {s:.1f}</span>"
    )


# ── News card renderer ─────────────────────────────────────────────────────────

def render_news_card(item: dict) -> str:
    level  = item.get("threat_level", "INFO")
    color  = LEVEL_COLORS.get(level, "#888888")
    title  = html.escape(item.get("title", "(no title)"))
    url    = _safe_url(item.get("url", "#"))
    source = html.escape(item.get("source", ""))
    action = html.escape(item.get("action_summary", ""))
    pub    = html.escape((item.get("published") or item.get("created_at", ""))[:10])
    meter  = _threat_meter(level)
    cvss   = _cvss_badge(item.get("cvss_score"))

    cves: list = []
    try:
        cves = json.loads(item.get("cve_ids") or "[]")
    except Exception:
        pass

    # Clickable CVE chips → NVD link (CVE IDs are alphanumeric so escaping is safe)
    cve_html = " ".join(
        f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(str(c))}" target="_blank" '
        f'style="background:#f0f0f0;padding:1px 7px;border-radius:4px;'
        f'font-size:11px;color:#1f6feb;text-decoration:none">{html.escape(str(c))}</a>'
        for c in cves[:5]
    ) if cves else ""

    return f"""
<div class="news-card" style="border-left:4px solid {color};padding:10px 14px;
     margin-bottom:8px;background:white;border-radius:0 8px 8px 0;
     box-shadow:0 1px 3px rgba(0,0,0,.06)">
  <div class="card-header" style="display:flex;justify-content:space-between;
       align-items:center;margin-bottom:4px">
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px">
      <span style="background:{color};color:white;padding:2px 9px;border-radius:12px;
                   font-size:11px;font-weight:700">{html.escape(level)}</span>
      {meter}{cvss}
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

def build_news_html(
    level_filter: str,
    search_query: str,
    sort_by: str,
    cve_only: bool,
) -> str:
    filter_val = None if level_filter == "全部" else level_filter
    sort_key   = _SORT_MAP.get(sort_by, "threat_level")
    news = get_recent_news(
        limit=80,
        level_filter=filter_val,
        search_query=search_query or None,
        sort_by=sort_key,
        cve_only=cve_only,
    )
    if not news:
        hint = "請嘗試 CVE-ID（如 CVE-2024-1234）、產品名稱或來源網站名"
        active = filter_val or search_query or cve_only
        msg = f"找不到符合條件的資料 — {hint}" if active else "尚無資料，請先點擊「立即爬取」"
        return f"<p style='color:#888;text-align:center;padding:40px'>{msg}</p>"

    count_bar = (
        f"<p style='font-size:12px;color:#888;margin-bottom:8px'>"
        f"共找到 <strong>{len(news)}</strong> 筆</p>"
    )
    return count_bar + "".join(render_news_card(item) for item in news)


# ── Tab 1: re-analyze ─────────────────────────────────────────────────────────

def do_reanalyze(selected_value) -> tuple[str, str]:
    """Immediately re-analyze one item via pipeline.reanalyze_one()."""
    if selected_value is None:
        return "⚠ 請先從下拉選單選擇一篇新聞", ""
    try:
        news_id = int(selected_value)
        ok, msg = reanalyze_one(news_id)
        return msg, ""          # second output clears the dropdown
    except Exception as e:
        return f"❌ 發生錯誤：{e}", ""


def refresh_reanalyze_choices():
    return gr.Dropdown(choices=get_analyzed_news_for_dropdown(), value=None)


def manual_crawl() -> str:
    _, msg = run_crawl_cycle()
    return msg


# ── Tab 2: GitHub scan ────────────────────────────────────────────────────────

def run_github_scan(repo_url: str) -> str:
    if not repo_url.strip():
        return "<p style='color:#888'>請輸入 GitHub repo URL</p>"

    result     = scan_repo(repo_url.strip())
    if result.get("error"):
        return f"<p style='color:#E24B4A'>⚠ {html.escape(str(result['error']))}</p>"

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
        m_level   = html.escape(m.get("threat_level", "INFO"))
        m_dep     = html.escape(str(m.get("dep_name", "")))
        m_title   = html.escape(str(m.get("news_title", ""))[:100])
        m_action  = html.escape(str(m.get("action_summary", "")))
        cards.append(f"""
<div style='border-left:4px solid {color};padding:10px 14px;margin-bottom:8px;
     background:white;border-radius:0 8px 8px 0'>
  <span style='background:{color};color:white;padding:1px 7px;border-radius:10px;
               font-size:11px'>{m_level}</span>
  <strong style='margin-left:8px'>{m_dep}</strong><br>
  <span style='font-size:12px;color:#555'>{m_title}</span><br>
  <span style='font-size:12px;color:#333'>建議：{m_action}</span>
</div>""")

    return f"""
<div style='padding:8px;background:#fff3e0;border-radius:8px;margin-bottom:12px'>
  ⚠ 在 {deps_found} 個依賴中發現 <strong>{len(matches)}</strong> 個潛在漏洞
</div>
{"".join(cards)}"""


# ── Tab 3: Scan history ───────────────────────────────────────────────────────

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
        ts         = html.escape((r.get("scanned_at") or "")[:16].replace("T", " "))
        repo_url   = _safe_url(r.get("repo_url", ""))
        repo_disp  = html.escape(r.get("repo_url", "").replace("https://github.com/", ""))

        # Compute max threat level among hits
        max_level  = None
        if matches:
            max_level = max(
                matches,
                key=lambda m: _LEVEL_ORDER.get(m.get("threat_level", "INFO"), 1),
            ).get("threat_level", "INFO")

        status_col  = LEVEL_COLORS.get(max_level, "#44BB44") if max_level else "#44BB44"
        status_txt  = (
            f'<span style="background:{status_col};color:white;padding:1px 7px;'
            f'border-radius:4px;font-size:11px;font-weight:700">{max_level}</span>'
            f' {hit_count} 個漏洞命中'
            if hit_count > 0
            else "✅ 無漏洞命中"
        )

        # Expandable match detail table
        detail_html = ""
        if matches:
            rows = "".join(
                f"<tr>"
                f"<td><code>{html.escape(str(m.get('dep_name','')))}</code></td>"
                f"<td><span style='background:{LEVEL_COLORS.get(m.get('threat_level','INFO'),'#888')};"
                f"color:white;padding:1px 5px;border-radius:3px;font-size:10px'>"
                f"{html.escape(str(m.get('threat_level','INFO')))}</span></td>"
                f"<td><a href='{_safe_url(m.get('url','#'))}' target='_blank' "
                f"style='color:#1f6feb;font-size:11px'>"
                f"{html.escape(str(m.get('news_title',''))[:60])}</a></td>"
                f"<td style='font-size:11px;color:#555'>"
                f"{html.escape(str(m.get('action_summary',''))[:40])}</td>"
                f"</tr>"
                for m in matches
            )
            detail_html = f"""
<details>
  <summary>查看命中套件詳情（{hit_count} 個）</summary>
  <table>
    <thead><tr><th>套件</th><th>等級</th><th>相關新聞</th><th>建議行動</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</details>"""

        cards.append(f"""
<div class="scan-card" style='border:1px solid #e0e0e0;padding:12px 16px;
     margin-bottom:8px;border-radius:8px;background:white;
     box-shadow:0 1px 3px rgba(0,0,0,.05)'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>
    <a href='{repo_url}' target='_blank'
       style='font-size:13px;font-weight:600;color:#1a1a1a;text-decoration:none'>
      ⬡ {repo_disp}
    </a>
    <span style='font-size:11px;color:#888'>{ts}</span>
  </div>
  <div style='display:flex;gap:14px;align-items:center;flex-wrap:wrap'>
    <span style='font-size:12px'>{status_txt}</span>
    <span style='font-size:12px;color:#888'>掃描了 {dep_count} 個依賴</span>
  </div>
  {detail_html}
</div>""")

    return "".join(cards)


# ── Tab 4: System status ──────────────────────────────────────────────────────

def _check_ollama() -> tuple[bool, str]:
    try:
        r = _req.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            if any(OLLAMA_MODEL in m for m in models):
                return True, f"✅ 已連線 · 模型 {OLLAMA_MODEL} 已載入"
            return True, (
                f"⚠ 已連線但找不到 {OLLAMA_MODEL} "
                f"（請執行 <code>ollama pull {OLLAMA_MODEL}</code>）"
            )
    except Exception:
        pass
    return False, f"❌ 無法連線至 {OLLAMA_BASE_URL}（確認 Ollama 是否在執行）"


def get_status_html() -> str:
    stats = get_enhanced_stats()
    total     = stats["total_analyzed"]
    by_level  = stats["by_level"]
    unanalyzed = stats["unanalyzed"]
    failed    = stats["failed"]
    scans     = stats["scan_count"]
    last_crawl = stats["last_crawl"] or "（尚無記錄）"

    ollama_ok, ollama_msg = _check_ollama()

    # Threat level bar chart
    bars = ""
    for level in THREAT_LEVELS:
        count = by_level.get(level, 0)
        pct   = round(count / total * 100) if total else 0
        color = LEVEL_COLORS[level]
        bars += f"""
<div class="level-bar-wrap">
  <span class="level-bar-label" style="color:{color}">{level}</span>
  <div class="level-bar-track">
    <div class="level-bar-fill" style="width:{pct}%;background:{color}"></div>
  </div>
  <span class="level-bar-count">{count}</span>
</div>"""

    def stat_row(label, value, color="#ccc"):
        return (
            f'<div class="stat-row" style="border-left-color:{color}">'
            f'<span style="font-size:13px">{label}</span>'
            f'<strong style="font-size:13px">{value}</strong></div>'
        )

    return f"""
<div style='display:grid;grid-template-columns:1fr 1fr;gap:16px'>
  <div>
    <p style='font-weight:600;margin-bottom:8px'>📊 新聞資料庫</p>
    {stat_row("已分析新聞", total, "#44BB44")}
    {stat_row("待分析", unanalyzed, "#FFCC00")}
    {stat_row("分析失敗", failed, "#E24B4A")}
    {stat_row("GitHub 掃描記錄", scans, "#888")}
    {stat_row("最近爬取時間", last_crawl, "#888")}
  </div>
  <div>
    <p style='font-weight:600;margin-bottom:8px'>⚙ 系統狀態</p>
    <div style='padding:8px 12px;border-radius:8px;font-size:13px;margin-bottom:12px;
         background:{"#e8f5e9" if ollama_ok else "#fce4ec"}'>{ollama_msg}</div>
    <p style='font-weight:600;margin-bottom:8px'>威脅等級分布</p>
    {bars}
  </div>
</div>
<p style='font-size:11px;color:#aaa;margin-top:12px'>
  CVSS 分數由 NVD crawler 填入 — 若欄位為空表示尚未整合
</p>"""


# ── Gradio app ────────────────────────────────────────────────────────────────

def create_app() -> gr.Blocks:
    with gr.Blocks(
        css=CUSTOM_CSS,
        title="ThreatRadar — Security News Dashboard",
        theme=gr.themes.Soft(),
    ) as app:

        # Header
        with gr.Row():
            gr.Markdown(
                "# 🛡 ThreatRadar\n"
                "*Security News Threat Intelligence Dashboard*",
                scale=5,
            )
            dark_btn = gr.Button("🌙 Dark Mode", scale=0, min_width=120)

        dark_btn.click(fn=None, js=DARK_TOGGLE_JS)
        app.load(fn=None, js=RESTORE_DARK_JS)

        with gr.Tabs():

            # ══ Tab 1: Threat Radar ══════════════════════════════════════════
            with gr.Tab("📡 威脅雷達"):

                with gr.Row():
                    search_box = gr.Textbox(
                        placeholder=(
                            "搜尋標題、CVE-ID（如 CVE-2024-1234）、"
                            "受影響產品或行動建議…"
                        ),
                        label="🔍 全文搜尋",
                        scale=4,
                    )
                    level_dd = gr.Dropdown(
                        choices=["全部"] + THREAT_LEVELS,
                        value="全部",
                        label="威脅等級篩選",
                        scale=2,
                    )
                    sort_dd = gr.Dropdown(
                        choices=list(_SORT_MAP.keys()),
                        value="威脅等級",
                        label="排序方式",
                        scale=2,
                    )

                cve_only_cb = gr.Checkbox(
                    label="只看有 CVE 編號的新聞",
                    value=False,
                )

                with gr.Row():
                    refresh_btn = gr.Button("🔄 重新整理", scale=1)
                    crawl_btn   = gr.Button("⬇ 立即爬取", variant="primary", scale=1)

                crawl_status = gr.Textbox(label="爬取狀態", interactive=False)
                news_html    = gr.HTML(
                    value=build_news_html("全部", "", "威脅等級", False)
                )

                # ── Re-analyze section ──────────────────────────────────────
                gr.Markdown("---\n#### 🔁 立即重新分析單篇新聞")
                gr.Markdown(
                    "<small>選擇一篇已分析的新聞，點擊後立即呼叫 Ollama 重新分析"
                    "（受全域 lock 保護，不會與排程器衝突）</small>",
                )
                with gr.Row():
                    reanalyze_dd = gr.Dropdown(
                        choices=get_analyzed_news_for_dropdown(),
                        label="選擇新聞（依威脅等級排序）",
                        scale=5,
                        interactive=True,
                    )
                    reanalyze_btn     = gr.Button("立即重新分析", variant="primary", scale=1)
                    reanalyze_ref_btn = gr.Button("🔄", scale=0, min_width=44)

                reanalyze_status = gr.Textbox(label="分析狀態", interactive=False)

                # ── Event wiring (all components declared above) ────────────
                _news_ins = [level_dd, search_box, sort_dd, cve_only_cb]

                refresh_btn.click(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                level_dd.change(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                sort_dd.change(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                search_box.submit(fn=build_news_html, inputs=_news_ins, outputs=news_html)
                cve_only_cb.change(fn=build_news_html, inputs=_news_ins, outputs=news_html)

                crawl_btn.click(fn=manual_crawl, outputs=crawl_status).then(
                    fn=build_news_html, inputs=_news_ins, outputs=news_html
                ).then(
                    fn=refresh_reanalyze_choices, outputs=reanalyze_dd
                )

                reanalyze_btn.click(
                    fn=do_reanalyze,
                    inputs=reanalyze_dd,
                    outputs=[reanalyze_status, reanalyze_dd],
                ).then(
                    fn=build_news_html, inputs=_news_ins, outputs=news_html
                ).then(
                    fn=refresh_reanalyze_choices, outputs=reanalyze_dd
                )
                reanalyze_ref_btn.click(
                    fn=refresh_reanalyze_choices, outputs=reanalyze_dd
                )

            # ══ Tab 2: GitHub Scan ═══════════════════════════════════════════
            with gr.Tab("🔍 GitHub 掃描"):
                gr.Markdown("輸入 GitHub repo URL，自動比對依賴套件是否有已知漏洞")
                repo_input  = gr.Textbox(
                    placeholder="https://github.com/owner/repo",
                    label="GitHub Repo URL",
                )
                scan_btn    = gr.Button("開始掃描", variant="primary")
                scan_result = gr.HTML()
                scan_btn.click(fn=run_github_scan, inputs=repo_input, outputs=scan_result)

            # ══ Tab 3: Scan History ═══════════════════════════════════════════
            with gr.Tab("📋 掃描歷史"):
                gr.Markdown(
                    "過去所有 GitHub repo 的掃描記錄（最新在前）。"
                    "點擊「查看命中套件詳情」可展開各筆漏洞資訊。"
                )
                history_ref_btn = gr.Button("🔄 重新整理")
                history_html    = gr.HTML(value=build_scan_history_html())
                history_ref_btn.click(fn=build_scan_history_html, outputs=history_html)

            # ══ Tab 4: System Status ══════════════════════════════════════════
            with gr.Tab("📊 系統狀態"):
                gr.Markdown("即時顯示資料庫統計、分析狀態與 Ollama 連線健康度。")
                stats_ref_btn = gr.Button("🔄 刷新統計")
                stats_html    = gr.HTML(value=get_status_html())
                stats_ref_btn.click(fn=get_status_html, outputs=stats_html)

    return app


def launch():
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=7860, share=False)
