"""
Gradio dashboard with three tabs:
1. 威脅雷達  - scrollable news cards with color-coded threat levels
2. GitHub 掃描 - input repo URL, show matched vulnerabilities
3. 系統狀態  - stats and manual refresh button

Run with: python main.py
"""

import json
import gradio as gr
from database.db import get_recent_news, get_stats
from github_scanner.scanner import scan_repo
from pipeline import run_crawl_cycle
from config import LEVEL_COLORS, THREAT_LEVELS


# -- Helper: render a single news card as HTML --

def render_news_card(item: dict) -> str:
    level = item.get("threat_level", "INFO")
    color = LEVEL_COLORS.get(level, "#888888")

    cves = []
    try:
        cves = json.loads(item.get("cve_ids") or "[]")
    except Exception:
        pass

    action = item.get("action_summary", "")
    title  = item.get("title", "")
    url    = item.get("url", "#")
    source = item.get("source", "")

    cve_html = ""
    if cves:
        cve_html = " ".join(
            f'<span style="background:#f0f0f0;padding:1px 6px;border-radius:4px;font-size:11px">{c}</span>'
            for c in cves[:3]
        )

    return f"""
<div style="border-left:4px solid {color};padding:10px 14px;margin-bottom:8px;
            background:white;border-radius:0 8px 8px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)">
  <div style="display:flex;justify-content:space-between;margin-bottom:4px">
    <span style="background:{color};color:white;padding:2px 8px;border-radius:12px;
                 font-size:11px;font-weight:600">{level}</span>
    <span style="font-size:11px;color:#888">{source}</span>
  </div>
  <a href="{url}" target="_blank"
     style="font-size:13px;font-weight:500;color:#1a1a1a;text-decoration:none">
    {title[:120]}
  </a>
  <div style="margin-top:6px;font-size:12px;color:#555">{action}</div>
  {f'<div style="margin-top:5px">{cve_html}</div>' if cve_html else ''}
</div>
"""


# -- Tab 1: 威脅雷達 --

def build_news_html(level_filter: str) -> str:
    filter_val = None if level_filter == "全部" else level_filter
    news = get_recent_news(limit=80, level_filter=filter_val)
    if not news:
        return "<p style='color:#888;text-align:center;padding:40px'>尚無資料，請先點擊「立即爬取」</p>"
    return "".join(render_news_card(item) for item in news)


# -- Tab 2: GitHub 掃描 --

def run_github_scan(repo_url: str) -> str:
    if not repo_url.strip():
        return "<p style='color:#888'>請輸入 GitHub repo URL</p>"

    result = scan_repo(repo_url.strip())

    if result.get("error"):
        return f"<p style='color:#E24B4A'>⚠ {result['error']}</p>"

    matches = result.get("matches", [])
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
               font-size:11px'>{m.get('threat_level','INFO')}</span>
  <strong style='margin-left:8px'>{m['dep_name']}</strong><br>
  <span style='font-size:12px;color:#555'>{m['news_title'][:100]}</span><br>
  <span style='font-size:12px;color:#333'>建議：{m.get('action_summary','')}</span>
</div>""")

    return f"""
<div style='padding:8px;background:#fff3e0;border-radius:8px;margin-bottom:12px'>
  ⚠ 在 {deps_found} 個依賴中發現 <strong>{len(matches)}</strong> 個潛在漏洞
</div>
{''.join(cards)}"""


# -- Tab 3: 系統狀態 --

def get_status_html() -> str:
    stats = get_stats()
    total = sum(stats.values())
    rows = ""
    for level in THREAT_LEVELS:
        count = stats.get(level, 0)
        color = LEVEL_COLORS[level]
        rows += f"""
<div style='display:flex;justify-content:space-between;padding:6px 10px;
            border-left:3px solid {color};margin-bottom:4px;background:white;border-radius:0 6px 6px 0'>
  <span style='font-weight:500'>{level}</span>
  <span style='color:{color};font-weight:600'>{count}</span>
</div>"""
    return f"""
<div style='margin-bottom:12px;font-size:13px;color:#555'>資料庫共 <strong>{total}</strong> 筆威脅情報</div>
{rows}"""


# -- Manual crawl trigger --

def manual_crawl() -> str:
    _, msg = run_crawl_cycle()
    return msg


# -- Build Gradio app --

def create_app() -> gr.Blocks:
    with gr.Blocks(title="資安新聞威脅雷達", theme=gr.themes.Soft()) as app:

        gr.Markdown("# 🛡 資安新聞即時威脅雷達")

        with gr.Tabs():

            # Tab 1
            with gr.Tab("📡 威脅雷達"):
                with gr.Row():
                    level_dropdown = gr.Dropdown(
                        choices=["全部"] + THREAT_LEVELS,
                        value="全部",
                        label="威脅等級篩選",
                        scale=2,
                    )
                    refresh_btn = gr.Button("🔄 重新整理", scale=1)
                    crawl_btn   = gr.Button("⬇ 立即爬取", variant="primary", scale=1)

                crawl_status = gr.Textbox(label="爬取狀態", visible=True, interactive=False)
                news_html    = gr.HTML(value=build_news_html("全部"))

                refresh_btn.click(fn=build_news_html, inputs=level_dropdown, outputs=news_html)
                level_dropdown.change(fn=build_news_html, inputs=level_dropdown, outputs=news_html)
                crawl_btn.click(fn=manual_crawl, outputs=crawl_status).then(
                    fn=build_news_html, inputs=level_dropdown, outputs=news_html
                )

            # Tab 2
            with gr.Tab("🔍 GitHub 掃描"):
                gr.Markdown("輸入 GitHub repo URL，系統自動比對依賴套件是否有已知漏洞")
                repo_input = gr.Textbox(
                    placeholder="https://github.com/owner/repo",
                    label="GitHub Repo URL",
                )
                scan_btn    = gr.Button("開始掃描", variant="primary")
                scan_result = gr.HTML()
                scan_btn.click(fn=run_github_scan, inputs=repo_input, outputs=scan_result)

            # Tab 3
            with gr.Tab("📊 系統狀態"):
                stats_btn  = gr.Button("刷新統計")
                stats_html = gr.HTML(value=get_status_html())
                stats_btn.click(fn=get_status_html, outputs=stats_html)

    return app


def launch():
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=7860, share=False)
