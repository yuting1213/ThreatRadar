"""
Auto-generated threat briefing — a single self-contained HTML page summarizing
the current state of the radar: KPIs, threat-level and priority distributions,
the highest-priority items, CISA KEV hits, and top products/CVEs. Charts are
inline SVG (no JS/CDN) so the file opens anywhere and can be emailed as-is.

    from reporting.briefing import generate_briefing
    path = generate_briefing()          # writes outputs/threat_briefing_*.html
"""

import html as _html
from datetime import datetime
from pathlib import Path

import config
import database.db as db
from reporting import charts_svg as C

BAND_COLORS = {"CRITICAL": "#E24B4A", "HIGH": "#D85A30", "MEDIUM": "#EF9F27", "LOW": "#639922"}
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _esc(s):
    return _html.escape(str(s))


def _kpi(label, value, color="#1a1a1a"):
    return (f'<div class="kpi"><div class="kpi-l">{_esc(label)}</div>'
            f'<div class="kpi-v" style="color:{color}">{_esc(value)}</div></div>')


def _badge(text, color):
    return (f'<span style="background:{color};color:#fff;padding:1px 7px;border-radius:10px;'
            f'font-size:11px;font-weight:600">{_esc(text)}</span>')


def _safe_url(u):
    u = str(u or "")
    return u if u.startswith(("http://", "https://")) else "#"


def build_briefing_html() -> str:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    stats = db.get_enhanced_stats()
    pstats = db.get_priority_stats()
    by_level = stats.get("by_level", {})
    total = stats.get("total_analyzed", 0)

    top = db.get_recent_news(limit=10, sort_by="priority")
    kev = db.get_kev_news(limit=15)
    sources = db.get_source_breakdown()
    products = db.get_top_products(8)
    cves = db.get_top_cves(8)

    # KPI cards
    crit = by_level.get("CRITICAL", 0)
    kpis = (
        _kpi("已分析新聞", total) +
        _kpi("CRITICAL", crit, "#E24B4A") +
        _kpi("CISA KEV 命中", pstats.get("kev_hits", 0), "#9C27B0") +
        _kpi("高優先 (CRITICAL band)", pstats.get("by_band", {}).get("CRITICAL", 0), "#E24B4A")
    )

    # charts
    lvl_data = {lv: by_level.get(lv, 0) for lv in LEVEL_ORDER if by_level.get(lv, 0)}
    lvl_chart = C.bar_chart(lvl_data, color_map=C.LEVEL_COLORS, title="威脅等級分布") if lvl_data else ""
    band_data = {b: pstats.get("by_band", {}).get(b, 0) for b in BAND_ORDER
                 if pstats.get("by_band", {}).get(b, 0)}
    band_chart = C.bar_chart(band_data, color_map=BAND_COLORS, title="優先級分布") if band_data else ""
    src_chart = C.hbar_chart(dict(list(sources.items())[:6]), title="新聞來源") if sources else ""
    prod_chart = C.hbar_chart(dict(products), title="Top 受影響產品") if products else ""

    # top priority table
    rows = ""
    for it in top:
        ps = it.get("priority_score")
        if ps is None:
            continue
        band = it.get("priority_band") or "—"
        kev_b = _badge("KEV", "#9C27B0") if it.get("kev_hit") else ""
        epss = it.get("epss_score")
        epss_s = f"{epss*100:.0f}%" if epss is not None else "—"
        rows += (
            f'<tr><td><b>{ps:.0f}</b> {_badge(band, BAND_COLORS.get(band, "#888"))}</td>'
            f'<td>{_badge(_esc(it.get("threat_level","INFO")), C.LEVEL_COLORS.get(it.get("threat_level"),"#888"))} {kev_b}</td>'
            f'<td>{epss_s}</td>'
            f'<td><a href="{_safe_url(it.get("url"))}" target="_blank">{_esc(str(it.get("title",""))[:80])}</a>'
            f'<div class="act">{_esc(it.get("action_summary",""))}</div></td></tr>'
        )
    top_table = (f'<table><thead><tr><th>優先級</th><th>等級</th><th>EPSS</th>'
                 f'<th>新聞 / 建議</th></tr></thead><tbody>{rows}</tbody></table>'
                 if rows else '<p class="muted">尚無優先級資料（請先跑一次爬取 + enrichment）。</p>')

    # KEV section
    if kev:
        kev_rows = "".join(
            f'<li><a href="{_safe_url(k.get("url"))}" target="_blank">{_esc(str(k.get("title",""))[:90])}</a> '
            f'{_badge(k.get("priority_band","—"), BAND_COLORS.get(k.get("priority_band"),"#888"))}</li>'
            for k in kev
        )
        kev_html = f'<ul class="kev">{kev_rows}</ul>'
    else:
        kev_html = '<p class="muted">目前資料庫中沒有命中 CISA KEV 的項目。</p>'

    cve_html = ("、".join(f"{_esc(c)} ({n})" for c, n in cves)) if cves else "—"

    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>ThreatRadar 威脅簡報 {stamp}</title>
<style>
 body{{font-family:system-ui,"Noto Sans TC",sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1a1a1a}}
 h1{{font-size:22px;font-weight:600}} h2{{font-size:17px;font-weight:600;margin-top:26px}}
 .meta{{color:#777;font-size:13px}}
 .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}
 .kpi{{background:#f6f6f6;border-radius:8px;padding:12px}}
 .kpi-l{{font-size:12px;color:#777}} .kpi-v{{font-size:24px;font-weight:600}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}
 th,td{{border:1px solid #eee;padding:6px 9px;text-align:left;vertical-align:top}}
 th{{background:#f6f6f6}}
 .act{{color:#666;font-size:12px;margin-top:2px}}
 a{{color:#1f6feb;text-decoration:none}}
 ul.kev{{padding-left:18px}} ul.kev li{{margin:4px 0;font-size:13px}}
 .muted{{color:#999;font-size:13px}}
 .foot{{color:#aaa;font-size:11px;margin-top:24px;border-top:1px solid #eee;padding-top:8px}}
</style></head><body>
<h1>🛡 ThreatRadar — 威脅簡報</h1>
<p class="meta">產生時間 {stamp} · 已 enrichment {pstats.get('enriched',0)} 筆 · 資料來源：本地威脅雷達資料庫</p>
<div class="kpis">{kpis}</div>

<h2>分布總覽</h2>
<div class="grid2"><div>{lvl_chart}</div><div>{band_chart}</div></div>

<h2>最高優先處理項目</h2>
{top_table}

<h2>🔥 CISA KEV（確認遭利用）命中</h2>
{kev_html}

<h2>來源與受影響產品</h2>
<div class="grid2"><div>{src_chart}</div><div>{prod_chart}</div></div>

<h2>熱門 CVE</h2>
<p style="font-size:13px">{cve_html}</p>

<p class="foot">優先級分數 = LLM 威脅等級 + CVSS + EPSS + CISA KEV 綜合計算（0–100）。本報告由 ThreatRadar 自動產生。</p>
</body></html>"""


def generate_briefing(out_dir=None) -> Path:
    out_dir = Path(out_dir or config.OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    path = out_dir / f"threat_briefing_{stamp}.html"
    path.write_text(build_briefing_html(), encoding="utf-8")
    return path


if __name__ == "__main__":
    print("Wrote", generate_briefing())
